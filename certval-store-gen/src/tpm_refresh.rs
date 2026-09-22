//! The build-script driver a provider crate generated from `TrustedTpm.cab` runs.
//!
//! Same sentinel as [`crate::build_refresh`] and [`crate::authroot_refresh`]: **in a working tree
//! with it present** the cabinet is re-fetched, verified, and -- if the publisher has something
//! newer -- the crate's material is regenerated for a person to review; **anywhere else** nothing
//! is fetched and nothing is written.
//!
//! ## What is checked where, and why the split
//!
//! The guarantee worth having is that the shipped store is the *validated output* of the committed
//! cabinet, which is what `tpm_roots` enforced by refusing to build when its `ca.cbor` did not
//! match. Establishing it means classifying 2,209 members, building a path graph over 2,158
//! intermediates and serializing the result -- far too much to put on every consumer's build, and
//! `TrustedTpm.cab` is thirty times the size of an InstallRoot stream.
//!
//! So it lives in the provider crate's **tests** rather than its build script: CI runs them on
//! every change, which is where a mismatch has to be caught, and a consumer building the crate
//! gets the committed material without paying for a regeneration it cannot act on anyway.
//!
//! ## The rollback guard
//!
//! `version.txt` inside the cabinet states when the contents last changed. A fetch offering a date
//! *older* than the committed one is a stale mirror rather than an update, and is refused --
//! carried over from `tpm_roots`, where it was the reason the version file was read at all.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use crate::adapters::tpm;
use crate::core;
use crate::provider;

/// Retries for a cabinet that gave no answer. It is one fetch of a couple of megabytes, so a
/// transient proxy failure should not end a refresh that is otherwise ready to run.
const RETRIES: usize = 3;

/// Run the refresh a sentinel allows, and regenerate what changed.
///
/// `env` names the directories under `roots/`, `cas/` and `provenance/`, and the CBOR store inside
/// `cas/<env>/`. Panics only when a write that was decided on then failed; every other unhappy
/// path keeps the committed material and says why, for the reason [`crate::refresh`] gives.
pub fn run(sentinel: &str, env: &str) {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={sentinel}");
    println!("cargo::rerun-if-changed=provenance/{env}/published.txt");

    if !Path::new(sentinel).exists() {
        return;
    }
    match refresh(env) {
        Ok(Outcome::Current { published }) => {
            log::info!("the committed cabinet is current (published {published})")
        }
        Ok(Outcome::Kept { why }) => log::warn!("keeping the committed TPM material: {why}"),
        Ok(Outcome::Regenerated {
            published,
            anchors,
            intermediates,
            dropped,
        }) => log::warn!(
            "TPM material regenerated from a cabinet published {published}: {anchors} roots, \
             {intermediates} intermediates, {dropped} intermediate(s) dropped for reaching no \
             root. Review the diff before committing."
        ),
        Err(e) => panic!("rewriting the TPM material failed: {e:#}"),
    }
}

/// What a refresh did.
enum Outcome {
    /// The publisher's cabinet is the one already committed, by its own date.
    Current { published: String },
    /// Nothing usable came back, or what did was older than what is in hand.
    Kept { why: String },
    Regenerated {
        published: String,
        anchors: usize,
        intermediates: usize,
        dropped: usize,
    },
}

fn refresh(env: &str) -> Result<Outcome> {
    let cab = match fetch_with_retries() {
        Ok(cab) => cab,
        Err(why) => return Ok(Outcome::Kept { why }),
    };

    // Route 1: this cabinet vouches for its members, and none of them is signed on its own.
    // Asserted rather than assumed -- an unsigned cabinet here would mean the publisher changed
    // how the material is authenticated, which is a decision, not a detail.
    match crate::cab::is_signed(&cab) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Outcome::Kept {
                why: "the cabinet fetched carries no Authenticode signature; this material is \
                      trusted because the cabinet is signed, so an unsigned one is refused"
                    .to_string(),
            })
        }
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("what was served is not a cabinet: {e:#}"),
            })
        }
    }
    let members = match crate::cab::open_verified(&cab) {
        Ok(members) => members,
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("the cabinet was refused: {e:#}"),
            })
        }
    };

    let contents = match tpm::build(&members) {
        Ok(contents) => contents,
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("the cabinet did not classify: {e:#}"),
            })
        }
    };
    let published = contents
        .inputs
        .published
        .clone()
        .ok_or_else(|| anyhow!("the cabinet states no date in {}", tpm::VERSION_MEMBER))?;

    // The rollback guard. ISO dates sort lexicographically, which is why the adapter writes them
    // that way.
    let committed = fs::read_to_string(format!("provenance/{env}/published.txt"))
        .ok()
        .map(|s| s.trim().to_string());
    if let Some(have) = &committed {
        if published.as_str() < have.as_str() {
            return Ok(Outcome::Kept {
                why: format!(
                    "the cabinet served is published {published}, older than the committed \
                     {have}; that is a stale mirror, not an update"
                ),
            });
        }
        // Current *and* present. The date says the publisher has nothing newer; it says nothing
        // about whether this crate still has what that date describes, and a refresh that reports
        // "current" over a missing store leaves a build failing on an include_bytes! of a file
        // nothing will now write.
        if published.as_str() == have.as_str() && Path::new(&store_path(env)).is_file() {
            return Ok(Outcome::Current { published });
        }
    }

    for skipped in &contents.skipped {
        log::warn!("a cabinet member did not yield a certificate: {skipped}");
    }

    // Intermediates that reach no root cannot be carried: a store's own conformance checks require
    // every CA to appear in a path. The names are recorded beside the material rather than logged
    // and lost, so the count is reviewable and a publisher fixing one shows as a change.
    let (inputs, dropped) = core::prune_unrooted(&contents.inputs)?;
    let store = core::generate(&inputs)?;
    provider::write(
        Path::new("."),
        env,
        env,
        provider::Material {
            anchors: &inputs.trust_anchors,
            intermediates: &inputs.intermediates,
            loose: provider::Intermediates::InStoreOnly,
            store: &store,
        },
        &provider::Provenance {
            published: Some(published.clone()),
            collected: provider::today(),
        },
    )?;
    write_dropped(env, &dropped)?;

    // The list in lib.rs is hand-maintained and a conformance test fails when it disagrees with
    // the files -- the check doing its job, but it cannot write the list. So the lines are printed
    // where a person regenerating will see them.
    if let Ok(lines) = provider::include_bytes_lines(&Path::new("roots").join(env)) {
        println!("cargo::warning=the roots changed; lib.rs wants:\n{lines}");
    }
    fs::write("inputs/TrustedTpm.cab", &cab).context("the cabinet could not be committed")?;

    Ok(Outcome::Regenerated {
        published,
        anchors: inputs.trust_anchors.len(),
        intermediates: inputs.intermediates.len(),
        dropped: dropped.len(),
    })
}

/// Where the generated store lives, which is also what tells a refresh the material is present.
fn store_path(env: &str) -> String {
    format!("cas/{env}/{env}.cbor")
}

/// Fetch the cabinet, retrying what gives no answer.
fn fetch_with_retries() -> std::result::Result<Vec<u8>, String> {
    let mut last = String::new();
    for attempt in 0..=RETRIES {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2 * attempt as u64));
        }
        match crate::refresh::fetch(tpm::CAB_URL) {
            Ok(bytes) => return Ok(bytes),
            // A 4xx is the publisher's answer about its own URL; asking again cannot change it.
            Err(crate::refresh::FetchError::Absent(why)) => return Err(why),
            Err(crate::refresh::FetchError::Unreachable(why)) => last = why,
        }
    }
    Err(last)
}

/// Record the intermediates that reached no root, one per line.
///
/// A file rather than a log line because it is the part of a regeneration a reviewer has to look
/// at: thirty-odd AMD CAs have been unrooted for years, and the number changing is the signal --
/// downward when a publisher fixes one, upward when a vendor's root stops being carried.
fn write_dropped(env: &str, dropped: &[String]) -> Result<()> {
    let dir = format!("provenance/{env}");
    fs::create_dir_all(&dir).with_context(|| format!("{dir} could not be created"))?;
    let path = format!("{dir}/dropped.txt");
    if dropped.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let mut body = String::from(
        "# Intermediate CAs in the cabinet that reach no root in it, so the store does not carry\n\
         # them. Written by certval-store-gen; a change here is a change in what the publisher\n\
         # ships, not in this crate.\n",
    );
    for name in dropped {
        body.push_str(name);
        body.push('\n');
    }
    fs::write(&path, body).with_context(|| format!("{path} could not be written"))
}

/// Regenerate from a committed cabinet and compare against a committed store.
///
/// The guarantee a provider crate's tests carry: what ships is the validated output of the cabinet
/// beside it. Uses [`crate::cab::members`] rather than `open_verified`, deliberately -- signature
/// verification reaches a timestamp authority for revocation, and a test that fails when a
/// responder is down is a test nobody trusts. The signature is checked where the material enters
/// the repository, which is the refresh above.
pub fn regenerate_from(cab: &[u8]) -> Result<(core::StoreInputs, Vec<String>)> {
    let members = crate::cab::members(cab).context("the committed cabinet did not unpack")?;
    let contents = tpm::build(&members)?;
    if !contents.skipped.is_empty() {
        bail!(
            "{} member(s) of the committed cabinet did not yield a certificate: {:?}",
            contents.skipped.len(),
            contents.skipped
        );
    }
    core::prune_unrooted(&contents.inputs)
}

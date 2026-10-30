//! The build-script driver a provider crate generated from `TrustedTpm.cab` runs.
//!
//! Same sentinel as [`crate::authroot_refresh`]: **in a working tree
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
//!
//! The *same* date does not end a refresh unless the cabinet is also byte for byte the committed
//! `inputs/TrustedTpm.cab`, because Microsoft reissues the cabinet with new vendor CAs without
//! moving `version.txt`.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use crate::adapters::tpm;
use crate::core;
use crate::provider;

/// Retries for a cabinet that gave no answer. It is one fetch of a couple of megabytes, so a
/// transient proxy failure should not end a refresh that is otherwise ready to run.
const RETRIES: usize = 3;

/// Refresh a provider crate from the published cabinet.
///
/// Returns what happened rather than deciding what to do about it; see
/// [`crate::authroot_refresh::refresh_crate`], which follows the same rule about what is an
/// outcome and what is an error.
pub fn refresh_crate(
    crate_dir: &Path,
    env: &str,
    from_committed: bool,
    as_of: Option<&str>,
) -> Result<Outcome> {
    let previous = std::env::current_dir().context("the working directory could not be read")?;
    std::env::set_current_dir(crate_dir)
        .with_context(|| format!("{} could not be entered", crate_dir.display()))?;
    let outcome = match from_committed {
        true => regenerate_committed(env, as_of),
        false => refresh(env, as_of),
    };
    std::env::set_current_dir(previous).context("the working directory could not be restored")?;
    outcome
}

/// What a refresh did.
pub enum Outcome {
    /// The publisher's cabinet is the one already committed, by its date and its bytes.
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

/// Where the cabinet being generated from came from, which decides what has to be checked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Just fetched. Its signature has not been looked at and it may be a rollback.
    Fetched,
    /// The `inputs/TrustedTpm.cab` already committed beside the crate. Its signature was checked
    /// when it was committed, and re-emitting it is the point, so neither the signature route nor
    /// the rollback guard applies -- and re-verifying would reach a timestamp authority, which is
    /// what `regenerate_from` avoids for the same reason.
    Committed,
}

fn refresh(env: &str, as_of: Option<&str>) -> Result<Outcome> {
    let cab = match fetch_with_retries() {
        Ok(cab) => cab,
        Err(why) => return Ok(Outcome::Kept { why }),
    };
    refresh_with(env, cab, Source::Fetched, as_of)
}

/// Re-emit a provider crate from the cabinet already committed beside it.
///
/// For when the *generator* changes rather than the material: the pruning rules move, and the
/// committed store has to be brought back into agreement with what the committed input now yields
/// -- which is the agreement `the_store_is_what_the_committed_cabinet_generates` asserts. Touches
/// no network.
pub fn regenerate_committed(env: &str, as_of: Option<&str>) -> Result<Outcome> {
    let cab = fs::read("inputs/TrustedTpm.cab")
        .context("inputs/TrustedTpm.cab could not be read; there is nothing to regenerate from")?;
    refresh_with(env, cab, Source::Committed, as_of)
}

fn refresh_with(env: &str, cab: Vec<u8>, source: Source, as_of: Option<&str>) -> Result<Outcome> {
    // Route 1: this cabinet vouches for its members, and none of them is signed on its own.
    // Asserted rather than assumed -- an unsigned cabinet here would mean the publisher changed
    // how the material is authenticated, which is a decision, not a detail.
    match match source {
        Source::Committed => Ok(true),
        Source::Fetched => crate::cab::is_signed(&cab),
    } {
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
    let members = match match source {
        Source::Committed => crate::cab::members(&cab),
        Source::Fetched => crate::cab::open_verified(&cab),
    } {
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
    if let (Source::Fetched, Some(have)) = (source, &committed) {
        if published.as_str() < have.as_str() {
            return Ok(Outcome::Kept {
                why: format!(
                    "the cabinet served is published {published}, older than the committed \
                     {have}; that is a stale mirror, not an update"
                ),
            });
        }
        let committed_cab = fs::read("inputs/TrustedTpm.cab").ok();
        if is_current(
            &published,
            have,
            Path::new(&store_path(env)).is_file(),
            &cab,
            committed_cab.as_deref(),
        ) {
            return Ok(Outcome::Current { published });
        }
        if published.as_str() == have.as_str() {
            log::info!(
                "the cabinet served states the committed date {published} but differs from \
                 inputs/TrustedTpm.cab; regenerating"
            );
        }
    }

    for skipped in &contents.skipped {
        log::warn!("a cabinet member did not yield a certificate: {skipped}");
    }

    // What the cabinet published that this store will not carry, and why. Two reasons: a CA whose
    // issuer the cabinet omits reaches no root, and a CA that had already lapsed when the cabinet
    // was published is not material a consumer of *this* store has a use for. Validating at the
    // publication date rather than at now is what keeps the output a function of the input alone.
    // The names are recorded beside the material rather than logged and lost, so the count is
    // reviewable and a publisher fixing one shows as a change.
    // The override is written beside the material, not just applied: the store has to stay a
    // function of what is committed, and a reference date a person chose is part of that input.
    // `regenerate_from` reads the same file, so the crate's own regeneration test keeps agreeing
    // with a store generated this way instead of failing against it.
    let reference = as_of.unwrap_or(published.as_str());
    let toi = core::published_as_time_of_interest(reference)?;
    write_as_of(env, as_of)?;
    let (inputs, dropped) = core::prune_unvalidated(&contents.inputs, toi)?;
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
            collected: collected_stamp(env, source),
        },
    )?;
    write_dropped(env, &dropped)?;
    fs::write("inputs/TrustedTpm.cab", &cab).context("the cabinet could not be committed")?;

    Ok(Outcome::Regenerated {
        published,
        anchors: inputs.trust_anchors.len(),
        intermediates: inputs.intermediates.len(),
        dropped: dropped.len(),
    })
}

/// Record the reference date a person chose, or clear the record when they chose none.
///
/// Absent means "the cabinet's own publication date", which is the default and needs no file. A
/// present file is part of the committed input: [`regenerate_from`] is handed it, so the provider's
/// regeneration test measures the store against the same date that produced it rather than against
/// a date the store was never generated with.
fn write_as_of(env: &str, as_of: Option<&str>) -> Result<()> {
    let dir = format!("provenance/{env}");
    fs::create_dir_all(&dir).with_context(|| format!("{dir} could not be created"))?;
    let path = format!("{dir}/as_of.txt");
    match as_of {
        None => {
            let _ = fs::remove_file(&path);
            Ok(())
        }
        Some(date) => {
            fs::write(&path, date).with_context(|| format!("{path} could not be written"))
        }
    }
}

/// The reference date recorded beside a committed environment, if one was. `None` means the
/// cabinet's own publication date was used, which is the default.
pub fn recorded_as_of(crate_dir: &Path, env: &str) -> Option<String> {
    fs::read_to_string(crate_dir.join(format!("provenance/{env}/as_of.txt")))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// When this material was obtained, which is not the same as when the generator last ran.
///
/// A fetch collected it today. A regeneration from the committed cabinet collected nothing, so the
/// date already beside it still stands -- stamping the run's date there would claim a freshness the
/// store does not have, and `collected` is shown to a user as precisely that. Falls back to today
/// only where nothing is recorded yet, which is a crate being populated for the first time.
fn collected_stamp(env: &str, source: Source) -> String {
    match source {
        Source::Fetched => provider::today(),
        Source::Committed => fs::read_to_string(format!("provenance/{env}/collected.txt"))
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(provider::today),
    }
}

/// Where the generated store lives, which is also what tells a refresh the material is present.
fn store_path(env: &str) -> String {
    format!("cas/{env}/{env}.cbor")
}

/// Whether a fetched cabinet leaves nothing to do: the date its `version.txt` states is the
/// committed one, the store that date describes is present, and the cabinet is byte for byte
/// `inputs/TrustedTpm.cab`.
///
/// The date alone is not enough, because Microsoft reissues the cabinet with new vendor CAs
/// without moving it. A re-signed cabinet with the same certificates also differs in its bytes;
/// regenerating from it writes the same store, so the cost is a run, not a wrong answer.
fn is_current(
    published: &str,
    committed_date: &str,
    store_present: bool,
    cab: &[u8],
    committed_cab: Option<&[u8]>,
) -> bool {
    published == committed_date && store_present && committed_cab == Some(cab)
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
fn write_dropped(env: &str, dropped: &[core::Dropped]) -> Result<()> {
    let dir = format!("provenance/{env}");
    fs::create_dir_all(&dir).with_context(|| format!("{dir} could not be created"))?;
    let path = format!("{dir}/dropped.txt");
    if dropped.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let mut body = String::from(
        "# Intermediate CAs in the cabinet that this store does not carry, with the reason.\n\
         # Written by certval-store-gen; a change here is a change in what the publisher ships,\n\
         # not in this crate.\n\
         #\n\
         # unrooted     the cabinet includes the CA but not its issuer, so nothing roots it\n\
         # unvalidated  a path to a root exists and none validated as of the publication date;\n\
         #              an InvalidNotAfterDate here is a CA the publisher shipped already lapsed\n",
    );
    for d in dropped {
        match &d.reason {
            core::DropReason::Unrooted => {
                body.push_str(&format!("unrooted     {}\n", d.name));
            }
            core::DropReason::Unvalidated(why) => {
                body.push_str(&format!("unvalidated  {}  {why}\n", d.name));
            }
        }
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
pub fn regenerate_from(
    cab: &[u8],
    as_of: Option<&str>,
) -> Result<(core::StoreInputs, Vec<core::Dropped>)> {
    let members = crate::cab::members(cab).context("the committed cabinet did not unpack")?;
    let contents = tpm::build(&members)?;
    if !contents.skipped.is_empty() {
        bail!(
            "{} member(s) of the committed cabinet did not yield a certificate: {:?}",
            contents.skipped.len(),
            contents.skipped
        );
    }
    let published = contents
        .inputs
        .published
        .as_deref()
        .ok_or_else(|| anyhow!("the cabinet states no publication date to validate against"))?;
    let reference = as_of.unwrap_or(published);
    core::prune_unvalidated(
        &contents.inputs,
        core::published_as_time_of_interest(reference)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATE: &str = "2026-10-23";

    #[test]
    fn same_date_same_bytes_with_a_store_is_current() {
        assert!(is_current(DATE, DATE, true, b"cab", Some(b"cab")));
    }

    #[test]
    fn same_date_different_bytes_is_regenerated() {
        // The case the date check alone missed: a reissue that leaves version.txt where it was.
        assert!(!is_current(DATE, DATE, true, b"reissued", Some(b"cab")));
    }

    #[test]
    fn same_cabinet_without_its_store_is_regenerated() {
        assert!(!is_current(DATE, DATE, false, b"cab", Some(b"cab")));
    }

    #[test]
    fn nothing_committed_is_regenerated() {
        assert!(!is_current(DATE, DATE, true, b"cab", None));
    }

    #[test]
    fn a_newer_date_is_regenerated() {
        assert!(!is_current("2026-11-01", DATE, true, b"cab", Some(b"cab")));
    }
}

//! The build-script driver a provider crate generated from the Microsoft trust list runs.
//!
//! Same two halves as [`crate::build_refresh`], and the same sentinel: **in a working tree with
//! the sentinel present** the list is re-fetched and, when it has changed, the crate's material is
//! rewritten for a person to review and commit; **anywhere else** nothing is fetched and nothing
//! is written, and the consumer gets the committed material and the checks.
//!
//! What differs is the cost of asking. An InstallRoot stream is one file and re-fetching it is
//! cheap; this program is 562 separate certificates, so a refresh asks first and almost always
//! stops there:
//!
//! ```text
//! conditional GET authrootstl.cab
//!   304                          -> nothing to do; the committed copy is current
//!   200, same sequenceNumber     -> nothing to do; the CDN re-served the same list
//!   200, changed                 -> fetch every listed certificate, verify each thumbprint,
//!                                   rewrite roots/ and src/env_*.rs wholesale
//! ```
//!
//! Two staleness checks rather than one, because they fail differently: `Last-Modified` is a
//! property of the transfer and can move without the material changing, while the list's own
//! `sequenceNumber` is the publisher's statement and survives a CDN reshuffle.
//!
//! **A rewrite is all or nothing.** Every entry in the list must be fetched and thumbprint-matched
//! before anything is written or deleted; a single failure leaves the committed material alone and
//! says which entry and why. Without that rule one bad morning of DNS would empty the store, and
//! the diff would look like Microsoft had dropped three hundred roots.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use const_oid::ObjectIdentifier;
use sha1::{Digest, Sha1};

use crate::adapters::authroot::{self, Ctl, Options};

/// Where a provider crate keeps the anchors the signed list is verified against.
///
/// Pinned, and deliberately not taken from the list: the signer chains to
/// `Microsoft Root Certificate Authority 2010`, which the list itself carries as an entry, so
/// reading the anchor out of the material being verified would prove nothing. A refresh never
/// writes here -- these files are the one part of the crate a regeneration cannot touch, the same
/// footing the hand-carried DoD interoperability roots sit on.
const ANCHORS_DIR: &str = "inputs";

/// One generated environment: a name, and the purpose it filters the program by.
pub struct Env {
    /// Names the generated index, `src/env_<name>.rs`, and nothing else -- the certificates live
    /// in one shared `roots/`, because six environments over one list would otherwise store the
    /// same root up to six times.
    pub name: &'static str,
    /// The EKU Microsoft must grant a root for it to appear here, or `None` for every root the
    /// program still trusts.
    pub eku: Option<&'static str>,
}

/// The environments a Microsoft root program crate carries, and the purpose each filters the list
/// by. `None` takes every root the program still trusts.
///
/// Here rather than in the CLI because it is a property of the material: these are the purposes
/// the program grants, and a crate's features name the same six. The exclusions -- expired, and
/// restricted past their disallowed date -- apply to all of them alike and are not repeated.
pub const ENVIRONMENTS: &[Env] = &[
    Env {
        name: "all",
        eku: None,
    },
    Env {
        name: "tls",
        eku: Some("1.3.6.1.5.5.7.3.1"),
    },
    Env {
        name: "client_auth",
        eku: Some("1.3.6.1.5.5.7.3.2"),
    },
    Env {
        name: "email",
        eku: Some("1.3.6.1.5.5.7.3.4"),
    },
    Env {
        name: "code_signing",
        eku: Some("1.3.6.1.5.5.7.3.3"),
    },
    Env {
        name: "timestamping",
        eku: Some("1.3.6.1.5.5.7.3.8"),
    },
];

/// Refresh a provider crate from the published trust list.
///
/// Returns what happened rather than deciding what to do about it: the CLI prints it, and a
/// scheduled job turns a rewrite into a pull request for a person to read.
///
/// **Reaching the publisher is not something to fail over.** An unreachable CDN, a cabinet that
/// will not verify, a list that will not parse, a certificate that does not arrive -- every one of
/// those is [`Outcome::Kept`], because the committed material is still good. `Err` is reserved for
/// a write that was decided on and then failed, which is the one case that leaves a crate
/// half-rewritten.
pub fn refresh_crate(crate_dir: &Path, published_at: &str, envs: &[Env]) -> Result<Outcome> {
    // The writers underneath address everything relative to the crate root, which is what a build
    // script's working directory used to be. Entering it keeps those paths as they are and makes
    // the crate an argument, which is what lets one command refresh any of them.
    let previous = std::env::current_dir().context("the working directory could not be read")?;
    std::env::set_current_dir(crate_dir)
        .with_context(|| format!("{} could not be entered", crate_dir.display()))?;
    let outcome = refresh(published_at, envs);
    std::env::set_current_dir(previous).context("the working directory could not be restored")?;
    outcome
}

/// Check a provider crate's committed material: every file in `roots/` hashes to its own name.
///
/// The same comparison that admitted each certificate -- the list is signed and the certificates
/// it names are not, so the SHA-1 the list gave is what binds them.
pub fn check_crate(crate_dir: &Path, envs: &[Env]) -> Result<()> {
    let previous = std::env::current_dir().context("the working directory could not be read")?;
    std::env::set_current_dir(crate_dir)
        .with_context(|| format!("{} could not be entered", crate_dir.display()))?;
    let checked = check_committed(envs);
    std::env::set_current_dir(previous).context("the working directory could not be restored")?;
    checked
}

/// What a refresh did, which is almost always nothing.
pub enum Outcome {
    /// The publisher has nothing newer.
    Unchanged(String),
    /// The publisher could not be reached, or what came back could not be used. The committed
    /// material stands, which is why this is an outcome and not an error.
    Kept {
        why: String,
    },
    Rewritten {
        carried: usize,
        listed: usize,
    },
}

fn refresh(published_at: &str, envs: &[Env]) -> Result<Outcome> {
    let since = read_provenance("last_modified.txt");
    let fetched = match crate::refresh::fetch_if_modified(published_at, since.as_deref()) {
        Ok(fetched) => fetched,
        Err(e) => return Ok(Outcome::Kept { why: e.to_string() }),
    };
    let Some((cab, last_modified)) = fetched else {
        return Ok(Outcome::Unchanged("the server answered 304".to_string()));
    };

    // `members`, not `open_verified`: this cabinet carries no Authenticode signature -- it has no
    // reserved area at all -- so it is packaging, and the signature that matters is the one inside
    // `authroot.stl`. Asserted rather than assumed, because taking this route on a *signed*
    // cabinet would silently discard its signature.
    match crate::cab::is_signed(&cab) {
        Ok(false) => {}
        Ok(true) => {
            return Ok(Outcome::Kept {
                why: format!(
                    "the cabinet at {published_at} now carries an Authenticode signature; it did \
                     not before, and this refresh verifies the list inside instead. Check which \
                     is authoritative before trusting either."
                ),
            })
        }
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("what {published_at} served is not a cabinet: {e:#}"),
            })
        }
    }
    let members = match crate::cab::members(&cab) {
        Ok(members) => members,
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("the cabinet fetched from {published_at} did not unpack: {e:#}"),
            })
        }
    };
    let Some(stl) = members
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case(authroot::STL_MEMBER))
    else {
        return Ok(Outcome::Kept {
            why: format!("the cabinet holds no {}", authroot::STL_MEMBER),
        });
    };
    // The only signature in this chain of custody. Everything below trusts the list because of
    // this call, so a failure keeps what is committed rather than proceeding with unverified
    // thumbprints.
    let anchors = match pinned_anchors() {
        Ok(anchors) => anchors,
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("the pinned anchors could not be read: {e:#}"),
            })
        }
    };
    let borrowed: Vec<&[u8]> = anchors.iter().map(Vec::as_slice).collect();
    if let Err(e) = authroot::verify_stl(&stl.bytes, &borrowed) {
        return Ok(Outcome::Kept {
            why: format!("{} was refused: {e:#}", authroot::STL_MEMBER),
        });
    }

    let ctl = match authroot::parse_stl(&stl.bytes) {
        Ok(ctl) => ctl,
        Err(e) => {
            return Ok(Outcome::Kept {
                why: format!("{} did not parse: {e:#}", authroot::STL_MEMBER),
            })
        }
    };

    // The publisher's own version, which is what decides. A `Last-Modified` that moved while the
    // sequence number did not means the CDN re-served the same list.
    let committed = read_provenance("sequence_number.txt");
    if committed.is_some() && committed == ctl.sequence_number {
        write_provenance("last_modified.txt", last_modified.as_deref())?;
        return Ok(Outcome::Unchanged(format!(
            "sequence number {} is the committed one",
            committed.unwrap_or_default()
        )));
    }

    let (fetched, absent, unreachable) = authroot::fetch_certificates(&ctl.entries);
    if !absent.is_empty() || !unreachable.is_empty() {
        return Ok(Outcome::Kept {
            why: format!(
                "{} of {} certificates did not arrive, so nothing was written and nothing \
                 deleted ({} absent, {} unreachable; first: {})",
                absent.len() + unreachable.len(),
                ctl.entries.len(),
                absent.len(),
                unreachable.len(),
                absent
                    .first()
                    .or_else(|| unreachable.first())
                    .map(String::as_str)
                    .unwrap_or("-")
            ),
        });
    }

    let carried = write_material(&ctl, &fetched, envs)?;
    write_provenance("published.txt", Some(&ctl.published))?;
    write_provenance("collected.txt", Some(&crate::provider::today()))?;
    write_provenance("sequence_number.txt", ctl.sequence_number.as_deref())?;
    write_provenance("last_modified.txt", last_modified.as_deref())?;
    Ok(Outcome::Rewritten {
        carried,
        listed: ctl.entries.len(),
    })
}

/// Write `roots/` and every `src/env_*.rs`, replacing what is there.
///
/// Wholesale rather than reconciled: the directory is emptied and rewritten from this list, so a
/// root the program dropped leaves by not being written rather than by being found and deleted.
/// That is the same thing the InstallRoot providers do, and it is what makes the claim "everything
/// here came from this fetch" true rather than nearly true.
fn write_material(ctl: &Ctl, fetched: &[(Vec<u8>, Vec<u8>)], envs: &[Env]) -> Result<usize> {
    let now = now_unix();
    let roots = Path::new("roots");
    if roots.exists() {
        fs::remove_dir_all(roots).context("roots/ could not be emptied")?;
    }
    fs::create_dir_all(roots).context("roots/ could not be created")?;

    let mut written: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut carried = 0;
    for env in envs {
        let eku = match env.eku {
            Some(oid) => Some(
                ObjectIdentifier::new(oid).map_err(|e| anyhow!("{} is not an OID: {e}", oid))?,
            ),
            None => None,
        };
        let (inputs, missing) = authroot::build(ctl, fetched, &Options { eku, now_unix: now })?;
        if !missing.is_empty() {
            bail!(
                "{}: {} entries produced nothing: {missing:?}",
                env.name,
                missing.len()
            );
        }

        let mut index = vec![
            format!(
                "//! Generated by `certval-store-gen` from `authroot.stl`, published {}. Do not edit.",
                ctl.published
            ),
            "//!".to_string(),
            format!(
                "//! The {} roots this environment carries, in thumbprint order.",
                inputs.trust_anchors.len()
            ),
            String::new(),
            "/// The trust anchors of this environment, in thumbprint order.".to_string(),
            "pub(crate) static ROOTS: &[&[u8]] = &[".to_string(),
        ];

        let mut anchors = inputs.trust_anchors;
        anchors.sort_by_key(|cf| Sha1::digest(&cf.bytes).to_vec());
        for cf in &anchors {
            let thumb = Sha1::digest(&cf.bytes)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>();
            if written.insert(cf.bytes.clone()) {
                fs::write(roots.join(format!("{thumb}.der")), &cf.bytes)
                    .with_context(|| format!("roots/{thumb}.der could not be written"))?;
            }
            // The friendly name rides in a comment so a review reads "DigiCert Baltimore Root
            // left the program", not a line of hex changing.
            index.push(format!(
                "    include_bytes!(\"../roots/{thumb}.der\"), // {}",
                cf.filename.trim_end_matches(".der")
            ));
        }
        index.push("];".to_string());
        index.push(String::new());

        fs::write(format!("src/env_{}.rs", env.name), index.join("\n"))
            .with_context(|| format!("src/env_{}.rs could not be written", env.name))?;
        if env.eku.is_none() {
            carried = anchors.len();
        }
    }
    Ok(carried)
}

/// What a consumer's build checks, since it fetches nothing: every file in `roots/` hashes to its
/// own name.
///
/// That is the same comparison that admitted the certificate in the first place. It is cheap --
/// a few hundred SHA-1 digests over half a megabyte -- and it is the one property that makes this
/// material trust material rather than bytes someone put in a directory.
fn check_committed(envs: &[Env]) -> Result<()> {
    let roots = Path::new("roots");
    if !roots.is_dir() {
        bail!("roots/ is missing");
    }
    let mut checked = 0;
    for entry in fs::read_dir(roots).context("roots/ could not be read")? {
        let path = entry.context("roots/ holds an unreadable entry")?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("der") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_uppercase();
        let bytes = fs::read(&path).with_context(|| format!("{} is unreadable", path.display()))?;
        let digest = Sha1::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        if digest != name {
            bail!(
                "{} does not hash to its own name ({digest}); it is not the certificate the trust \
                 list named",
                path.display()
            );
        }
        checked += 1;
    }
    if checked == 0 {
        bail!("roots/ holds no certificates");
    }
    for env in envs {
        let index = format!("src/env_{}.rs", env.name);
        if !Path::new(&index).is_file() {
            bail!("{index} is missing, so an environment this crate advertises has no material");
        }
    }
    Ok(())
}

/// Every DER certificate in [`ANCHORS_DIR`].
fn pinned_anchors() -> Result<Vec<Vec<u8>>> {
    let dir = Path::new(ANCHORS_DIR);
    let mut out = vec![];
    for entry in fs::read_dir(dir).with_context(|| format!("{ANCHORS_DIR}/ could not be read"))? {
        let path = entry.context("an unreadable directory entry")?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("der") {
            out.push(fs::read(&path).with_context(|| format!("{} is unreadable", path.display()))?);
        }
    }
    if out.is_empty() {
        bail!("{ANCHORS_DIR}/ holds no anchor, so the signed list could not be verified against anything");
    }
    Ok(out)
}

fn read_provenance(name: &str) -> Option<String> {
    fs::read_to_string(format!("provenance/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn write_provenance(name: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    fs::create_dir_all("provenance").context("provenance/ could not be created")?;
    fs::write(format!("provenance/{name}"), format!("{value}\n"))
        .with_context(|| format!("provenance/{name} could not be written"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

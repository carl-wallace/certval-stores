//! The Federal PKI store, built by walking the mesh from its committed anchor.
//!
//! The FPKI publishes no single artifact to generate from: it is a cross-certified mesh, linked by
//! the SIA `caRepository` and AIA `caIssuers` bundles its certificates name. [`crate::crawl`]
//! walks it from Federal Common Policy CA G2, following both; this module turns a walk into committed material for
//! `certval_stores_fpki` and regenerates the store from that material.
//!
//! ## What is committed
//!
//! - `inputs/crawl/<host>/<path>`: every bundle the walk read, exactly as its repository served
//!   it, BER included. These are the publishers' own artifacts, so a refresh diff names the
//!   repository that changed. A refresh replaces the whole folder, so it always holds the last
//!   complete walk and nothing a repository has since withdrawn.
//! - `provenance/fpki/collected.txt`: the day of the walk. It is also the date the store is
//!   validated at, since a mesh states no publication date of its own, and recording it keeps the
//!   store a function of what is committed: regenerating on a later day reproduces it.
//! - `provenance/fpki/dropped.txt`: what the walk reached that the store does not carry, and why.
//! - `cas/fpki/fpki.cbor`: the store.
//!
//! The anchor under `roots/fpki/` is never written here. It is committed by hand, and a walk must
//! not be able to change it.
//!
//! ## A repository that does not answer
//!
//! The FPKI's repositories are not reliably up, and one host failing must not cost the refresh.
//! A repository that gives no answer after the walk's retries is read from its bundle under
//! `inputs/crawl/` instead, and the walk continues through it, so the subtree beneath it stays
//! covered. Anything in that earlier copy that has expired since is pruned at the walk date like
//! any other expired certificate. A repository with no committed copy is skipped and logged: the
//! committed store held nothing from it either, so nothing is lost. A walk a limit stopped is not
//! committed, since that is a sizing problem rather than an outage.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use der::Decode;
use x509_cert::Certificate;

use certval::{CertFile, PkiEnvironment};

use crate::core::{self, StoreInputs};
use crate::ingest;

/// Names the directories under `cas/` and `provenance/`.
pub const ENV: &str = "fpki";

/// The committed anchor the walk starts from, relative to the crate.
pub const ANCHOR: &str = "roots/fpki/Federal_Common_Policy_CA_G2.der";

/// Where the bundles a walk read are committed, relative to the crate.
pub const CRAWL_DIR: &str = "inputs/crawl";

/// The bundles committed under [`CRAWL_DIR`], as `(path relative to it, bytes)`, sorted by path.
pub fn read_bundles(crate_dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let root = crate_dir.join(CRAWL_DIR);
    let mut out = vec![];
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("{} could not be read", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = path
                .strip_prefix(&root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| path.display().to_string());
            let bytes =
                fs::read(&path).with_context(|| format!("{} could not be read", path.display()))?;
            out.push((name, bytes));
        }
    }
    out.sort();
    Ok(out)
}

/// Generator inputs from the committed anchors and the bundles a walk read.
///
/// The same certificates the walk itself collected: every certificate the bundles hold, less the
/// anchors, anything that is not a certificate, and duplicates. Then the self-signed ones are
/// dropped, as [`crate::crawl::into_inputs`] drops them. The refresh builds its store through this
/// function too, so what it commits is by construction what the crate's regeneration test
/// recomputes.
pub fn inputs_from(
    pe: &PkiEnvironment,
    anchors: Vec<CertFile>,
    bundles: &[(String, Vec<u8>)],
) -> Result<StoreInputs> {
    let mut seen: std::collections::BTreeSet<Vec<u8>> =
        anchors.iter().map(|a| a.bytes.clone()).collect();
    let mut certificates = vec![];
    for (name, bytes) in bundles {
        let certs = ingest::certs_from_bytes(bytes).map_err(|e| anyhow!("{name}: {e}"))?;
        for cf in certs {
            if Certificate::from_der(&cf.bytes).is_err() {
                continue;
            }
            if seen.insert(cf.bytes.clone()) {
                certificates.push(cf);
            }
        }
    }
    let (intermediates, _roots) = ingest::drop_self_signed(pe, certificates);
    Ok(StoreInputs {
        trust_anchors: anchors,
        intermediates,
        published: None,
    })
}

/// The walk date recorded beside the committed bundles, if there is one.
pub fn recorded_collected(crate_dir: &Path) -> Option<String> {
    fs::read_to_string(crate_dir.join(format!("provenance/{ENV}/collected.txt")))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Regenerate from what is committed: the anchor, the bundles and the walk date.
///
/// Returns the inputs the store holds and what was dropped from them. No network: this is what the
/// crate's regeneration test runs, and what [`refresh_crate`] runs after writing a walk.
pub fn regenerate_from(crate_dir: &Path) -> Result<(StoreInputs, Vec<core::Dropped>)> {
    let anchors = ingest::read_cert_file(&crate_dir.join(ANCHOR))?;
    let bundles = read_bundles(crate_dir)?;
    let collected = recorded_collected(crate_dir).ok_or_else(|| {
        anyhow!("provenance/{ENV}/collected.txt is missing; there is no date to validate at")
    })?;
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let inputs = inputs_from(&pe, anchors, &bundles)?;
    let (validated, mut dropped) =
        core::prune_unvalidated(&inputs, core::published_as_time_of_interest(&collected)?)?;
    // Validation judges each certificate against the whole walk, so dropping one can strand
    // another. USPTO's key rollover is the case: the certificate that has the new key certified by
    // the old one validated through the expired Bridge G4 cross-certificate, and once that was
    // dropped its only remaining route returned to a key already on the path, which no partial
    // path takes. `prune_unrooted` reads the serialized graph itself, as the conformance check
    // does, and removing what appears in no path cannot strand anything that does, so one pass
    // settles it.
    let (kept, unrooted) = core::prune_unrooted(&validated)?;
    dropped.extend(unrooted.into_iter().map(|name| core::Dropped {
        name,
        reason: core::DropReason::Unrooted,
    }));
    Ok((kept, dropped))
}

/// What a refresh did.
#[cfg(feature = "fetch")]
pub enum Outcome {
    /// The walk read exactly the bundles already committed, so nothing was written.
    Current { collected: String },
    /// The walk was incomplete, so the committed material stands.
    Kept { why: String },
    Regenerated {
        collected: String,
        bundles: usize,
        intermediates: usize,
        dropped: usize,
    },
}

/// Walk the mesh and regenerate `certval_stores_fpki` from it, or with `from_committed`,
/// regenerate from the bundles already committed and fetch nothing.
///
/// The second is for when this tool's rules change rather than the mesh; it keeps the recorded
/// walk date, since nothing was collected.
#[cfg(feature = "fetch")]
pub fn refresh_crate(crate_dir: &Path, from_committed: bool) -> Result<Outcome> {
    let bundles = match from_committed {
        true => read_bundles(crate_dir)?.len(),
        false => {
            let anchors = ingest::read_cert_file(&crate_dir.join(ANCHOR))?;
            let committed = crate_dir.join(CRAWL_DIR);
            let crawled = crate::crawl::from_anchors_with(
                &anchors,
                &crate::crawl::Limits::default(),
                |uri| {
                    path_for(uri)
                        .ok()
                        .and_then(|p| fs::read(committed.join(p)).ok())
                },
            );
            for why in &crawled.unreachable {
                log::warn!("no answer and no earlier copy, skipped: {why}");
            }
            if crawled.truncated {
                return Ok(Outcome::Kept {
                    why: "a limit stopped the walk before it finished".to_string(),
                });
            }
            for absent in &crawled.absent {
                log::info!("nothing published there: {absent}");
            }
            // Unchanged means nothing is written, the walk date included: a scheduled refresh that
            // rewrote the date every day would open a pull request every day. The store keeps the
            // date of the last walk that moved something, as a cabinet keeps its publication date.
            if unchanged(crate_dir, &crawled.bundles)? {
                return Ok(Outcome::Current {
                    collected: recorded_collected(crate_dir).unwrap_or_default(),
                });
            }
            write_bundles(crate_dir, &crawled.bundles)?;
            write_collected(crate_dir, &crate::provider::today())?;
            crawled.bundles.len()
        }
    };

    let (inputs, dropped) = regenerate_from(crate_dir)?;
    let store = core::generate(&inputs)?;
    let ca = store
        .ca_cbor
        .ok_or_else(|| anyhow!("the walk yielded no intermediates"))?;
    let path = crate_dir.join(format!("cas/{ENV}/{ENV}.cbor"));
    fs::write(&path, &ca).with_context(|| format!("{} could not be written", path.display()))?;
    log::info!("wrote {} ({} bytes)", path.display(), ca.len());
    write_dropped(crate_dir, &dropped)?;

    Ok(Outcome::Regenerated {
        collected: recorded_collected(crate_dir).unwrap_or_default(),
        bundles,
        intermediates: inputs.intermediates.len(),
        dropped: dropped.len(),
    })
}

/// Whether a walk read exactly the bundles committed, by path and bytes, and the store and its walk
/// date are present to go with them.
#[cfg(feature = "fetch")]
fn unchanged(crate_dir: &Path, bundles: &[(String, Vec<u8>)]) -> Result<bool> {
    if recorded_collected(crate_dir).is_none()
        || !crate_dir.join(format!("cas/{ENV}/{ENV}.cbor")).is_file()
        || !crate_dir.join(CRAWL_DIR).is_dir()
    {
        return Ok(false);
    }
    let mut fresh = bundles
        .iter()
        .map(|(uri, bytes)| {
            path_for(uri).map(|p| (p.to_string_lossy().replace('\\', "/"), bytes.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    fresh.sort();
    Ok(fresh == read_bundles(crate_dir)?)
}

/// Replace [`CRAWL_DIR`] with the bundles of one walk.
///
/// Replaced rather than merged: a repository the walk no longer reaches has left the mesh or
/// stopped publishing, and a file left behind would put its certificates back into the store.
#[cfg(feature = "fetch")]
fn write_bundles(crate_dir: &Path, bundles: &[(String, Vec<u8>)]) -> Result<()> {
    let root = crate_dir.join(CRAWL_DIR);
    if root.exists() {
        fs::remove_dir_all(&root)
            .with_context(|| format!("{} could not be cleared", root.display()))?;
    }
    for (uri, bytes) in bundles {
        let path = root.join(path_for(uri)?);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("{} could not be created", dir.display()))?;
        }
        fs::write(&path, bytes)
            .with_context(|| format!("{} could not be written", path.display()))?;
    }
    log::info!("wrote {} bundle(s) under {}", bundles.len(), root.display());
    Ok(())
}

/// Where a repository's bundle is committed: its URI's host and path, so two repositories
/// publishing the same file name stay apart.
///
/// Characters outside a conservative set become `_`, and an empty, `.` or `..` segment is refused
/// rather than mapped, since a URI is publisher-controlled and must not be able to name a path
/// outside the folder.
#[cfg(feature = "fetch")]
fn path_for(uri: &str) -> Result<std::path::PathBuf> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .ok_or_else(|| anyhow!("{uri} is not an http or https URI"))?;
    let mut path = std::path::PathBuf::new();
    for segment in rest.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(anyhow!(
                "{uri} has a path segment that cannot be committed as a file"
            ));
        }
        let safe: String = segment
            .chars()
            .map(
                |c| match c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    true => c,
                    false => '_',
                },
            )
            .collect();
        path.push(safe);
    }
    Ok(path)
}

/// Record the walk date, which is also the date the store is validated at.
#[cfg(feature = "fetch")]
fn write_collected(crate_dir: &Path, date: &str) -> Result<()> {
    let dir = crate_dir.join(format!("provenance/{ENV}"));
    fs::create_dir_all(&dir).with_context(|| format!("{} could not be created", dir.display()))?;
    let path = dir.join("collected.txt");
    fs::write(&path, date).with_context(|| format!("{} could not be written", path.display()))
}

/// Record what the walk reached that the store does not carry, one per line.
///
/// A file rather than a log line because it is what a reviewer of a refresh looks at: a CA
/// expiring, or a publisher leaving an expired cross-certificate in its bundle, shows here.
#[cfg(feature = "fetch")]
fn write_dropped(crate_dir: &Path, dropped: &[core::Dropped]) -> Result<()> {
    let path = crate_dir.join(format!("provenance/{ENV}/dropped.txt"));
    if dropped.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let mut body = String::from(
        "# Certificates the walk reached that this store does not carry, with the reason.\n\
         # Written by certval-store-gen; a change here is a change in what the mesh publishes,\n\
         # not in this crate.\n\
         #\n\
         # unrooted     reached, but no partial path from the committed anchor includes it,\n\
         #              which includes one stranded when another certificate was dropped\n\
         # unvalidated  a path to the anchor exists and none validated as of the walk date;\n\
         #              an InvalidNotAfterDate here is a certificate the publisher still serves\n\
         #              after it expired\n",
    );
    for d in dropped {
        match &d.reason {
            core::DropReason::Unrooted => body.push_str(&format!("unrooted     {}\n", d.name)),
            core::DropReason::Unvalidated(why) => {
                body.push_str(&format!("unvalidated  {}  {why}\n", d.name))
            }
        }
    }
    fs::write(&path, body).with_context(|| format!("{} could not be written", path.display()))
}

#[cfg(all(test, feature = "fetch"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_uri_maps_to_its_host_and_path() {
        assert_eq!(
            path_for("http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c").unwrap(),
            PathBuf::from("repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c")
        );
        assert_eq!(
            path_for("http://pki.treasury.gov/root_sia.p7c?x=1").unwrap(),
            PathBuf::from("pki.treasury.gov/root_sia.p7c_x_1")
        );
    }

    #[test]
    fn a_uri_cannot_name_a_path_outside_the_folder() {
        assert!(path_for("http://example.com/../escape.p7c").is_err());
        assert!(path_for("http://example.com//double.p7c").is_err());
        assert!(path_for("ldap://example.com/x.p7c").is_err());
    }
}

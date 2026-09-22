//! Writing a generated store into a `certval_stores_*` provider crate's layout.
//!
//! A provider crate does not consume a `ta.cbor`: it embeds each root as its own DER file via
//! `include_bytes!`, keeps the intermediates as loose DER beside the CBOR store built from them,
//! and its conformance tests assert that those three agree. So generation has to write the same
//! three things:
//!
//! ```text
//! roots/<env>/<label>.der          one per trust anchor, embedded by lib.rs
//! cas/<env>/<label>.der            one per intermediate, checked against the store
//! cas/<env>/<env>.cbor             the store built from exactly those intermediates
//! provenance/<env>/published.txt   the source's own date, where it states one
//! provenance/<env>/collected.txt   the day this material was taken
//! ```
//!
//! The two dates are files rather than lines in `lib.rs` for the same reason the material
//! is: a refresh writes them, so they cannot be left behind by a hand edit that forgot
//! them. The provider `include_str!`s each one into `StoreEntry::published` /
//! `StoreEntry::collected`, and a frontend shows them as how current the store is.
//!
//! Writing is preceded by a diff against whatever the crate holds today, because these files are
//! reviewed material: the point of a regeneration is that a human can see what the publisher
//! changed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use der::Decode;
use x509_cert::Certificate;

use certval::CertFile;

use crate::core::GeneratedStore;

/// What a regeneration would change, by certificate rather than by file.
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: usize,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Compare the certificates about to be written against those already in `dir`.
///
/// Identity is the DER itself, so a re-issued certificate — same subject, same key, new serial —
/// shows up as one addition and one removal rather than as no change at all. Descriptions carry
/// the serial for exactly that case.
pub fn diff(dir: &Path, generated: &[CertFile]) -> Result<Diff> {
    let existing = read_der_dir(dir)?;
    let new: BTreeMap<Vec<u8>, String> = generated
        .iter()
        .map(|cf| (cf.bytes.clone(), describe(&cf.bytes)))
        .collect();

    let added = new
        .iter()
        .filter(|(bytes, _)| !existing.contains_key(*bytes))
        .map(|(_, d)| d.clone())
        .collect::<Vec<_>>();
    let removed = existing
        .iter()
        .filter(|(bytes, _)| !new.contains_key(*bytes))
        .map(|(_, d)| d.clone())
        .collect::<Vec<_>>();
    let unchanged = new.len() - added.len();

    Ok(Diff {
        added,
        removed,
        unchanged,
    })
}

/// Whether an environment keeps its intermediates as loose DER beside the CBOR store.
///
/// The DER is for review and nothing reads it back: the crate embeds the roots and loads the
/// store, so this decides what a regeneration's diff looks like, not what ships.
pub enum Intermediates {
    /// Written as files as well as into the store, so a refresh shows which certificates changed.
    /// Right where a publisher has dozens.
    AsFiles,
    /// Only in the store. Right where a publisher has thousands: `TrustedTpm.cab` yields 2,480,
    /// and committing them loose means ten megabytes of the same certificates twice over, in a
    /// diff no one can read. What replaces the review is the check that regenerates the store from
    /// the committed cabinet and compares -- stronger than reading DER, and it runs in CI.
    InStoreOnly,
}

/// One generated environment's material, as it goes to disk.
///
/// Grouped rather than passed as four more parameters: they travel together, and every call site
/// writes exactly one environment's worth.
pub struct Material<'a> {
    pub anchors: &'a [CertFile],
    pub intermediates: &'a [CertFile],
    /// Whether the intermediates are also written as loose DER for review.
    pub loose: Intermediates,
    pub store: &'a GeneratedStore,
}

/// Write the roots, the intermediates and the CBOR store into the provider layout, replacing any
/// DER already there.
///
/// The old files are removed rather than merged over: the stream is the material of record, so a
/// file it no longer publishes is stale, and leaving it behind would put it back into the store on
/// the next generation.
pub fn write(
    crate_dir: &Path,
    env: &str,
    store_name: &str,
    material: Material<'_>,
    provenance: &Provenance,
) -> Result<()> {
    let Material {
        anchors,
        intermediates,
        loose,
        store,
    } = material;
    let roots_dir = crate_dir.join("roots").join(env);
    let cas_dir = crate_dir.join("cas").join(env);

    write_der_dir(&roots_dir, anchors, true)?;
    match loose {
        Intermediates::AsFiles => write_der_dir(&cas_dir, intermediates, false)?,
        // Still swept: switching an environment to this mode has to remove the files it wrote
        // before, or the crate ships a directory of certificates nothing generated.
        Intermediates::InStoreOnly => write_der_dir(&cas_dir, &[], false)?,
    }

    match &store.ca_cbor {
        Some(bytes) => {
            let path = cas_dir.join(format!("{store_name}.cbor"));
            std::fs::write(&path, bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
            log::info!("wrote {} ({} bytes)", path.display(), bytes.len());
        }
        None => log::info!("no intermediates; wrote no CA store"),
    }
    write_provenance(crate_dir, env, provenance)?;
    Ok(())
}

/// Today's date in UTC as `YYYY-MM-DD`, the default collection date.
///
/// UTC rather than local time because the date is compared against the publisher's own date --
/// a timestamp authority's `genTime` for an InstallRoot stream -- which is UTC, and
/// `check_entry_shape` rejects a store collected before it was published, which a westward local
/// date could manufacture out of nothing.
///
/// Here rather than in the CLI because a provider crate's `build.rs` writes the same file
/// when it regenerates, and two implementations of "today" is one more than the number of
/// answers the question has.
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dt = der::DateTime::from_unix_duration(std::time::Duration::from_secs(secs))
        .expect("the current time is within the range DateTime covers");
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month(), dt.day())
}

/// The two dates written beside a generated environment.
pub struct Provenance {
    /// What the source says about when it published this material, `YYYY-MM-DD`, or `None`
    /// where it says nothing. Comes from the adapter — the `installroot` one reads it off the
    /// verified timestamp on the stream's members — never from the machine running the generator.
    pub published: Option<String>,
    /// The day the material was collected from the source, `YYYY-MM-DD`.
    pub collected: String,
}

/// Write `provenance/<env>/{published,collected}.txt`.
///
/// No trailing newline, because the provider reads these with `include_str!` and shows the
/// result to a user; the receiving end trims anyway, and the conformance suite rejects a
/// date that is not exactly `YYYY-MM-DD`, so this is belt and braces on a file a person
/// might also edit.
///
/// A publication date that is not known removes the file rather than writing an empty one:
/// the provider distinguishes "no date" from "the empty date", and a stale file left from a
/// generation that did know one would be worse than either.
fn write_provenance(crate_dir: &Path, env: &str, provenance: &Provenance) -> Result<()> {
    let dir = crate_dir.join("provenance").join(env);
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let published = dir.join("published.txt");
    match &provenance.published {
        Some(date) => {
            std::fs::write(&published, date)
                .with_context(|| format!("failed to write {}", published.display()))?;
            log::info!("wrote {} ({date})", published.display());
        }
        None if published.exists() => {
            std::fs::remove_file(&published)
                .with_context(|| format!("failed to remove {}", published.display()))?;
            log::info!(
                "{} removed: this source states no publication date",
                published.display()
            );
        }
        None => log::info!("the source states no publication date; wrote none"),
    }

    let collected = dir.join("collected.txt");
    std::fs::write(&collected, &provenance.collected)
        .with_context(|| format!("failed to write {}", collected.display()))?;
    log::info!("wrote {} ({})", collected.display(), provenance.collected);
    Ok(())
}

/// The `include_bytes!` lines for the roots just written, so the list in `lib.rs` can be brought
/// into step. The crate embeds each root explicitly, and its own conformance check fails when the
/// embedded list and the files disagree — which is the check doing its job, but it cannot write
/// the list.
pub fn include_bytes_lines(roots_dir: &Path) -> Result<String> {
    let env = roots_dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut names: Vec<String> = der_files(roots_dir)?
        .iter()
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    Ok(names
        .iter()
        .map(|n| format!("    include_bytes!(\"../roots/{env}/{n}.der\"),"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Write one directory's worth of DER.
///
/// `mint_names` decides what happens to a certificate that is already committed. Keeping its
/// existing filename is right for the intermediates: there are dozens, a person reviews the diff,
/// and respelling eighty unchanged names would bury the four that changed -- while the name is
/// only a label, since `CertFile` equality ignores it and path building indexes by SKID. Minting
/// is right for the roots: there are a handful, their `include_bytes!` list is regenerated
/// wholesale, and a set half hand-named and half generated reads as an accident.
fn write_der_dir(dir: &Path, certs: &[CertFile], mint_names: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let mut existing_name: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for path in der_files(dir)? {
        let bytes =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // A duplicate -- the same certificate committed under two names -- collapses to one file
        // here, keeping whichever name sorts first so the choice is not left to directory order.
        existing_name.entry(bytes).or_insert(stem);
    }

    // Stale files go first so a certificate the stream no longer publishes does not survive, and
    // so a rename cannot leave both spellings behind.
    for stale in der_files(dir)? {
        std::fs::remove_file(&stale)
            .with_context(|| format!("failed to remove {}", stale.display()))?;
    }

    let mut renamed = 0usize;
    for cf in certs {
        let name = match existing_name.get(&cf.bytes) {
            Some(kept) if !mint_names => kept.clone(),
            _ => {
                renamed += 1;
                cf.filename.clone()
            }
        };
        let path = dir.join(format!("{name}.der"));
        std::fs::write(&path, &cf.bytes)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    log::info!(
        "wrote {} certificate(s) to {} ({renamed} named by the generator)",
        certs.len(),
        dir.display()
    );
    Ok(())
}

fn der_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = vec![];
    if !dir.exists() {
        return Ok(out);
    }
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?
    {
        let path = entry?.path();
        if path.extension().map(|e| e == "der").unwrap_or(false) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn read_der_dir(dir: &Path) -> Result<BTreeMap<Vec<u8>, String>> {
    let mut out = BTreeMap::new();
    for path in der_files(dir)? {
        let bytes =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let description = describe(&bytes);
        out.insert(bytes, description);
    }
    Ok(out)
}

/// Subject and serial, which is what makes a re-issued certificate legible in a diff.
fn describe(der: &[u8]) -> String {
    match Certificate::from_der(der) {
        Ok(cert) => format!(
            "{} (serial {})",
            cert.tbs_certificate().subject(),
            cert.tbs_certificate().serial_number()
        ),
        Err(_) => "<does not parse as a certificate>".to_string(),
    }
}

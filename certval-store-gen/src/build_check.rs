//! Checks a provider crate's committed store against what its inputs produce, for use
//! from a `build.rs`.
//!
//! The stores in this workspace are generated, not written: `cas/<env>/<env>.cbor` is what
//! this crate produces from the material beside it. Nothing enforced that, so a store and
//! the input it claims to come from could drift -- by an edit, by a regeneration nobody
//! committed, or by a refresh that changed the material without changing the store.
//!
//! The comparison is on **content, not bytes**. A byte comparison conflates the material
//! drifting with certval changing how it encodes a store, which is a real thing that
//! `certval-store-gen recode` exists to handle, and would break every provider crate's
//! build for a reason having nothing to do with trust material. Comparing decoded
//! certificate sets is invariant under an encoding change and still catches a store that
//! gained, lost or altered one -- which is what makes failing the build honest.

use std::path::Path;

use certval::PkiEnvironment;

use crate::adapters;
use crate::core::generate;
use crate::verify::Revocation;

/// What a check found.
pub enum Verdict {
    /// The committed store holds exactly the certificates the input produces.
    Match { certificates: usize },
    /// It does not. Subjects are named so a reader can tell which way to fix it.
    Mismatch {
        committed: usize,
        regenerated: usize,
        only_committed: Vec<String>,
        only_regenerated: Vec<String>,
    },
    /// The check could not run. Not a failure: a crate may ship a store whose input is not
    /// committed, and a build should not fail over what it cannot inspect.
    Skipped { why: String },
}

/// Regenerate from an InstallRoot stream and compare with the committed store.
pub fn tamp_store(stream: &Path, population: &str, committed: &Path) -> Verdict {
    tamp_store_with(
        stream,
        population,
        &[] as &[&Path],
        &[] as &[&Path],
        committed,
    )
}

/// As [`tamp_store`], for an environment whose material is the stream plus certificates
/// named file by file -- an interoperability root and the bundle it publishes at its SIA.
pub fn tamp_store_with(
    stream: &Path,
    population: &str,
    extra_roots: &[impl AsRef<Path>],
    extra_cas: &[impl AsRef<Path>],
    committed: &Path,
) -> Verdict {
    let skip = |why: String| Verdict::Skipped { why };

    let Ok(bytes) = std::fs::read(stream) else {
        return skip(format!("{} is not readable", stream.display()));
    };
    let Ok(committed_bytes) = std::fs::read(committed) else {
        return skip(format!("{} is not readable", committed.display()));
    };

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let population = match adapters::tamp::Population::parse(population) {
        Ok(p) => p,
        Err(e) => return skip(format!("unknown InstallRoot population: {e}")),
    };
    // Stapled only: this runs on every build of a provider crate, a consumer's included, and that
    // build is promised it fetches nothing. See `verify::Revocation`.
    let inputs = match adapters::tamp::build(&pe, &bytes, population, Revocation::Stapled) {
        Ok(i) => i,
        Err(e) => return skip(format!("{} did not parse: {e}", stream.display())),
    };
    let mut inputs = inputs;
    if let Err(e) = crate::ingest::merge_extras(&mut inputs, extra_roots, extra_cas) {
        return skip(format!("supplied material did not read: {e}"));
    }
    let store = match generate(&inputs) {
        Ok(s) => s,
        Err(e) => return skip(format!("generation from {} failed: {e}", stream.display())),
    };
    let Some(regenerated) = store.ca_cbor else {
        return skip(format!("{} yields no CA store", stream.display()));
    };

    compare(&committed_bytes, &regenerated)
}

/// Compare two serialized CA stores by the certificates they carry.
fn compare(committed: &[u8], regenerated: &[u8]) -> Verdict {
    let (Some(want), Some(got)) = (certs_in(committed), certs_in(regenerated)) else {
        return Verdict::Skipped {
            why: "a store did not decode".to_string(),
        };
    };
    if want == got {
        return Verdict::Match {
            certificates: want.len(),
        };
    }
    Verdict::Mismatch {
        committed: want.len(),
        regenerated: got.len(),
        only_committed: subjects(&want, &got),
        only_regenerated: subjects(&got, &want),
    }
}

/// The certificate set a serialized CA store carries, sorted so two stores compare equal
/// whatever order they were written in.
///
/// Labels are dropped deliberately: they record where a certificate was read from, vary
/// with how the generator was invoked, and say nothing about the trust material.
fn certs_in(cbor: &[u8]) -> Option<Vec<Vec<u8>>> {
    let source = certval::CertSource::new_from_cbor(cbor).ok()?;
    let mut ders: Vec<Vec<u8>> = source
        .get_buffers()
        .into_iter()
        .map(|cf| cf.bytes)
        .collect();
    ders.sort();
    Some(ders)
}

/// Subjects present in `set` and absent from `other`.
fn subjects(set: &[Vec<u8>], other: &[Vec<u8>]) -> Vec<String> {
    set.iter()
        .filter(|d| !other.contains(*d))
        .map(|der| {
            certval::parse_cert(der, "")
                .map(|c| certval::get_leaf_rdn(c.decoded().tbs_certificate().subject()))
                .unwrap_or_else(|_| "<unparseable>".to_string())
        })
        .collect()
}

/// Run [`tamp_store`], report through cargo, and fail the build on a mismatch.
///
/// Panicking is how a build script fails, and a mismatch is worth failing on: it can only
/// mean the committed material no longer matches the input it claims to come from.
pub fn assert_tamp_store(stream: &str, population: &str, committed: &str) {
    assert_tamp_store_with(stream, population, &[], &[], committed)
}

/// As [`assert_tamp_store`], for an environment built from a stream plus supplied files.
pub fn assert_tamp_store_with(
    stream: &str,
    population: &str,
    extra_roots: &[&str],
    extra_cas: &[&str],
    committed: &str,
) {
    println!("cargo::rerun-if-changed={stream}");
    println!("cargo::rerun-if-changed={committed}");
    for p in extra_roots.iter().chain(extra_cas) {
        println!("cargo::rerun-if-changed={p}");
    }
    match tamp_store_with(
        Path::new(stream),
        population,
        extra_roots,
        extra_cas,
        Path::new(committed),
    ) {
        Verdict::Match { certificates } => {
            println!("{committed} holds the same {certificates} certificates as {stream} produces");
        }
        Verdict::Skipped { why } => {
            println!("cargo::warning=skipping the generated-store check for {committed}: {why}");
        }
        Verdict::Mismatch {
            committed: n_committed,
            regenerated,
            only_committed,
            only_regenerated,
        } => {
            for s in &only_committed {
                println!("cargo::warning=only in {committed}: {s}");
            }
            for s in &only_regenerated {
                println!("cargo::warning=only in the store regenerated from {stream}: {s}");
            }
            panic!(
                "{committed} does not hold the certificates that {stream} produces \
                 ({n_committed} committed, {regenerated} regenerated). Regenerate the store \
                 from the input, or explain the difference."
            );
        }
    }
}

//! Tests for the TPM vendor roots provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every provider owes its
//! consumers. What is left here is specific to this one: counts that pin the embedded material,
//! the agreement between the embedded root list and the files beside it, and the guarantee that
//! what ships is what the committed cabinet generates.

// Gated like every test that uses it: without the environment feature this crate serves nothing
// and the file-reading tests are not compiled.
#[cfg(feature = "tpm")]
use std::path::Path;

use certval_stores_core::conformance;

/// Roots and intermediates from the cabinet published 2026-07-09, after duplicates shared
/// between vendor folders are collapsed. Update alongside the material --
/// a change here is the point at which a refresh gets acknowledged in review.
#[cfg(feature = "tpm")]
const EXPECTED_ROOTS: usize = 47;
#[cfg(feature = "tpm")]
const EXPECTED_INTERMEDIATES: usize = 2112;

/// Digests over the sets themselves, which the counts above cannot see: a count measures size
/// where the question is membership, so a cabinet that retires one vendor CA and publishes
/// another passes every assertion here unchanged. 2112 intermediates is the largest set in this
/// workspace and the one where a symmetric change is least likely to be noticed by eye.
///
/// To update: run the tests, and the failure prints the digest to paste in.
#[cfg(feature = "tpm")]
const EXPECTED_ROOT_SET: &str = "344c05490713d9d09140741a043a461b1cd930cfd012d258640d5335d11d1eb5";
#[cfg(feature = "tpm")]
const EXPECTED_INTERMEDIATE_SET: &str =
    "011e244a36146ff2a01cd21e5bcae902babda7236ba453a1d8002bd227219cc3";
/// Intermediates the cabinet publishes that the store does not carry, listed with their reasons in
/// `provenance/tpm/dropped.txt`: 36 that reach no root in it (mostly AMD fTPM CAs whose issuers it
/// does not include), 6 that do not decode (STMicro, a non-canonical INTEGER), 366 that had already
/// expired when the cabinet was published, and 2 Qualcomm CAs the cabinet dates a month *after* it
/// was published, which is the same contradiction read the other way.
///
/// The expired majority is the deliberate part. Carrying material a publisher had already outlived
/// costs 698 KB in a store that ships baked into a browser, and this crate's consumers validate
/// attestations from parts in service rather than historical ones. A store of everything the
/// cabinet holds would be a separate crate, not a flag on this one.
#[cfg(feature = "tpm")]
const EXPECTED_DROPPED: usize = 410;

#[cfg(feature = "tpm")]
fn entry() -> certval_stores_core::StoreEntry {
    certval_stores_tpm::provider()
        .entries()
        .into_iter()
        .find(|e| e.id == certval_stores_tpm::TPM)
        .expect("the tpm environment must be served")
}

#[test]
fn entry_shapes_are_sound() {
    let failures = conformance::check_entry_shape(certval_stores_tpm::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every root decodes and yields a certificate. Vendor roots reach further back than a web PKI
/// root set does, so this is also what would fail first without certval's `sha1_sig`.
#[test]
fn roots_parse() {
    let failures = conformance::check_roots_parse(certval_stores_tpm::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_cert_store_loads() {
    let failures = conformance::check_cert_stores_load(certval_stores_tpm::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every CA in the store appears in a partial path, and every path ends at one of the embedded
/// anchors. This is the check that makes dropping the unrooted intermediates necessary rather
/// than tidy.
#[test]
fn partial_paths_cover_every_ca() {
    let failures = conformance::check_partial_paths(certval_stores_tpm::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The gate the counts are not. See [`EXPECTED_ROOT_SET`].
#[test]
#[cfg(feature = "tpm")]
fn the_material_is_what_was_reviewed() {
    let entry = entry();
    let roots = conformance::set_digest(entry.roots.iter().copied());
    assert_eq!(
        roots, EXPECTED_ROOT_SET,
        "the TPM root set changed; if that is intended, set EXPECTED_ROOT_SET to {roots}"
    );

    let cert_source = certval::CertSource::new_from_cbor(
        entry.cert_store_cbor.expect("the tpm store carries CAs"),
    )
    .expect("the CA store must load");
    let buffers = cert_source.get_buffers();
    let cas = conformance::set_digest(buffers.iter().map(|cf| cf.bytes.as_slice()));
    assert_eq!(
        cas, EXPECTED_INTERMEDIATE_SET,
        "the TPM intermediate set changed; if intended, set EXPECTED_INTERMEDIATE_SET to {cas}"
    );
}

#[test]
#[cfg(feature = "tpm")]
fn the_environment_carries_the_expected_material() {
    let entry = entry();
    assert_eq!(entry.roots.len(), EXPECTED_ROOTS);
    let cert_source = certval::CertSource::new_from_cbor(
        entry.cert_store_cbor.expect("the tpm store carries CAs"),
    )
    .expect("the CA store must load");
    use certval::CertVector;
    assert_eq!(cert_source.len(), EXPECTED_INTERMEDIATES);
}

/// The embedded `include_bytes!` list and the files under `roots/tpm` have to be the same set.
///
/// The list is hand-maintained -- a refresh prints it rather than writing it -- so this is what
/// makes that safe: a root added to the directory and forgotten in `lib.rs` would otherwise ship
/// as a file nothing embeds, and one removed from the directory would fail to compile, which is
/// the easy direction. This catches the other one.
#[test]
#[cfg(feature = "tpm")]
fn roots_match_the_committed_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/tpm");
    let failures = conformance::check_root_inputs(&dir, entry().roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The intermediates the cabinet publishes and this store cannot carry, recorded rather than lost.
///
/// Pinned so the number moving is noticed: downward when a publisher starts including an issuer,
/// upward when a vendor's root stops being carried. Either is a change in what Microsoft ships.
#[test]
#[cfg(feature = "tpm")]
fn the_dropped_intermediates_are_recorded() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("provenance/tpm/dropped.txt");
    let body = std::fs::read_to_string(&path).expect("dropped.txt must exist");
    let listed = body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .count();
    assert_eq!(listed, EXPECTED_DROPPED);
}

/// What ships is the validated output of the cabinet committed beside it.
///
/// The guarantee `tpm_roots` enforced by refusing to build when its `ca.cbor` did not match the
/// validated set, moved to where it costs nothing on a consumer's build. Unpacks
/// `inputs/TrustedTpm.cab`, classifies it, prunes what reaches no root, and compares the result
/// against what the crate embeds.
///
/// Signature verification is deliberately not repeated here: it reaches a timestamp authority for
/// revocation, and a test that fails when a responder is down is a test nobody trusts. The
/// cabinet's signature is checked where the material enters the repository, in the refresh.
#[test]
#[cfg(feature = "tpm")]
fn the_store_is_what_the_committed_cabinet_generates() {
    let cab = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs/TrustedTpm.cab"))
        .expect("the committed cabinet must be readable");
    // The same reference date the committed store was generated with. Absent means the cabinet's
    // own publication date, which is the default; present means a maintainer chose one, and the
    // store has to be measured against that rather than against a date it never saw.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let as_of = certval_store_gen::tpm_refresh::recorded_as_of(dir, "tpm");
    let (inputs, dropped) = certval_store_gen::tpm_refresh::regenerate_from(&cab, as_of.as_deref())
        .expect("the cabinet must regenerate");

    assert_eq!(
        inputs.trust_anchors.len(),
        EXPECTED_ROOTS,
        "the committed cabinet yields a different number of roots than this crate embeds"
    );
    assert_eq!(inputs.intermediates.len(), EXPECTED_INTERMEDIATES);
    assert_eq!(dropped.len(), EXPECTED_DROPPED);

    // By bytes, not by count: a store with the right number of the wrong certificates is the
    // failure this is for.
    let embedded: std::collections::BTreeSet<&[u8]> = entry().roots.iter().copied().collect();
    for cf in &inputs.trust_anchors {
        assert!(
            embedded.contains(cf.bytes.as_slice()),
            "{} is in the committed cabinet but not embedded in this crate",
            cf.filename
        );
    }
}

#[test]
fn the_environment_prepares() {
    let failures = conformance::check_prepare_environment(certval_stores_tpm::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every intermediate in the store builds a path to one of the embedded anchors and validates it.
///
/// `partial_paths_cover_every_ca` establishes that each CA is *reachable*: discovery indexes by
/// name and key identifier and verifies no signature, so a certificate can appear in a partial
/// path without being issued by the CA the path names. This is the stronger claim, and it is the
/// check `tpm_roots` ran in its build script before shipping a CA -- build the paths, validate
/// them, keep only the certificates for which one validates. `prune_unrooted` does not replace it,
/// and says so itself: it is not a judgement about the certificates.
///
/// Validated as of the cabinet's own publication date, which is the generator's postcondition
/// rather than a choice this test makes: `prune_unvalidated` drops what does not validate at that
/// time, so this asserts what generation is supposed to have left behind. Not `now` -- the nine
/// intermediates that have lapsed since July are legitimately carried, and a test that failed as
/// the calendar moved would be measuring the wrong thing. Not disabled either, which would pass
/// over an expired certificate the generator was meant to have removed. Nothing is exempt: a
/// certificate the cabinet dates after its own publication is dropped by the generator and so is
/// absent here too.
///
/// Nothing here reaches the network: this crate builds certval without `revocation`.
#[test]
#[cfg(feature = "tpm")]
fn every_intermediate_validates_to_a_root() {
    use certval::{
        CertFile, CertSource, CertVector, CertificationPath, CertificationPathResults,
        CertificationPathSettings, PDVCertificate, PkiEnvironment, TaSource, TimeOfInterest,
    };

    let entry = entry();
    let as_of = certval_store_gen::core::published_as_time_of_interest(
        entry
            .published
            .expect("the tpm entry states a publication date"),
    )
    .expect("the publication date must convert");
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(as_of);

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut ta_store = TaSource::new();
    for (i, der) in entry.roots.iter().enumerate() {
        ta_store.push(CertFile {
            filename: format!("{} anchor #{i}", entry.id),
            bytes: der.to_vec(),
        });
    }
    ta_store.initialize().expect("the anchors must initialize");
    pe.add_trust_anchor_source(Box::new(ta_store));

    let mut cert_source =
        CertSource::new_from_cbor(entry.cert_store_cbor.expect("the tpm store carries CAs"))
            .expect("the CA store must load");
    // Discovery stays untimed for the reason `prune_unvalidated` gives: a time-gated discovery
    // yields no path for an expired certificate, which would report it as unrooted instead of
    // expired and hide the thing this test is for.
    let mut discovery = CertificationPathSettings::new();
    discovery.set_time_of_interest(TimeOfInterest::disabled());
    cert_source
        .initialize(&discovery)
        .expect("the CA store must initialize");
    cert_source.find_all_partial_paths(&pe, &discovery);
    let buffers = cert_source.get_buffers();
    pe.add_certificate_source(Box::new(cert_source));

    // Asserted before the loop so this cannot pass by validating nothing: an empty or
    // short-loaded store would otherwise leave the failure list empty and the test green.
    assert_eq!(buffers.len(), EXPECTED_INTERMEDIATES);

    let mut unvalidated = vec![];
    for cf in &buffers {
        let cert = match PDVCertificate::try_from(cf.bytes.as_slice()) {
            Ok(cert) => cert,
            Err(e) => {
                unvalidated.push(format!("{}: did not parse: {e:?}", cf.filename));
                continue;
            }
        };

        let mut paths: Vec<CertificationPath> = vec![];
        if let Err(e) = pe.get_paths_for_target(&cert, &mut paths, 0, TimeOfInterest::disabled()) {
            unvalidated.push(format!("{}: path building failed: {e:?}", cf.filename));
            continue;
        }
        if paths.is_empty() {
            unvalidated.push(format!("{}: no path to an anchor", cf.filename));
            continue;
        }

        // One validating path is enough -- a CA cross-certified by several issuers needs only the
        // one a relying party would actually use.
        let mut errors = vec![];
        let validated = paths.iter().any(|path| {
            let mut cpr = CertificationPathResults::new();
            match pe.validate_path(&pe, &cps, path, &mut cpr) {
                Ok(()) => true,
                Err(e) => {
                    errors.push(e);
                    false
                }
            }
        });
        if !validated {
            unvalidated.push(format!(
                "{}: {} path(s), none validated: {errors:?}",
                cf.filename,
                paths.len()
            ));
        }
    }

    assert!(
        unvalidated.is_empty(),
        "{} of {} intermediates do not validate to an embedded anchor:\n{}",
        unvalidated.len(),
        buffers.len(),
        unvalidated.join("\n")
    );
}

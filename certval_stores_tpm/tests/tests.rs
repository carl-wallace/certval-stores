//! Tests for the TPM vendor roots provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every provider owes its
//! consumers. What is left here is specific to this one: counts that pin the embedded material,
//! the agreement between the embedded root list and the files beside it, and the guarantee that
//! what ships is what the committed cabinet generates.

use std::path::Path;

use certval_stores_core::conformance;

/// Roots and intermediates from the cabinet published 2026-07-09, after duplicates shared
/// between vendor folders are collapsed. Update alongside the material --
/// a change here is the point at which a refresh gets acknowledged in review.
#[cfg(feature = "tpm")]
const EXPECTED_ROOTS: usize = 47;
#[cfg(feature = "tpm")]
const EXPECTED_INTERMEDIATES: usize = 2480;
/// Intermediates the cabinet publishes that reach no root in it, listed in
/// `provenance/tpm/dropped.txt`. Mostly AMD fTPM CAs whose issuers it does not include.
#[cfg(feature = "tpm")]
const EXPECTED_DROPPED: usize = 42;

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
    let (inputs, dropped) =
        certval_store_gen::tpm_refresh::regenerate_from(&cab).expect("the cabinet must regenerate");

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

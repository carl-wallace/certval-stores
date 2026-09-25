//! Tests for the FPKI provider.
//!
//! These assert the shape of the embedded material and that it actually
//! deserializes — a corrupted or truncated `fpki.cbor` fails here rather than at
//! a consumer's first path build. The shared checks in
//! `certval_stores_core::conformance` cover the rest of what every provider owes
//! its consumers.
//!
//! There is no generator-input check here, unlike the other providers: the FPKI
//! store is built from a crawler bundle rather than from `.der` files kept
//! beside it, so there is nothing on disk to compare against. See `README.md`
//! for the refresh procedure.

#[cfg(any(feature = "fpki", feature = "fpki_legacy"))]
use std::path::Path;

#[cfg(feature = "fpki")]
use certval::{CertSource, CertVector};
use certval::{Error, PkiEnvironment, TaSource};
use certval_stores_core::{conformance, prepare_certval_environment, TrustStoreProvider};

/// The anchors an environment advertises, for the checks that take them
/// alongside the directory they were loaded from.
#[cfg(any(feature = "fpki", feature = "fpki_legacy"))]
fn roots_for(id: &str) -> &'static [&'static [u8]] {
    certval_stores_fpki::PROVIDER
        .entries()
        .iter()
        .find(|e| e.id == id)
        .map(|e| e.roots)
        .unwrap_or_else(|| panic!("the enabled features must yield a {id} entry"))
}

/// Number of intermediate CA certificates in the embedded FPKI CA store. Update
/// this with the store; see README.md for the refresh procedure.
#[cfg(feature = "fpki")]
const EXPECTED_INTERMEDIATES: usize = 133;
/// Digest over the intermediate set, which the count above cannot see. The FPKI crawler
/// republishes whenever any participant's cross-certificates change, so a refresh that swaps one
/// cross-certificate for another leaves the count identical and the mesh materially different.
///
/// To update: run the tests, and the failure prints the digest to paste in.
#[cfg(feature = "fpki")]
const EXPECTED_INTERMEDIATE_SET: &str =
    "a2cf31cd0cfd07258203b8830c8c069f5f8139a7c92a623e5d9f14e15199dfa5";

/// The gate the count is not. See [`EXPECTED_INTERMEDIATE_SET`].
#[test]
#[cfg(feature = "fpki")]
fn the_intermediate_set_is_what_was_reviewed() {
    let entries = certval_stores_fpki::PROVIDER.entries();
    let cbor = entries
        .iter()
        .find(|e| e.id == certval_stores_fpki::FPKI)
        .and_then(|e| e.cert_store_cbor)
        .expect("FPKI entry must carry a CA store");
    let mut cert_source = CertSource::new_from_cbor(cbor).expect("fpki.cbor must deserialize");
    cert_source
        .initialize(&Default::default())
        .expect("fpki.cbor must initialize");
    let buffers = cert_source.get_buffers();
    let actual = conformance::set_digest(buffers.iter().map(|cf| cf.bytes.as_slice()));
    assert_eq!(
        actual, EXPECTED_INTERMEDIATE_SET,
        "the FPKI intermediate set changed; if intended, set EXPECTED_INTERMEDIATE_SET to {actual}"
    );
}

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_fpki::provider()]
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_fpki::provider());
}

#[test]
#[cfg(feature = "fpki")]
fn fpki_entry_has_one_anchor_and_a_ca_store() {
    let entries = certval_stores_fpki::PROVIDER.entries();
    let fpki = entries
        .iter()
        .find(|e| e.id == certval_stores_fpki::FPKI)
        .expect("the fpki feature must yield an FPKI entry");

    // The FPKI is anchored at a single root by design, not by omission.
    assert_eq!(fpki.roots.len(), 1);
    assert!(!fpki.roots[0].is_empty());
    assert!(fpki.cert_store_cbor.is_some());
}

#[test]
#[cfg(feature = "fpki")]
fn embedded_ca_store_deserializes_and_initializes() {
    let entries = certval_stores_fpki::PROVIDER.entries();
    let cbor = entries
        .iter()
        .find(|e| e.id == certval_stores_fpki::FPKI)
        .and_then(|e| e.cert_store_cbor)
        .expect("FPKI entry must carry a CA store");

    let mut cert_source = CertSource::new_from_cbor(cbor).expect("fpki.cbor must deserialize");
    cert_source
        .initialize(&Default::default())
        .expect("fpki.cbor must initialize");
    assert_eq!(cert_source.len(), EXPECTED_INTERMEDIATES);
}

#[test]
#[cfg(feature = "fpki")]
fn prepare_environment_accepts_fpki() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    prepare_certval_environment(
        &providers(),
        &mut pe,
        &mut ta_store,
        certval_stores_fpki::FPKI,
    )
    .expect("FPKI must be a recognized store id");
    assert_eq!(ta_store.len(), 1);
}

#[test]
fn prepare_environment_rejects_unknown_environment() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    let r = prepare_certval_environment(&providers(), &mut pe, &mut ta_store, "NOT_AN_ENV");
    assert!(matches!(r, Err(Error::Unrecognized)));
}

#[test]
#[cfg(feature = "fpki_legacy")]
fn legacy_entry_is_anchors_only() {
    let entries = certval_stores_fpki::PROVIDER.entries();
    let legacy = entries
        .iter()
        .find(|e| e.id == certval_stores_fpki::FPKI_LEGACY)
        .expect("the fpki_legacy feature must yield an FPKI_LEGACY entry");

    assert_eq!(legacy.roots.len(), 1);
    // The G1 mesh is no longer published, so there is deliberately no CA store.
    assert!(legacy.cert_store_cbor.is_none());
}

/// The store has no generator inputs to check, but the anchors do have files on
/// disk, and they reach the crate through the `include_bytes!` list in
/// `src/lib.rs`, which the compiler only half-checks: remove a file and the
/// build breaks, add one and it ships looking like an anchor without being one.
/// Both environments here are single-anchor, so a second `.der` appearing in
/// either directory is the drift this catches.
#[test]
#[cfg(feature = "fpki")]
fn fpki_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/fpki");
    let failures = conformance::check_root_inputs(&dir, roots_for(certval_stores_fpki::FPKI));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "fpki_legacy")]
fn legacy_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/legacy");
    let failures =
        conformance::check_root_inputs(&dir, roots_for(certval_stores_fpki::FPKI_LEGACY));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Path *validation*, not just path building: signatures verified from the
/// anchor down. The environment comes from here rather than from the harness
/// because the crypto a store needs is the provider's business — this crate's
/// dev-dependency on certval enables `rsa` for that reason, and without it
/// certval reports every RSA-signed CA as unverifiable rather than failing
/// loudly. Settings are time-independent so this asks whether the material is
/// sound, not whether it is current.
#[test]
#[cfg(feature = "fpki")]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_fpki::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

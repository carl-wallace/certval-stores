//! Tests for the NIPR (DoD PKI) provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every
//! provider owes its consumers (roots parse for both certval and reqwest, the
//! CA store loads, its serialized partial paths cover every CA and are keyed and
//! rooted correctly, every advertised environment is accepted). What is left
//! here is NIPR-specific: the environment labels, which are the match keys
//! callers pass, counts that pin the embedded material so a root or CA cannot be
//! added or dropped silently, and the path validation the harness delegates to
//! each provider.

#[cfg(any(feature = "nipr", feature = "om_nipr"))]
use std::path::Path;

#[cfg(any(feature = "nipr", feature = "om_nipr"))]
use certval::{CertSource, CertVector};
use certval_stores_core::{conformance, get_roots, TrustStoreProvider};

/// Number of intermediate CAs in the embedded NIPR production store. Update
/// alongside the store.
#[cfg(feature = "nipr")]
const EXPECTED_NIPR_INTERMEDIATES: usize = 37;

/// Number of intermediate CAs in the embedded NIPR operational-test (JITC)
/// store. Update alongside the store.
#[cfg(feature = "om_nipr")]
const EXPECTED_OM_NIPR_INTERMEDIATES: usize = 45;

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_nipr::provider()]
}

/// Load an embedded store the way a consumer does, with time-of-interest checks
/// disabled so this counts what the store carries rather than what is currently
/// valid.
#[cfg(any(feature = "nipr", feature = "om_nipr"))]
fn load(cbor: &[u8]) -> CertSource {
    let mut cps = certval::CertificationPathSettings::new();
    cps.set_time_of_interest(certval::TimeOfInterest::disabled());
    let mut cert_source = CertSource::new_from_cbor(cbor).expect("store must deserialize");
    cert_source.initialize(&cps).expect("store must initialize");
    cert_source
}

#[cfg(any(feature = "nipr", feature = "om_nipr"))]
fn entry(env: &str) -> certval_stores_core::StoreEntry {
    certval_stores_nipr::PROVIDER
        .entries()
        .into_iter()
        .find(|e| e.env == env)
        .unwrap_or_else(|| panic!("the enabled features must yield a {env} entry"))
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_nipr::provider());
}

#[test]
#[cfg(feature = "nipr")]
fn nipr_entry_carries_three_roots_and_a_ca_store() {
    let nipr = entry("NIPR");
    assert_eq!(nipr.roots.len(), 3);
    let cert_source = load(nipr.cert_store_cbor.expect("NIPR must carry a CA store"));
    assert_eq!(cert_source.len(), EXPECTED_NIPR_INTERMEDIATES);
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_entry_carries_three_roots_and_a_ca_store() {
    let om = entry("OM_NIPR");
    assert_eq!(om.roots.len(), 3);
    let cert_source = load(om.cert_store_cbor.expect("OM_NIPR must carry a CA store"));
    assert_eq!(cert_source.len(), EXPECTED_OM_NIPR_INTERMEDIATES);
}

/// The shared checks are only worth running if they fail on a store that has
/// drifted, which needs real material to demonstrate: refile one CA's paths
/// under a key no certificate in the store has, and the store still loads, still
/// covers every buffer, and is still rooted correctly — but those paths are now
/// unreachable, because `get_paths_for_target` finds paths by that key.
#[test]
#[cfg(feature = "nipr")]
fn paths_filed_under_the_wrong_key_are_reported() {
    let nipr = entry("NIPR");
    let cbor = nipr.cert_store_cbor.expect("NIPR CA store");
    let mut bap: certval::BuffersAndPaths =
        ciborium::de::from_reader(cbor).expect("store must deserialize");

    let row = bap
        .partial_paths
        .first_mut()
        .expect("store must have paths");
    let key = row.keys().next().expect("row must have a key").clone();
    let paths = row.remove(&key).expect("key was just read");
    row.insert("DEADBEEF".to_string(), paths);

    let mut mangled = vec![];
    ciborium::ser::into_writer(&bap, &mut mangled).expect("store must serialize");
    let mangled: &'static [u8] = Box::leak(mangled.into_boxed_slice());

    struct Mangled(&'static [u8], &'static [&'static [u8]]);
    impl TrustStoreProvider for Mangled {
        fn entries(&self) -> Vec<certval_stores_core::StoreEntry> {
            vec![certval_stores_core::StoreEntry {
                env: "NIPR",
                roots: self.1,
                cert_store_cbor: Some(self.0),
            }]
        }
    }

    // Exactly one failure: refiling a key leaves coverage, rooting, indices and
    // row lengths intact, so anything else firing would mean the mangle broke
    // more than the one property under test.
    let failures = conformance::check_partial_paths(&Mangled(mangled, nipr.roots));
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(failures[0].contains("DEADBEEF"), "{failures:#?}");
}

/// `get_roots` is what a consumer hands to a TLS client, so it must expose every
/// anchor the provider advertises — no more (a duplicated `include_bytes!`) and
/// no fewer (an entry left out of the fold).
#[test]
fn get_roots_returns_every_advertised_anchor() {
    let expected: usize = certval_stores_nipr::PROVIDER
        .entries()
        .iter()
        .map(|e| e.roots.len())
        .sum();
    assert_eq!(get_roots(&providers()).len(), expected);
}

/// The `cas/<env>/*.der` files are the store generator's inputs: they ship but
/// nothing `include_bytes!`es them, so they drift from the store in silence.
#[test]
#[cfg(feature = "nipr")]
fn nipr_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/prod");
    let cbor = entry("NIPR").cert_store_cbor.expect("NIPR CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/om");
    let cbor = entry("OM_NIPR").cert_store_cbor.expect("OM_NIPR CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The `roots/<env>/*.der` files reach the crate through the `include_bytes!`
/// list in `src/lib.rs`, which the compiler only half-checks: remove a file and
/// the build breaks, add one and it ships looking like an anchor without being
/// one.
#[test]
#[cfg(feature = "nipr")]
fn nipr_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/prod");
    let failures = conformance::check_root_inputs(&dir, entry("NIPR").roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/om");
    let failures = conformance::check_root_inputs(&dir, entry("OM_NIPR").roots);
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
#[cfg(any(feature = "nipr", feature = "om_nipr"))]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_nipr::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

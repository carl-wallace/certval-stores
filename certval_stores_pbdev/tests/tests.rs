//! Tests for the Purebred development provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every
//! provider owes its consumers (roots parse for both certval and reqwest, the
//! CA store loads, its serialized partial paths cover every CA and are keyed and
//! rooted correctly, every advertised environment is accepted). What is left
//! here is dev-specific: the `DEV` environment label callers pass, counts that
//! pin the embedded material, and the path validation the harness delegates to
//! each provider.

#[cfg(feature = "dev")]
use std::path::Path;

#[cfg(feature = "dev")]
use certval::{CertSource, CertVector};
use certval_stores_core::{conformance, get_roots, TrustStoreProvider};

/// Number of intermediate CAs in the embedded dev store. Update alongside the
/// store.
#[cfg(feature = "dev")]
const EXPECTED_DEV_INTERMEDIATES: usize = 4;

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_pbdev::provider()]
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_pbdev::provider());
}

#[test]
#[cfg(feature = "dev")]
fn dev_entry_carries_two_roots_and_a_ca_store() {
    let entries = certval_stores_pbdev::PROVIDER.entries();
    let dev = entries
        .iter()
        .find(|e| e.env == "DEV")
        .expect("the dev feature must yield a DEV entry");

    assert_eq!(dev.roots.len(), 2);

    let mut cps = certval::CertificationPathSettings::new();
    cps.set_time_of_interest(certval::TimeOfInterest::disabled());
    let mut cert_source = CertSource::new_from_cbor(dev.cert_store_cbor.expect("DEV CA store"))
        .expect("dev.cbor must deserialize");
    cert_source
        .initialize(&cps)
        .expect("dev.cbor must initialize");
    assert_eq!(cert_source.len(), EXPECTED_DEV_INTERMEDIATES);
}

/// `get_roots` is what a consumer hands to a TLS client, so it must expose every
/// anchor the provider advertises — no more (a duplicated `include_bytes!`) and
/// no fewer (an entry left out of the fold).
#[test]
fn get_roots_returns_every_advertised_anchor() {
    let expected: usize = certval_stores_pbdev::PROVIDER
        .entries()
        .iter()
        .map(|e| e.roots.len())
        .sum();
    assert_eq!(get_roots(&providers()).len(), expected);
}

/// The `cas/dev/*.der` files are the store generator's inputs: they ship but
/// nothing `include_bytes!`es them, so they drift from the store in silence.
#[test]
#[cfg(feature = "dev")]
fn dev_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/dev");
    let entries = certval_stores_pbdev::PROVIDER.entries();
    let cbor = entries
        .iter()
        .find(|e| e.env == "DEV")
        .and_then(|e| e.cert_store_cbor)
        .expect("DEV CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
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
#[cfg(feature = "dev")]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_pbdev::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

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
fn dev_entry_carries_one_root_and_a_ca_store() {
    let entries = certval_stores_pbdev::provider().entries();
    let dev = entries
        .iter()
        .find(|e| e.id == certval_stores_pbdev::PUREBRED_DEV)
        .expect("the dev feature must yield a DEV entry");

    assert_eq!(dev.roots.len(), 1);

    let mut cps = certval::CertificationPathSettings::new();
    cps.set_time_of_interest(certval::TimeOfInterest::disabled());
    let mut cert_source = CertSource::new_from_cbor(dev.cert_store_cbor.expect("DEV CA store"))
        .expect("dev.cbor must deserialize");
    cert_source
        .initialize(&cps)
        .expect("dev.cbor must initialize");
    certval_stores_core::pin!(EXPECTED_DEV_INTERMEDIATES, cert_source.len());
}

/// `get_roots` is the provider's anchors as certval sees them, so it must expose
/// every anchor the provider advertises — no more (a duplicated `include_bytes!`) and
/// no fewer (an entry left out of the fold).
#[test]
fn get_roots_returns_every_advertised_anchor() {
    let expected: usize = certval_stores_pbdev::provider()
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
    let entries = certval_stores_pbdev::provider().entries();
    let cbor = entries
        .iter()
        .find(|e| e.id == certval_stores_pbdev::PUREBRED_DEV)
        .and_then(|e| e.cert_store_cbor)
        .expect("DEV CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The `roots/dev/*.der` files reach the crate through the `include_bytes!`
/// list in `src/lib.rs`, which the compiler only half-checks: remove a file and
/// the build breaks, add one and it ships looking like an anchor without being
/// one.
#[test]
#[cfg(feature = "dev")]
fn dev_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/dev");
    let entries = certval_stores_pbdev::provider().entries();
    let roots = entries
        .iter()
        .find(|e| e.id == certval_stores_pbdev::PUREBRED_DEV)
        .map(|e| e.roots)
        .expect("DEV anchors");
    let failures = conformance::check_root_inputs(&dir, roots);
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

/// `src/roots_dev.rs` is what `certval-store-gen` writes from the committed `roots/dev/`.
///
/// The roots of this crate change seldom, so the generator would otherwise go unexercised for
/// months at a time; this runs it on every build. The root-inputs check above then ties the
/// embedded list to the same files.
#[test]
fn the_root_list_matches_the_directory() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(e) = certval_store_gen::provider::check_roots_module(dir, "dev") {
        panic!("{e}");
    }
}

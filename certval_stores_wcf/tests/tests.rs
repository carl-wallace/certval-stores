//! Tests for the DoD WCF provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every
//! provider owes its consumers (roots parse for both certval and reqwest, the
//! CA store loads, its serialized partial paths cover every CA and are keyed and
//! rooted correctly, every advertised environment is accepted). What is left
//! here is WCF-specific: the environment label, which is the match key callers
//! pass, counts that pin the embedded material so a root or CA cannot be added
//! or dropped silently, the two-level shape of the store, and the path
//! validation the harness delegates to each provider.

#[cfg(feature = "wcf")]
use std::path::Path;

#[cfg(feature = "wcf")]
use certval::{CertSource, CertVector};
use certval_stores_core::{conformance, get_roots, TrustStoreProvider};

/// Number of intermediate CAs in the embedded WCF store, which is every CA the
/// `WCF.ir4` stream publishes: one intermediate and ten signing CAs beneath it.
/// Update alongside the store.
#[cfg(feature = "wcf")]
const EXPECTED_INTERMEDIATES: usize = 11;

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_wcf::provider()]
}

/// Load an embedded store the way a consumer does, with time-of-interest checks
/// disabled so this counts what the store carries rather than what is currently
/// valid.
#[cfg(feature = "wcf")]
fn load(cbor: &[u8]) -> CertSource {
    let mut cps = certval::CertificationPathSettings::new();
    cps.set_time_of_interest(certval::TimeOfInterest::disabled());
    let mut cert_source = CertSource::new_from_cbor(cbor).expect("store must deserialize");
    cert_source.initialize(&cps).expect("store must initialize");
    cert_source
}

#[cfg(feature = "wcf")]
fn entry(id: &str) -> certval_stores_core::StoreEntry {
    certval_stores_wcf::PROVIDER
        .entries()
        .into_iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("the enabled features must yield a {id} entry"))
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_wcf::provider());
}

#[test]
#[cfg(feature = "wcf")]
fn wcf_entry_carries_one_root_and_a_ca_store() {
    let wcf = entry(certval_stores_wcf::WCF);
    assert_eq!(wcf.roots.len(), 1);
    let cert_source = load(wcf.cert_store_cbor.expect("WCF must carry a CA store"));
    assert_eq!(cert_source.len(), EXPECTED_INTERMEDIATES);
}

/// The store is two deep: the root issues one intermediate and that intermediate
/// issues every signing CA. The serialized partial paths have to show that,
/// because a consumer building a path offline gets only what is serialized — a
/// signing CA filed with a one-certificate path would be a path that does not
/// reach the anchor.
///
/// Asserted as a distribution rather than per certificate so a re-issue that
/// renumbers the CAs does not need this edited, while adding a *third* level or
/// flattening one would fail it.
#[test]
#[cfg(feature = "wcf")]
fn every_signing_ca_is_two_certificates_from_the_anchor() {
    let wcf = entry(certval_stores_wcf::WCF);
    let cbor = wcf.cert_store_cbor.expect("WCF CA store");
    let store = conformance::RawStore::from_cbor(cbor);

    let mut lengths: Vec<usize> = store
        .partial_paths
        .iter()
        .flat_map(|row| row.values())
        .flatten()
        .map(|path| path.len())
        .collect();
    lengths.sort_unstable();

    let of_one = lengths.iter().filter(|&&n| n == 1).count();
    let of_two = lengths.iter().filter(|&&n| n == 2).count();
    assert_eq!(
        (1, 10),
        (of_one, of_two),
        "expected one 1-certificate path (the intermediate) and ten 2-certificate paths (the \
         signing CAs), got lengths {lengths:?}"
    );
    assert_eq!(
        EXPECTED_INTERMEDIATES,
        lengths.len(),
        "every CA must be reachable by exactly one path"
    );
}

/// The shared checks are only worth running if they fail on a store that has
/// drifted, which needs real material to demonstrate: refile one CA's paths
/// under a key no certificate in the store has, and the store still loads, still
/// covers every buffer, and is still rooted correctly — but those paths are now
/// unreachable, because `get_paths_for_target` finds paths by that key.
#[test]
#[cfg(feature = "wcf")]
fn paths_filed_under_the_wrong_key_are_reported() {
    let wcf = entry(certval_stores_wcf::WCF);
    let cbor = wcf.cert_store_cbor.expect("WCF CA store");
    // `conformance::RawStore` rather than `certval::BuffersAndPaths`, which is `#[readonly::make]`
    // and so cannot be edited from here -- and editing is the whole point.
    let mut store = conformance::RawStore::from_cbor(cbor);
    let row = store
        .partial_paths
        .first_mut()
        .expect("store must have paths");
    let key = row.keys().next().expect("row must have a key").clone();
    let paths = row.remove(&key).expect("key was just read");
    row.insert("DEADBEEF".to_string(), paths);
    let mangled = store.into_static_cbor();

    struct Mangled(&'static [u8], &'static [&'static [u8]]);
    impl TrustStoreProvider for Mangled {
        fn entries(&self) -> Vec<certval_stores_core::StoreEntry> {
            vec![certval_stores_core::StoreEntry {
                id: "dod_wcf",
                label: "Test",
                roots: self.1,
                cert_store_cbor: Some(self.0),
                published: None,
                collected: None,
            }]
        }
    }

    // Exactly one failure: refiling a key leaves coverage, rooting, indices and
    // row lengths intact, so anything else firing would mean the mangle broke
    // more than the one property under test.
    let failures = conformance::check_partial_paths(&Mangled(mangled, wcf.roots));
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(failures[0].contains("DEADBEEF"), "{failures:#?}");
}

/// `get_roots` is the provider's anchors as certval sees them, so it must expose
/// every anchor the provider advertises — no more (a duplicated `include_bytes!`) and
/// no fewer (an entry left out of the fold).
#[test]
fn get_roots_returns_every_advertised_anchor() {
    let expected: usize = certval_stores_wcf::PROVIDER
        .entries()
        .iter()
        .map(|e| e.roots.len())
        .sum();
    assert_eq!(get_roots(&providers()).len(), expected);
}

/// The `cas/prod/*.der` files are the store generator's outputs: they ship but
/// nothing `include_bytes!`es them, so they drift from the store in silence.
#[test]
#[cfg(feature = "wcf")]
fn generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/prod");
    let cbor = entry(certval_stores_wcf::WCF)
        .cert_store_cbor
        .expect("WCF CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The `roots/prod/*.der` files reach the crate through the `include_bytes!`
/// list in `src/lib.rs`, which the compiler only half-checks: remove a file and
/// the build breaks, add one and it ships looking like an anchor without being
/// one.
#[test]
#[cfg(feature = "wcf")]
fn root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/prod");
    let failures = conformance::check_root_inputs(&dir, entry(certval_stores_wcf::WCF).roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Path *validation*, not just path building: signatures verified from the
/// anchor down, and here that means through two certificates rather than one.
/// The environment comes from here rather than from the harness because the
/// crypto a store needs is the provider's business — this crate's dev-dependency
/// on certval enables `rsa` for that reason, and without it certval reports every
/// RSA-signed CA as unverifiable rather than failing loudly. Settings are
/// time-independent so this asks whether the material is sound, not whether it is
/// current.
#[test]
#[cfg(feature = "wcf")]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_wcf::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

/// Generated from `inputs/WCF.ir4`, whose members carry a verified RFC 3161 timestamp, so
/// both dates are knowable. See the same test in `certval_stores_nipr`.
#[test]
#[cfg(feature = "wcf")]
fn the_wcf_entry_carries_both_dates() {
    let wcf = entry(certval_stores_wcf::WCF);
    assert!(wcf.published.is_some(), "WCF.ir4 is timestamped");
    assert!(wcf.collected.is_some());
}

/// What ships is what the committed `WCF.ir4` generates.
///
/// The check `build.rs` ran on every build, moved to where it costs a consumer nothing. Stronger
/// than comparing the loose `cas/prod/*.der` files against the store, since the generator wrote
/// both of those and they agree even when neither matches the stream. This regenerates from
/// `inputs/WCF.ir4` -- the signed artifact of record.
///
/// `Skipped` fails here where a build script tolerated it: a build could not know whether a crate
/// ships an input at all, and this one does.
#[test]
#[cfg(feature = "wcf")]
fn the_store_is_what_the_committed_stream_generates() {
    use certval_store_gen::build_check::{tamp_store, Verdict};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let verdict = tamp_store(
        &dir.join("inputs/WCF.ir4"),
        "wcf",
        &dir.join("cas/prod/prod.cbor"),
    );
    match verdict {
        Verdict::Match { .. } => {}
        other => panic!("the committed store does not match what WCF.ir4 generates: {other:?}"),
    }
}

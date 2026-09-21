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

#[cfg(any(
    feature = "nipr",
    feature = "om_nipr",
    feature = "nipr_interop",
    feature = "nipr_cceb_interop"
))]
use std::path::Path;

#[cfg(any(
    feature = "nipr",
    feature = "om_nipr",
    feature = "nipr_interop",
    feature = "nipr_cceb_interop"
))]
use certval::{CertSource, CertVector};
use certval_stores_core::{conformance, get_roots, TrustStoreProvider};

/// Number of intermediate CAs in the embedded NIPR production store, which is every CA the
/// `DoD.ir4` stream publishes. Update alongside the store.
#[cfg(feature = "nipr")]
const EXPECTED_NIPR_INTERMEDIATES: usize = 41;

/// Number of intermediate CAs in the embedded NIPR operational-test (JITC/O&M) store, which is
/// the DoD population of the `JITC.ir4` stream. Update alongside the store.
#[cfg(feature = "om_nipr")]
const EXPECTED_OM_NIPR_INTERMEDIATES: usize = 53;

/// Intermediates in the NIPR + Interoperability store: the 41 the production stream publishes,
/// plus the five certificates DoD Interoperability Root CA 2 publishes at its own SIA (DoD Root
/// CA 3 and 6, ECA Root CA 4 and 5, Federal Bridge CA G4). Update alongside the store.
#[cfg(feature = "nipr_interop")]
const EXPECTED_NIPR_INTEROP_INTERMEDIATES: usize = 46;

/// Same shape for CCEB: 41 plus the four in US DoD CCEB Interoperability Root CA 2's bundle (DoD
/// Root CA 3 and 6, Australian Defence Interoperability CA, DND/MDN Canada). Update alongside
/// the store.
#[cfg(feature = "nipr_cceb_interop")]
const EXPECTED_NIPR_CCEB_INTEROP_INTERMEDIATES: usize = 45;

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_nipr::provider()]
}

/// Load an embedded store the way a consumer does, with time-of-interest checks
/// disabled so this counts what the store carries rather than what is currently
/// valid.
#[cfg(any(
    feature = "nipr",
    feature = "om_nipr",
    feature = "nipr_interop",
    feature = "nipr_cceb_interop"
))]
fn load(cbor: &[u8]) -> CertSource {
    let mut cps = certval::CertificationPathSettings::new();
    cps.set_time_of_interest(certval::TimeOfInterest::disabled());
    let mut cert_source = CertSource::new_from_cbor(cbor).expect("store must deserialize");
    cert_source.initialize(&cps).expect("store must initialize");
    cert_source
}

#[cfg(any(
    feature = "nipr",
    feature = "om_nipr",
    feature = "nipr_interop",
    feature = "nipr_cceb_interop"
))]
fn entry(id: &str) -> certval_stores_core::StoreEntry {
    certval_stores_nipr::PROVIDER
        .entries()
        .into_iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("the enabled features must yield a {id} entry"))
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_nipr::provider());
}

#[test]
#[cfg(feature = "nipr")]
fn nipr_entry_carries_four_roots_and_a_ca_store() {
    let nipr = entry(certval_stores_nipr::NIPR_PROD);
    assert_eq!(nipr.roots.len(), 4);
    let cert_source = load(nipr.cert_store_cbor.expect("NIPR must carry a CA store"));
    assert_eq!(cert_source.len(), EXPECTED_NIPR_INTERMEDIATES);
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_entry_carries_four_roots_and_a_ca_store() {
    let om = entry(certval_stores_nipr::NIPR_OM);
    assert_eq!(om.roots.len(), 4);
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
    let nipr = entry(certval_stores_nipr::NIPR_PROD);
    let cbor = nipr.cert_store_cbor.expect("NIPR CA store");
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
                id: "dod_nipr_prod",
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
    let failures = conformance::check_partial_paths(&Mangled(mangled, nipr.roots));
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(failures[0].contains("DEADBEEF"), "{failures:#?}");
}

/// `get_roots` is the provider's anchors as certval sees them, so it must expose
/// every anchor the provider advertises — no more (a duplicated `include_bytes!`) and
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
    let cbor = entry(certval_stores_nipr::NIPR_PROD)
        .cert_store_cbor
        .expect("NIPR CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/om");
    let cbor = entry(certval_stores_nipr::NIPR_OM)
        .cert_store_cbor
        .expect("OM_NIPR CA store");
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
    let failures =
        conformance::check_root_inputs(&dir, entry(certval_stores_nipr::NIPR_PROD).roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "om_nipr")]
fn om_nipr_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/om");
    let failures = conformance::check_root_inputs(&dir, entry(certval_stores_nipr::NIPR_OM).roots);
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
#[cfg(any(
    feature = "nipr",
    feature = "om_nipr",
    feature = "nipr_interop",
    feature = "nipr_cceb_interop"
))]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_nipr::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

/// Both environments are generated from an InstallRoot stream, so both dates are
/// knowable and a missing one means a refresh dropped them rather than that the
/// publisher said nothing. The published date is `TSTInfo.genTime` from the verified
/// RFC 3161 timestamp on the stream's members -- the streams assert no `signingTime`
/// of their own. The format itself is `conformance::check_entry_shape`'s job; what is
/// asserted here is that they are there at all.
#[test]
#[cfg(feature = "nipr")]
fn the_production_entry_carries_both_dates() {
    let nipr = entry(certval_stores_nipr::NIPR_PROD);
    assert!(nipr.published.is_some(), "DoD.ir4 is timestamped");
    assert!(nipr.collected.is_some());
}

#[test]
#[cfg(feature = "om_nipr")]
fn the_operational_test_entry_carries_both_dates() {
    let om = entry(certval_stores_nipr::NIPR_OM);
    assert!(om.published.is_some(), "JITC.ir4 is timestamped");
    assert!(om.collected.is_some());
}

// The interoperability environments. Each is NIPR plus exactly two things: a cross-certified
// root, and the bundle that root publishes at its own SIA. Neither appears in any `.ir4`
// message, so unlike `prod` and `om` this material can never be re-derived from a stream --
// which makes the checks below the only thing standing between a hand-carried root and a
// silent change to it.

#[test]
#[cfg(feature = "nipr_interop")]
fn nipr_interop_entry_carries_five_roots_and_a_ca_store() {
    let interop = entry(certval_stores_nipr::NIPR_INTEROP);
    // The four DoD roots plus DoD Interoperability Root CA 2.
    assert_eq!(interop.roots.len(), 5);
    let cert_source = load(
        interop
            .cert_store_cbor
            .expect("interop must carry a CA store"),
    );
    assert_eq!(cert_source.len(), EXPECTED_NIPR_INTEROP_INTERMEDIATES);
}

#[test]
#[cfg(feature = "nipr_cceb_interop")]
fn nipr_cceb_interop_entry_carries_five_roots_and_a_ca_store() {
    let cceb = entry(certval_stores_nipr::NIPR_CCEB_INTEROP);
    // The four DoD roots plus US DoD CCEB Interoperability Root CA 2.
    assert_eq!(cceb.roots.len(), 5);
    let cert_source = load(
        cceb.cert_store_cbor
            .expect("CCEB interop must carry a CA store"),
    );
    assert_eq!(cert_source.len(), EXPECTED_NIPR_CCEB_INTEROP_INTERMEDIATES);
}

/// The interoperability roots are hand-carried: DoD Interoperability Root CA 2 and US DoD CCEB
/// Interoperability Root CA 2 are published nowhere fetchable, so no refresh can rewrite
/// `roots/interop/` or `roots/cceb_interop/` and no generator can put them back. For these two
/// environments this check is not a stopgap until generation covers them — it is the mechanism.
#[test]
#[cfg(feature = "nipr_interop")]
fn nipr_interop_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/interop");
    let failures =
        conformance::check_root_inputs(&dir, entry(certval_stores_nipr::NIPR_INTEROP).roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "nipr_cceb_interop")]
fn nipr_cceb_interop_root_inputs_match_the_embedded_anchors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/cceb_interop");
    let failures =
        conformance::check_root_inputs(&dir, entry(certval_stores_nipr::NIPR_CCEB_INTEROP).roots);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "nipr_interop")]
fn nipr_interop_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/interop");
    let cbor = entry(certval_stores_nipr::NIPR_INTEROP)
        .cert_store_cbor
        .expect("interop CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[cfg(feature = "nipr_cceb_interop")]
fn nipr_cceb_interop_generator_inputs_match_the_store() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/cceb_interop");
    let cbor = entry(certval_stores_nipr::NIPR_CCEB_INTEROP)
        .cert_store_cbor
        .expect("CCEB interop CA store");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The dates come from the production stream both environments are built on, so they are as
/// knowable here as for `prod` — the supplied interop material carries no publication date of
/// its own and does not get to erase one.
#[test]
#[cfg(feature = "nipr_interop")]
fn the_interop_entry_carries_both_dates() {
    let interop = entry(certval_stores_nipr::NIPR_INTEROP);
    assert!(interop.published.is_some(), "DoD.ir4 is timestamped");
    assert!(interop.collected.is_some());
}

#[test]
#[cfg(feature = "nipr_cceb_interop")]
fn the_cceb_interop_entry_carries_both_dates() {
    let cceb = entry(certval_stores_nipr::NIPR_CCEB_INTEROP);
    assert!(cceb.published.is_some(), "DoD.ir4 is timestamped");
    assert!(cceb.collected.is_some());
}

/// Full subject of a DER-encoded certificate.
#[cfg(any(feature = "nipr_interop", feature = "nipr_cceb_interop"))]
fn subject_of(der: &[u8]) -> String {
    let cert = certval::parse_cert(der, "").expect("a committed certificate must parse");
    cert.decoded().tbs_certificate().subject().to_string()
}

/// Anchors that appear again in the CA store as a *different* certificate, by subject.
///
/// Asserts the certificates differ rather than assuming it: an anchor byte-identical to a store
/// entry would mean the generator filed a root as an intermediate, which is a different bug and
/// should not read as the doubling this is looking for.
#[cfg(any(feature = "nipr_interop", feature = "nipr_cceb_interop"))]
fn doubled_anchors(entry: &certval_stores_core::StoreEntry) -> Vec<String> {
    let anchors: Vec<(String, &[u8])> = entry
        .roots
        .iter()
        .map(|der| (subject_of(der), *der))
        .collect();

    let mut doubled = vec![];
    for cf in load(entry.cert_store_cbor.expect("an interop CA store")).get_buffers() {
        let subject = subject_of(&cf.bytes);
        if let Some((_, anchor)) = anchors.iter().find(|(s, _)| *s == subject) {
            assert_ne!(
                *anchor,
                cf.bytes.as_slice(),
                "{subject} is in both the anchors and the CA store as the same certificate; a \
                 root has been filed as an intermediate"
            );
            doubled.push(subject);
        }
    }
    doubled.sort();
    doubled
}

/// The doubled role, which is the whole mechanism of an interoperability environment and the
/// shape most likely to break quietly.
///
/// The interop root issued DoD Root CA 3 and DoD Root CA 6, so each exists twice: a self-signed
/// certificate that anchors a path, and a cross-certified one that continues a path up to the
/// interop root and out to the other side. Anchor and intermediate share a subject *and* a key
/// identifier, so a store that collapsed the two — or an anchor lookup that resolved to the
/// cross-certificate — would disable both anchors while every structural check still passed.
#[test]
#[cfg(feature = "nipr_interop")]
fn the_interop_store_carries_the_doubled_dod_roots() {
    let doubled = doubled_anchors(&entry(certval_stores_nipr::NIPR_INTEROP));
    assert_eq!(
        doubled.len(),
        2,
        "expected DoD Root CA 3 and DoD Root CA 6 to appear as anchors and again as \
         interop-issued intermediates, found {doubled:?}"
    );
    assert!(
        doubled.iter().any(|s| s.contains("DoD Root CA 3")),
        "{doubled:?}"
    );
    assert!(
        doubled.iter().any(|s| s.contains("DoD Root CA 6")),
        "{doubled:?}"
    );
}

#[test]
#[cfg(feature = "nipr_cceb_interop")]
fn the_cceb_interop_store_carries_the_doubled_dod_roots() {
    let doubled = doubled_anchors(&entry(certval_stores_nipr::NIPR_CCEB_INTEROP));
    assert_eq!(
        doubled.len(),
        2,
        "expected DoD Root CA 3 and DoD Root CA 6 to appear as anchors and again as \
         CCEB-issued intermediates, found {doubled:?}"
    );
    assert!(
        doubled.iter().any(|s| s.contains("DoD Root CA 3")),
        "{doubled:?}"
    );
    assert!(
        doubled.iter().any(|s| s.contains("DoD Root CA 6")),
        "{doubled:?}"
    );
}

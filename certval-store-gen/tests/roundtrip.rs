//! End-to-end check that stores produced by the real generation core load through the
//! same consumer APIs pittv3 (desktop and wasm) use: `TaSource::new_from_cbor` for
//! ta.cbor and `CertSource::new_from_cbor` for ca.cbor.

use std::path::PathBuf;

use certval::{CertSource, CertificationPathSettings, PkiEnvironment, TaSource, TimeOfInterest};

use certval_store_gen::adapters::{local, webpki};
use certval_store_gen::core::generate;

#[test]
fn webpki_ta_cbor_loads_in_consumer() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // Drive the real Web PKI adapter + core (roots-only: no intermediates).
    let inputs = webpki::build(&pe, webpki::Intermediates::None, TimeOfInterest::disabled())
        .expect("build webpki inputs");
    let expected = inputs.trust_anchors.len();
    assert!(expected > 0, "webpki produced no roots");
    assert!(inputs.intermediates.is_empty());

    let store = generate(&inputs).expect("generate store");
    assert!(
        store.ca_cbor.is_none(),
        "roots-only store must skip ca.cbor"
    );

    // Load ta.cbor exactly as pittv3 does.
    let mut loaded = TaSource::new_from_cbor(&store.ta_cbor).expect("TaSource::new_from_cbor");
    loaded.initialize().expect("initialize loaded TA source");
    assert_eq!(
        loaded.get_tas().len(),
        expected,
        "loaded TA count must match generated"
    );
}

/// Exercise the local-folders adapter (roots dir + intermediates dir) against a real
/// hierarchy and confirm both stores load through the pittv3 consumer APIs. Uses pb_pki's
/// NIPR-prod material when the sibling checkout is present; self-skips otherwise so the
/// test is safe in a standalone checkout / CI.
#[test]
fn local_folders_roundtrip() {
    let pb = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../carl-wallace/pb_pki");
    let ta_dir = pb.join("roots/NIPR/prod");
    let ca_dir = pb.join("cas/NIPR/prod");
    if !ta_dir.is_dir() || !ca_dir.is_dir() {
        eprintln!("skipping local_folders_roundtrip: pb_pki fixture not present at {pb:?}");
        return;
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let inputs = local::build(
        &pe,
        ta_dir.to_str().unwrap(),
        Some(ca_dir.to_str().unwrap()),
        TimeOfInterest::disabled(),
    )
    .expect("build local inputs");
    let n_ta = inputs.trust_anchors.len();
    let n_ca = inputs.intermediates.len();
    assert!(n_ta > 0 && n_ca > 0, "expected roots and intermediates");

    let store = generate(&inputs).expect("generate store");
    let ca_cbor = store.ca_cbor.expect("intermediates present -> ca.cbor");

    // No absolute source path (build-machine directory layout) must leak into the store.
    let leak = pb.to_str().unwrap().as_bytes();
    assert!(
        !windows_contains(&store.ta_cbor, leak) && !windows_contains(&ca_cbor, leak),
        "generated store leaks an absolute source path"
    );

    // ta.cbor loads via TaSource::new_from_cbor.
    let mut ta = TaSource::new_from_cbor(&store.ta_cbor).expect("TaSource::new_from_cbor");
    ta.initialize().expect("initialize TA source");
    assert_eq!(ta.get_tas().len(), n_ta);

    // ca.cbor loads via CertSource::new_from_cbor (the pittv3 intermediate-store path).
    let mut cps = CertificationPathSettings::new();
    cps.set_enforce_trust_anchor_validity(false);
    let mut cs = CertSource::new_from_cbor(&ca_cbor).expect("CertSource::new_from_cbor");
    cs.initialize(&cps).expect("initialize cert source");
    assert_eq!(
        cs.num_buffers(),
        n_ca,
        "loaded intermediate count must match"
    );
}

/// True if `haystack` contains `needle` as a contiguous byte subsequence.
fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

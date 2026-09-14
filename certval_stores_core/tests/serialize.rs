//! Does `serialize_environment` produce artifacts certval loads back?
//!
//! The point of the emitter is a consumer that fetches CBOR at run time instead
//! of linking a provider crate, so the test that matters is the round trip:
//! serialize, read back through the same constructors that consumer uses, and
//! check the anchors survived.

use certval::{CertSource, Error, TaSource};
use certval_stores_core::{serialize_environment, TrustStoreProvider};

/// Roots the provider advertises for `env`, as the emitter should have found them.
fn advertised_roots(provider: &dyn TrustStoreProvider, env: &str) -> usize {
    provider
        .entries()
        .iter()
        .filter(|e| e.env == env)
        .map(|e| e.roots.len())
        .sum()
}

#[test]
fn serialized_anchors_load_back_through_tasource() {
    let provider = certval_stores_nipr::provider();
    let store = serialize_environment(&[provider], "NIPR").expect("NIPR must serialize");

    let mut ta_source =
        TaSource::new_from_cbor(&store.ta_cbor).expect("emitted ta_cbor must deserialize");
    ta_source
        .initialize()
        .expect("emitted ta_cbor must initialize");

    // get_tas is the consumer-visible count, and it is deliberately not the same
    // question as "how many buffers were written": initialize drops a buffer it
    // cannot use. Comparing against what the provider advertises is what catches
    // an anchor lost in serialization.
    assert_eq!(
        ta_source.get_tas().len(),
        advertised_roots(provider, "NIPR"),
        "anchors were lost between the provider and the serialized store"
    );
}

#[test]
fn ca_store_is_passed_through_unchanged() {
    let provider = certval_stores_nipr::provider();
    let store = serialize_environment(&[provider], "NIPR").expect("NIPR must serialize");

    let embedded = provider
        .entries()
        .into_iter()
        .find(|e| e.env == "NIPR")
        .and_then(|e| e.cert_store_cbor)
        .expect("the NIPR entry carries a CA store");
    assert_eq!(
        store.ca_cbor.as_deref(),
        Some(embedded),
        "cert_store_cbor is already the serialized form; it must not be re-encoded"
    );

    // And it is still loadable after the round trip, not merely equal.
    let mut cert_source = CertSource::new_from_cbor(&store.ca_cbor.unwrap())
        .expect("emitted ca_cbor must deserialize");
    cert_source
        .initialize(&Default::default())
        .expect("emitted ca_cbor must initialize");
}

/// An anchors-only environment must serialize with no CA store rather than an
/// empty one — `CertSource::new_from_cbor` on empty bytes is an error, so the
/// distinction reaches the consumer.
#[test]
fn an_anchors_only_environment_emits_no_ca_store() {
    let provider = certval_stores_fpki::provider();
    let store = serialize_environment(&[provider], "FPKI_LEGACY")
        .expect("the retired G1 environment must serialize");
    assert!(store.ca_cbor.is_none());
    assert!(!store.ta_cbor.is_empty());
}

#[test]
fn an_unserved_environment_is_unrecognized() {
    let provider = certval_stores_nipr::provider();
    assert_eq!(
        serialize_environment(&[provider], "NOPE").err(),
        Some(Error::Unrecognized)
    );
}

/// Regenerating the same material must produce the same bytes, or a build step
/// that emits these artifacts churns its output on every run.
#[test]
fn serialization_is_deterministic() {
    let provider = certval_stores_nipr::provider();
    let a = serialize_environment(&[provider], "NIPR").expect("NIPR must serialize");
    let b = serialize_environment(&[provider], "NIPR").expect("NIPR must serialize");
    assert_eq!(a.ta_cbor, b.ta_cbor);
    assert_eq!(a.ca_cbor, b.ca_cbor);
}

/// The CBOR has nowhere to carry the dates, so `SerializedStore` is the only route
/// by which a consumer that fetches artifacts can say how current a store is. A
/// serializer that dropped them would leave the browser frontend silently unable to
/// answer the question the desktop answers from the provider directly.
#[test]
fn the_dates_survive_serialization() {
    let provider = certval_stores_nipr::provider();
    let entry = provider
        .entries()
        .into_iter()
        .find(|e| e.env == "NIPR")
        .expect("the provider serves NIPR");
    let store = serialize_environment(&[provider], "NIPR").expect("NIPR must serialize");

    assert_eq!(store.published, entry.published);
    assert_eq!(store.collected, entry.collected);
    assert!(
        store.published.is_some() && store.collected.is_some(),
        "the NIPR store is generated from a dated stream, so both dates are known"
    );
}

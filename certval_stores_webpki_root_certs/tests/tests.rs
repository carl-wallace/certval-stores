//! Tests for the webpki-root-certs provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every
//! provider owes its consumers -- roots parse for both certval and reqwest,
//! every advertised environment is accepted, anchors are usable. What is left
//! here is the adapter's own contract: the store id a caller matches on, the
//! anchors-only shape, and the absent dates.
//!
//! **Deliberately no count or digest over the material.** The sibling crates
//! pin one because their certificates are vendored, where a moving count means
//! a local edit or a botched regeneration. Nothing here is local: the roots move
//! when `webpki-root-certs` moves, which is the reason to use this crate at all.
//! A pin would fail on every legitimate `cargo update`, say only "something
//! moved" and nothing about what, and so teach whoever hits it to bump the
//! constant unread -- a green signal that means less than no test. Reviewing
//! each change to the trust set is what `certval_stores_mozilla` is for. The
//! signal that this material moved is the `Cargo.lock` diff, which is free and
//! arrives at the moment someone chooses to update.

use certval_stores_core::{conformance, TrustStoreProvider};

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_webpki_root_certs::provider()]
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_webpki_root_certs::provider());
}

#[test]
fn providers_compose() {
    conformance::assert_providers_compose(&providers());
}

#[test]
fn advertises_one_anchors_only_store() {
    let entries = certval_stores_webpki_root_certs::provider().entries();
    assert_eq!(entries.len(), 1, "this crate carries one environment");

    let entry = &entries[0];
    assert_eq!(
        entry.id,
        certval_stores_webpki_root_certs::WEBPKI_ROOT_CERTS
    );
    assert_eq!(entry.id, "webpki_root_certs");
    assert!(
        entry.cert_store_cbor.is_none(),
        "anchors-only: the source publishes roots and no intermediates"
    );
    assert!(
        entry.published.is_none() && entry.collected.is_none(),
        "the source states no dates, so the provider states none"
    );
}

/// The adapter must pass the whole upstream set through, not a slice of it.
/// Deliberately a lower bound rather than an exact count -- see the note at the
/// top of this file.
#[test]
fn carries_the_upstream_roots() {
    let roots = certval_stores_core::get_roots(&providers());
    assert!(
        !roots.is_empty(),
        "the provider must publish the roots it takes from webpki-root-certs"
    );
}

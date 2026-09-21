//! Do the public providers compose?
//!
//! Every other test in this workspace judges one provider on its own, but
//! consumers assemble several into a single `PkiEnvironment` — and a provider
//! that is conformant alone can still collide with another once they share one.
//! This lives in the core crate because it is about the family rather than any
//! member of it, which means core dev-depends on the providers that normally
//! depend on core. Cargo permits that cycle for dev-dependencies, and it is the
//! only arrangement that puts the check somewhere none of the providers owns.
//!
//! A new provider — the private SIPR one, a webpki/Mozilla one — belongs in the
//! list below as soon as it is public and buildable here. The list is written out
//! rather than discovered, so adding a crate to the workspace does not add it
//! here: `certval_stores_eca` was in the workspace, tested and lint-clean while
//! still missing from this check.

use certval_stores_core::{conformance, TrustStoreProvider};

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_eca::provider(),
        certval_stores_fpki::provider(),
        certval_stores_nipr::provider(),
        certval_stores_pbdev::provider(),
        certval_stores_wcf::provider(),
    ]
}

/// No two anchors across the family may share a key identifier while carrying
/// different keys, and no two providers may claim the same environment label.
#[test]
fn the_public_providers_compose() {
    conformance::assert_providers_compose(&providers());
}

/// Each provider is separately conformant, so a failure here is about that
/// provider rather than the composition.
#[test]
fn every_public_provider_is_conformant() {
    for provider in providers() {
        conformance::assert_conformant(provider);
    }
}

//! NIPR (DoD PKI) trust stores for certval.
//!
//! Provides trust anchors and CA stores for the NIPR production (`nipr`) and
//! operational-test / JITC (`om_nipr`) environments. Enable the feature(s) for
//! the environment(s) you need; with neither feature enabled this crate builds
//! but its provider yields no entries.

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "om_nipr")]
static OM_NIPR_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/om/DOD_JITC_Root_CA-3.der"),
    include_bytes!("../roots/om/DOD_JITC_Root_CA-5.der"),
    include_bytes!("../roots/om/DOD_JITC_Root_CA-6.der"),
];

#[cfg(feature = "nipr")]
static NIPR_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/prod/DOD_Root_CA-3.der"),
    include_bytes!("../roots/prod/DOD_Root_CA-5.der"),
    include_bytes!("../roots/prod/DOD_Root_CA-6.der"),
];

/// Trust-store provider for the NIPR (DoD PKI) environments.
pub struct NiprStores;

impl TrustStoreProvider for NiprStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "om_nipr")]
        entries.push(StoreEntry {
            env: "OM_NIPR",
            roots: OM_NIPR_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/om/om.cbor")),
        });
        #[cfg(feature = "nipr")]
        entries.push(StoreEntry {
            env: "NIPR",
            roots: NIPR_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/prod/prod.cbor")),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: NiprStores = NiprStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

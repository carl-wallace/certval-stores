#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "eca")]
static ECA_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/prod/ECA_Root_CA_4.der"),
    include_bytes!("../roots/prod/ECA_Root_CA_5.der"),
];

/// Trust-store provider for the ECA (DoD External Certification Authority) program.
pub struct EcaStores;

impl TrustStoreProvider for EcaStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "eca")]
        entries.push(StoreEntry {
            env: "ECA",
            roots: ECA_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/prod/prod.cbor")),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: EcaStores = EcaStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "fpki")]
static FPKI_ROOTS: &[&[u8]] = &[include_bytes!(
    "../roots/fpki/Federal_Common_Policy_CA_G2.der"
)];

#[cfg(feature = "fpki_legacy")]
static FPKI_LEGACY_ROOTS: &[&[u8]] = &[include_bytes!(
    "../roots/legacy/Federal_Common_Policy_CA.der"
)];

/// Trust-store provider for the Federal PKI environments.
pub struct FpkiStores;

impl TrustStoreProvider for FpkiStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "fpki")]
        entries.push(StoreEntry {
            env: "FPKI",
            roots: FPKI_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/fpki/fpki.cbor")),
        });
        #[cfg(feature = "fpki_legacy")]
        entries.push(StoreEntry {
            env: "FPKI_LEGACY",
            roots: FPKI_LEGACY_ROOTS,
            cert_store_cbor: None,
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: FpkiStores = FpkiStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

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
            // The crawler's own publication date for the bundle this store was built
            // from, and the day it was taken; both are recorded in the README's
            // provenance section. Literals rather than generator-written files, because
            // the `fpki` adapter is handed a `.p7b` that states neither -- they come off
            // the GSA repository the bundle was downloaded from.
            published: Some("2026-08-10"),
            collected: Some("2026-08-12"),
        });
        #[cfg(feature = "fpki_legacy")]
        entries.push(StoreEntry {
            env: "FPKI_LEGACY",
            roots: FPKI_LEGACY_ROOTS,
            cert_store_cbor: None,
            // No publication date: the G1 mesh is no longer published, and the anchor was
            // fetched from `repo.fpki.gov` rather than out of a dated bundle. The
            // collection date is the day it reached this repository, which is the latest
            // it can have been fetched -- the honest direction to round for a date whose
            // purpose is to bound staleness.
            published: None,
            collected: Some("2026-08-13"),
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

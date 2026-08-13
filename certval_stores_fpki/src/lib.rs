//! Federal PKI trust store for certval.
//!
//! Unlike the other provider crates in this family, the FPKI is a *cross-certified
//! mesh with a single anchor* rather than a set of roots: the `FPKI` environment
//! carries exactly one trust anchor — the Federal Common Policy CA G2 — and every
//! other participant (DoD, Treasury, Entrust, DigiCert, State, WidePoint/ORC,
//! CertiPath, …) reaches it through cross-certificates carried in the CA store.
//!
//! The `fpki_legacy` feature adds the retired Federal Common Policy CA (G1) as a
//! separate `FPKI_LEGACY` environment. It is anchors-only: the G1 mesh is no
//! longer published, so there is no CA store to go with it. Enable it only to
//! validate paths that predate the G2 migration.
//!
//! See `README.md` for the provenance of the embedded material and how to
//! refresh it — unlike the DoD stores, the FPKI mesh is republished frequently.

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

#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "fpki")]
static FPKI_ROOTS: &[&[u8]] = &[include_bytes!(
    "../roots/fpki/Federal_Common_Policy_CA_G2.der"
)];

/// The day of the walk the store was built from, written by `certval-store-gen fpki-crawl`.
#[cfg(feature = "fpki")]
const FPKI_COLLECTED: &str = include_str!("../provenance/fpki/collected.txt").trim_ascii_end();

#[cfg(feature = "fpki_legacy")]
static FPKI_LEGACY_ROOTS: &[&[u8]] = &[include_bytes!(
    "../roots/legacy/Federal_Common_Policy_CA.der"
)];

/// Trust-store provider for the Federal PKI environments.
pub struct FpkiStores;

/// Store id for the U.S. Federal PKI store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "fpki")]
pub const FPKI: &str = "fpki";

/// Store id for the legacy Federal PKI G1 mesh store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "fpki_legacy")]
pub const FPKI_LEGACY: &str = "fpki_legacy";

impl TrustStoreProvider for FpkiStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "fpki")]
        entries.push(StoreEntry {
            id: FPKI,
            label: "U.S. Federal PKI (Common Policy CA G2)",
            roots: FPKI_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/fpki/fpki.cbor")),
            // A mesh states no publication date: each repository answers for itself, so the
            // store's date is the day it was walked, which is also the date it was validated at.
            published: None,
            collected: Some(FPKI_COLLECTED),
        });
        #[cfg(feature = "fpki_legacy")]
        entries.push(StoreEntry {
            id: FPKI_LEGACY,
            label: "U.S. Federal PKI (legacy G1 mesh)",
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

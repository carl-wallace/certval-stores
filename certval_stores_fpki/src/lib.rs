#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(any(feature = "fpki", feature = "fpki_legacy"))]
use certval_stores_provider_core::Date;
use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "fpki")]
static FPKI_ROOTS: &[&[u8]] = &[include_bytes!(
    "../roots/fpki/Federal_Common_Policy_CA_G2.der"
)];

/// The day of the walk the store was built from, written by `certval-store-gen fpki-crawl`.
#[cfg(feature = "fpki")]
const FPKI_COLLECTED: Date =
    Date::parse(include_str!("../provenance/fpki/collected.txt").trim_ascii_end())
        .expect("provenance/fpki/collected.txt is not a YYYY-MM-DD date");

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
        entries.push(
            // A mesh states no publication date: each repository answers for itself, so the
            // store's date is the day it was walked, which is also the date it was validated at.
            StoreEntry::new(FPKI, "U.S. Federal PKI (Common Policy CA G2)", FPKI_ROOTS)
                .with_cert_store_cbor(include_bytes!("../cas/fpki/fpki.cbor"))
                .with_collected(FPKI_COLLECTED),
        );
        #[cfg(feature = "fpki_legacy")]
        entries.push(
            // No publication date: the G1 mesh is no longer published, and the anchor was
            // fetched from `repo.fpki.gov` rather than out of a dated bundle. The
            // collection date is the day it reached this repository, which is the latest
            // it can have been fetched -- the honest direction to round for a date whose
            // purpose is to bound staleness.
            StoreEntry::new(
                FPKI_LEGACY,
                "U.S. Federal PKI (legacy G1 mesh)",
                FPKI_LEGACY_ROOTS,
            )
            .with_collected(const { Date::parse("2026-08-13").expect("not a YYYY-MM-DD date") }),
        );
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

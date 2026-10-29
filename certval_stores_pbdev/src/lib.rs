#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "dev")]
use certval_stores_provider_core::Date;
use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "dev")]
mod roots_dev;

struct PbDevStores;

/// Store id for the Purebred development store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "dev")]
pub const PUREBRED_DEV: &str = "dod_purebred_dev";

impl TrustStoreProvider for PbDevStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "dev")]
        entries.push(
            // The development PKI publishes nothing anywhere, so there is no publication
            // date to state -- see the README's note that these roots have no external
            // source to corroborate them against either.
            StoreEntry::new(
                PUREBRED_DEV,
                "U.S. DoD (Purebred development)",
                roots_dev::ROOTS,
            )
            .with_cert_store_cbor(include_bytes!("../cas/dev/dev.cbor"))
            .with_collected(const { Date::parse("2026-08-06").expect("not a YYYY-MM-DD date") }),
        );
        entries
    }
}

/// The trust-store provider for the Purebred development environment.
///
/// Add it to the list of providers passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PbDevStores
}

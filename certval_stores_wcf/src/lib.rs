#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "wcf")]
use certval_stores_provider_core::Date;
use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "wcf")]
mod roots_prod;

// Written by `certval-store-gen` from `inputs/WCF.ir4`: `published` is the verified RFC 3161
// timestamp on the InstallRoot messages read, `collected` the day the stream was fetched. See the
// same pair in `certval_stores_nipr` for why they are files rather than literals.
#[cfg(feature = "wcf")]
const WCF_PUBLISHED: Date =
    Date::parse(include_str!("../provenance/prod/published.txt").trim_ascii_end())
        .expect("provenance/prod/published.txt is not a YYYY-MM-DD date");
#[cfg(feature = "wcf")]
const WCF_COLLECTED: Date =
    Date::parse(include_str!("../provenance/prod/collected.txt").trim_ascii_end())
        .expect("provenance/prod/collected.txt is not a YYYY-MM-DD date");

/// Trust-store provider for the DoD WCF PKI.
pub struct WcfStores;

/// Store id for the WCF store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "wcf")]
pub const WCF: &str = "dod_wcf";

impl TrustStoreProvider for WcfStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "wcf")]
        entries.push(
            StoreEntry::new(WCF, "U.S. DoD (WCF)", roots_prod::ROOTS)
                .with_cert_store_cbor(include_bytes!("../cas/prod/prod.cbor"))
                .with_published(WCF_PUBLISHED)
                .with_collected(WCF_COLLECTED),
        );
        entries
    }
}

/// The provider instance.
pub static PROVIDER: WcfStores = WcfStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

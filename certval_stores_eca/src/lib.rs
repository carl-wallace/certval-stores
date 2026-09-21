#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "eca")]
static ECA_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/prod/ECA_Root_CA_4.der"),
    include_bytes!("../roots/prod/ECA_Root_CA_5.der"),
];

// Written by `certval-store-gen` from `inputs/ECA.ir4`: `published` is the verified RFC 3161
// timestamp on the InstallRoot messages read, `collected` the day the stream was fetched. See the
// same pair in `certval_stores_nipr` for why they are files rather than literals.
#[cfg(feature = "eca")]
const ECA_PUBLISHED: &str = include_str!("../provenance/prod/published.txt").trim_ascii_end();
#[cfg(feature = "eca")]
const ECA_COLLECTED: &str = include_str!("../provenance/prod/collected.txt").trim_ascii_end();

/// Trust-store provider for the ECA (DoD External Certification Authority) program.
pub struct EcaStores;

/// Store id for the ECA store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "eca")]
pub const ECA: &str = "dod_eca";

impl TrustStoreProvider for EcaStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "eca")]
        entries.push(StoreEntry {
            id: ECA,
            label: "U.S. DoD (ECA)",
            roots: ECA_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/prod/prod.cbor")),
            published: Some(ECA_PUBLISHED),
            collected: Some(ECA_COLLECTED),
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

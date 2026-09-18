#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "om_nipr")]
static OM_NIPR_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/om/DoD_JITC_Root_CA_3.der"),
    include_bytes!("../roots/om/DoD_JITC_Root_CA_4.der"),
    include_bytes!("../roots/om/DoD_JITC_Root_CA_5.der"),
    include_bytes!("../roots/om/DoD_JITC_Root_CA_6.der"),
];

#[cfg(feature = "nipr")]
static NIPR_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/prod/DoD_Root_CA_3.der"),
    include_bytes!("../roots/prod/DoD_Root_CA_4.der"),
    include_bytes!("../roots/prod/DoD_Root_CA_5.der"),
    include_bytes!("../roots/prod/DoD_Root_CA_6.der"),
];

// Written by `certval-store-gen` from the stream each environment is generated from:
// `published` is the `signingTime` of the InstallRoot messages read, `collected` the day
// the stream was fetched. Files rather than literals so a refresh carries the dates with
// the material instead of leaving them to a hand edit -- the gap the two answer is real
// here, `JITC.ir4` having been signed well over a year before it was fetched.
#[cfg(feature = "nipr")]
const NIPR_PUBLISHED: &str = include_str!("../provenance/prod/published.txt").trim_ascii_end();
#[cfg(feature = "nipr")]
const NIPR_COLLECTED: &str = include_str!("../provenance/prod/collected.txt").trim_ascii_end();
#[cfg(feature = "om_nipr")]
const OM_NIPR_PUBLISHED: &str = include_str!("../provenance/om/published.txt").trim_ascii_end();
#[cfg(feature = "om_nipr")]
const OM_NIPR_COLLECTED: &str = include_str!("../provenance/om/collected.txt").trim_ascii_end();

/// Trust-store provider for the NIPR (DoD PKI) environments.
pub struct NiprStores;

/// Store id for the NIPR operational-test (JITC) store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "om_nipr")]
pub const NIPR_OM: &str = "dod_nipr_om";

/// Store id for the NIPR production store, to pass to `prepare_certval_environment`
/// or `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "nipr")]
pub const NIPR_PROD: &str = "dod_nipr_prod";

impl TrustStoreProvider for NiprStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "om_nipr")]
        entries.push(StoreEntry {
            id: NIPR_OM,
            label: "U.S. DoD (JITC)",
            roots: OM_NIPR_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/om/om.cbor")),
            published: Some(OM_NIPR_PUBLISHED),
            collected: Some(OM_NIPR_COLLECTED),
        });
        #[cfg(feature = "nipr")]
        entries.push(StoreEntry {
            id: NIPR_PROD,
            label: "U.S. DoD (NIPR)",
            roots: NIPR_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/prod/prod.cbor")),
            published: Some(NIPR_PUBLISHED),
            collected: Some(NIPR_COLLECTED),
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

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

// The interoperability environments are NIPR plus one cross-certified root and the
// bundle that root publishes at its own SIA. DoD Root CA 3 and DoD Root CA 6 appear
// here as anchors and again in the CA store as the interop root issued them -- same
// subjects, different certificates, which is what lets a DoD-anchored consumer reach
// the other side.
#[cfg(feature = "nipr_interop")]
static NIPR_INTEROP_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/interop/DoD_Interoperability_Root_CA_2.der"),
    include_bytes!("../roots/interop/DoD_Root_CA_3.der"),
    include_bytes!("../roots/interop/DoD_Root_CA_4.der"),
    include_bytes!("../roots/interop/DoD_Root_CA_5.der"),
    include_bytes!("../roots/interop/DoD_Root_CA_6.der"),
];

#[cfg(feature = "nipr_cceb_interop")]
static NIPR_CCEB_INTEROP_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/cceb_interop/DoD_Root_CA_3.der"),
    include_bytes!("../roots/cceb_interop/DoD_Root_CA_4.der"),
    include_bytes!("../roots/cceb_interop/DoD_Root_CA_5.der"),
    include_bytes!("../roots/cceb_interop/DoD_Root_CA_6.der"),
    include_bytes!("../roots/cceb_interop/US_DoD_CCEB_Interoperability_Root_CA_2.der"),
];

// Written by `certval-store-gen` from the stream each environment is generated from:
// `published` is the verified RFC 3161 timestamp on the InstallRoot messages read (DoD
// asserts no `signingTime` of its own), `collected` the day
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
#[cfg(feature = "nipr_interop")]
const NIPR_INTEROP_PUBLISHED: &str =
    include_str!("../provenance/interop/published.txt").trim_ascii_end();
#[cfg(feature = "nipr_interop")]
const NIPR_INTEROP_COLLECTED: &str =
    include_str!("../provenance/interop/collected.txt").trim_ascii_end();
#[cfg(feature = "nipr_cceb_interop")]
const NIPR_CCEB_INTEROP_PUBLISHED: &str =
    include_str!("../provenance/cceb_interop/published.txt").trim_ascii_end();
#[cfg(feature = "nipr_cceb_interop")]
const NIPR_CCEB_INTEROP_COLLECTED: &str =
    include_str!("../provenance/cceb_interop/collected.txt").trim_ascii_end();

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

/// Store id for NIPR plus the DoD Interoperability Root CA 2 material, to pass to
/// `prepare_certval_environment` or `serialize_environment` rather than spelling it out.
///
/// Anchoring on the interop root as well as the four DoD roots is what lets a path reach
/// ECA Root CA 4 and 5 and, through Federal Bridge CA G4, the federal mesh.
#[cfg(feature = "nipr_interop")]
pub const NIPR_INTEROP: &str = "dod_nipr_interop";

/// Store id for NIPR plus the US DoD CCEB Interoperability Root CA 2 material, to pass to
/// `prepare_certval_environment` or `serialize_environment` rather than spelling it out.
///
/// The CCEB root reaches allied national PKIs -- the Australian Defence Interoperability
/// CA and DND/MDN Canada -- rather than the federal mesh, so this is a different offer
/// from [`NIPR_INTEROP`] and not a variant of it.
#[cfg(feature = "nipr_cceb_interop")]
pub const NIPR_CCEB_INTEROP: &str = "dod_nipr_cceb_interop";

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
        #[cfg(feature = "nipr_interop")]
        entries.push(StoreEntry {
            id: NIPR_INTEROP,
            label: "U.S. DoD (NIPR + Interoperability)",
            roots: NIPR_INTEROP_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/interop/interop.cbor")),
            published: Some(NIPR_INTEROP_PUBLISHED),
            collected: Some(NIPR_INTEROP_COLLECTED),
        });
        #[cfg(feature = "nipr_cceb_interop")]
        entries.push(StoreEntry {
            id: NIPR_CCEB_INTEROP,
            label: "U.S. DoD (NIPR + CCEB Interoperability)",
            roots: NIPR_CCEB_INTEROP_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/cceb_interop/cceb_interop.cbor")),
            published: Some(NIPR_CCEB_INTEROP_PUBLISHED),
            collected: Some(NIPR_CCEB_INTEROP_COLLECTED),
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

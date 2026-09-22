#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

// The 48 vendor roots the cabinet publishes, one `include_bytes!` each. Hand-maintained, as in
// every provider here: `certval-store-gen` prints this list when a refresh changes it, and
// `roots_match_the_committed_files` fails when the list and the directory disagree -- which is
// what makes a hand-maintained list safe rather than a liability.
//
// The vendor survives only in these names. The store is one environment because an attestation
// key chains to whichever vendor made the part, and a consumer cannot know which in advance.
#[cfg(feature = "tpm")]
static TPM_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/tpm/AMD_AMD-Pluton-Global-Factory-ICA.der"),
    include_bytes!("../roots/tpm/AMD_AMD-Root-CA.der"),
    include_bytes!("../roots/tpm/AMD_Microsoft Pluton Root CA 2021.der"),
    include_bytes!("../roots/tpm/Atmel_Atmel TPM Root Signing Module.der"),
    include_bytes!("../roots/tpm/Infineon_IFX TPM EK Root CA.der"),
    include_bytes!("../roots/tpm/Infineon_IFX-RootCA.der"),
    include_bytes!("../roots/tpm/Infineon_IFX_TPM_RootCert_008.der"),
    include_bytes!("../roots/tpm/Infineon_Infineon OPTIGA(TM) ECC Root CA.der"),
    include_bytes!("../roots/tpm/Infineon_Infineon OPTIGA(TM) RSA Root CA.der"),
    include_bytes!("../roots/tpm/Infineon_Infineon_OPTIGA(TM)_ECC_Root_CA_2.der"),
    include_bytes!("../roots/tpm/Infineon_Infineon_OPTIGA(TM)_RSA_Root_CA_2.der"),
    include_bytes!("../roots/tpm/Infineon_OptigaEccRootCA3.der"),
    include_bytes!("../roots/tpm/Infineon_OptigaRsaRootCA3.der"),
    include_bytes!("../roots/tpm/Intel_EKRootPublicKey.der"),
    include_bytes!("../roots/tpm/Intel_ODCA_CA2_CSME_Intermediate.der"),
    include_bytes!("../roots/tpm/Intel_ODCA_CA2_OSSE_Intermediate.der"),
    include_bytes!("../roots/tpm/Intel_OnDie_CA_RootCA_Certificate.der"),
    include_bytes!("../roots/tpm/Microsoft_Microsoft TPM Root Certificate Authority 2014.der"),
    include_bytes!("../roots/tpm/NationZ_EkRootCA.der"),
    include_bytes!("../roots/tpm/NationZ_NSEccRootCA001.der"),
    include_bytes!("../roots/tpm/NationZ_NSRsaRootCA001.der"),
    include_bytes!("../roots/tpm/NationZ_NSTPMEccRootCA001.der"),
    include_bytes!("../roots/tpm/NationZ_NSTPMRsaRootCA001.der"),
    include_bytes!("../roots/tpm/Nuvoton_NPCTxxxECC521RootCA.der"),
    include_bytes!("../roots/tpm/Nuvoton_NTC TPM EK Root CA 01.der"),
    include_bytes!("../roots/tpm/Nuvoton_NTC TPM EK Root CA 02.der"),
    include_bytes!("../roots/tpm/Nuvoton_NTC TPM EK Root CA ARSUF 01.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 1013.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 1014.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 1110.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 1111.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 1210.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2010.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2011.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2012.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2110.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2111.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2112.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2210.der"),
    include_bytes!("../roots/tpm/Nuvoton_Nuvoton TPM Root CA 2211.der"),
    include_bytes!("../roots/tpm/QC_qwes_prod_ek_provisioning_root.der"),
    include_bytes!("../roots/tpm/STMicro_GlobalSign Trusted Computing CA.der"),
    include_bytes!("../roots/tpm/STMicro_GlobalSign Trusted Platform Module ECC Root CA.der"),
    include_bytes!("../roots/tpm/STMicro_ST TPM Root Certificate.der"),
    include_bytes!("../roots/tpm/STMicro_STM TPM ECC Root CA 01.der"),
    include_bytes!("../roots/tpm/STMicro_STSAFE ECC Root CA 02.der"),
    include_bytes!("../roots/tpm/STMicro_STSAFE RSA Root CA 02.der"),
];

// Written by `certval-store-gen` from the cabinet: `published` is the date `version.txt` states
// the contents last changed, `collected` the day it was fetched. Files rather than literals so a
// refresh carries the dates with the material instead of leaving them to a hand edit.
#[cfg(feature = "tpm")]
const TPM_PUBLISHED: &str = include_str!("../provenance/tpm/published.txt").trim_ascii_end();
#[cfg(feature = "tpm")]
const TPM_COLLECTED: &str = include_str!("../provenance/tpm/collected.txt").trim_ascii_end();

/// Trust-store provider for the TPM vendor roots.
pub struct TpmStores;

/// Store id for the TPM vendor environment, to pass to `prepare_certval_environment` or
/// `serialize_environment` rather than spelling it out: the parameter is a `&str`, so a stale
/// literal compiles and fails at run time.
#[cfg(feature = "tpm")]
pub const TPM: &str = "tpm";

impl TrustStoreProvider for TpmStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "tpm")]
        entries.push(StoreEntry {
            id: TPM,
            label: "TPM vendor roots",
            roots: TPM_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/tpm/tpm.cbor")),
            published: Some(TPM_PUBLISHED),
            collected: Some(TPM_COLLECTED),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: TpmStores = TpmStores;

/// Convenience accessor returning the provider as a trait object, for adding to a provider list
/// passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

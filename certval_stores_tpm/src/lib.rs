#![doc = include_str!("../README.md")]

use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

// The vendor roots the cabinet publishes, one `include_bytes!` each in the generated `roots_tpm`
// module, which a refresh rewrites together with `roots/tpm/` so the list cannot fall behind the
// files.
//
// The vendor survives only in these names. The store is one environment because an attestation
// key chains to whichever vendor made the part, and a consumer cannot know which in advance.
#[cfg(feature = "tpm")]
mod roots_tpm;

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
        entries.push(
            StoreEntry::new(TPM, "TPM vendor roots", roots_tpm::ROOTS)
                .with_cert_store_cbor(include_bytes!("../cas/tpm/tpm.cbor"))
                .with_published(TPM_PUBLISHED)
                .with_collected(TPM_COLLECTED),
        );
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

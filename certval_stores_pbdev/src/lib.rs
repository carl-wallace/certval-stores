//! Development (`dev`) trust store for certval — the Purebred development
//! environment (DoD Engineering roots).
//!
//! Enable the `dev` feature (on by default). With `dev` disabled this crate
//! builds but its provider yields no entries.

use certval_stores_core::{StoreEntry, TrustStoreProvider};

#[cfg(feature = "dev")]
static DEV_ROOTS: &[&[u8]] = &[
    include_bytes!("../roots/dev/DOD_ENG_Root-3.der"),
    include_bytes!("../roots/dev/DOD_ENG_Root-6.der"),
];

/// Trust-store provider for the Purebred development environment.
pub struct PbDevStores;

impl TrustStoreProvider for PbDevStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "dev")]
        entries.push(StoreEntry {
            env: "DEV",
            roots: DEV_ROOTS,
            cert_store_cbor: Some(include_bytes!("../cas/dev/dev.cbor")),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: PbDevStores = PbDevStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

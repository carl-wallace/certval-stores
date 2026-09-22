#![doc = include_str!("../README.md")]

use certval_stores_core::{StoreEntry, TrustStoreProvider};

// One generated index per environment, each an `include_bytes!` list over the shared `roots/`
// directory. Generated rather than hand-written, unlike every other provider in this family: at
// 357 certificates across six overlapping views, a hand-kept list would be six places for the
// same root to be forgotten. What keeps that honest is that the generator writes all of it from
// one signed list, and `roots/` holds each certificate exactly once.
#[cfg(feature = "msft_all")]
mod env_all;
#[cfg(feature = "msft_client_auth")]
mod env_client_auth;
#[cfg(feature = "msft_code_signing")]
mod env_code_signing;
#[cfg(feature = "msft_email")]
mod env_email;
#[cfg(feature = "msft_timestamping")]
mod env_timestamping;
#[cfg(feature = "msft_tls")]
mod env_tls;

// Written by `certval-store-gen` from the trust list itself: `published` is the CTL's own
// `thisUpdate`, `collected` the day the list was fetched. Files rather than literals so a refresh
// carries the dates with the material instead of leaving them to a hand edit.
const PUBLISHED: &str = include_str!("../provenance/published.txt").trim_ascii_end();
const COLLECTED: &str = include_str!("../provenance/collected.txt").trim_ascii_end();

/// Trust-store provider for the Microsoft root program.
pub struct MsftStores;

/// Store id for every root in the program. Pass this rather than a literal: the parameter is a
/// `&str`, so a stale spelling compiles and fails at run time.
#[cfg(feature = "msft_all")]
pub const MSFT_ALL: &str = "msft_all";

/// Store id for the roots granted `id-kp-serverAuth`.
#[cfg(feature = "msft_tls")]
pub const MSFT_TLS: &str = "msft_tls";

/// Store id for the roots granted `id-kp-clientAuth`.
#[cfg(feature = "msft_client_auth")]
pub const MSFT_CLIENT_AUTH: &str = "msft_client_auth";

/// Store id for the roots granted `id-kp-emailProtection`.
#[cfg(feature = "msft_email")]
pub const MSFT_EMAIL: &str = "msft_email";

/// Store id for the roots granted `id-kp-codeSigning`.
#[cfg(feature = "msft_code_signing")]
pub const MSFT_CODE_SIGNING: &str = "msft_code_signing";

/// Store id for the roots granted `id-kp-timeStamping`.
#[cfg(feature = "msft_timestamping")]
pub const MSFT_TIMESTAMPING: &str = "msft_timestamping";

impl TrustStoreProvider for MsftStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        // `cert_store_cbor` is `None` throughout, and for a reason that belongs with the
        // material rather than in a comment on one entry: Microsoft publishes roots and nothing
        // else. There are no intermediates to carry and so no partial paths to precompute, which
        // is what a consumer needs to know before selecting one of these to validate a chain.
        #[cfg(feature = "msft_all")]
        entries.push(StoreEntry {
            id: MSFT_ALL,
            label: "Microsoft Root Program",
            roots: env_all::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        #[cfg(feature = "msft_tls")]
        entries.push(StoreEntry {
            id: MSFT_TLS,
            label: "Microsoft Root Program (TLS)",
            roots: env_tls::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        #[cfg(feature = "msft_client_auth")]
        entries.push(StoreEntry {
            id: MSFT_CLIENT_AUTH,
            label: "Microsoft Root Program (client authentication)",
            roots: env_client_auth::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        #[cfg(feature = "msft_email")]
        entries.push(StoreEntry {
            id: MSFT_EMAIL,
            label: "Microsoft Root Program (S/MIME)",
            roots: env_email::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        #[cfg(feature = "msft_code_signing")]
        entries.push(StoreEntry {
            id: MSFT_CODE_SIGNING,
            label: "Microsoft Root Program (code signing)",
            roots: env_code_signing::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        #[cfg(feature = "msft_timestamping")]
        entries.push(StoreEntry {
            id: MSFT_TIMESTAMPING,
            label: "Microsoft Root Program (timestamping)",
            roots: env_timestamping::ROOTS,
            cert_store_cbor: None,
            published: Some(PUBLISHED),
            collected: Some(COLLECTED),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: MsftStores = MsftStores;

/// Convenience accessor returning the provider as a trait object, for adding to a provider list
/// passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

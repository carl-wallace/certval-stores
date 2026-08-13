#![doc = include_str!("../README.md")]
//!
//! # Example
//! ```no_run
//! use certval::{PkiEnvironment, TaSource};
//! use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};
//!
//! # fn providers() -> Vec<&'static dyn TrustStoreProvider> { vec![] }
//! let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! let mut ta_store = TaSource::new();
//!
//! // `providers()` is assembled by the consumer from its enabled features,
//! // e.g. certval_stores_nipr::provider(), certval_stores_sipr::provider(), …
//! let providers = providers();
//! if let Err(e) = prepare_certval_environment(&providers, &mut pe, &mut ta_store, "NIPR") {
//!     log::error!("prepare_certval_environment failed with: {e}");
//! }
//! ```

#[cfg(feature = "test-util")]
pub mod conformance;

// reqwest's wasm backend is a thin fetch() wrapper: no Identity, no Certificate,
// and no timeout/add_root_certificate on ClientBuilder. Enabling the client on a
// wasm target therefore fails deep inside this crate with a cascade of missing
// methods; say so once, here, instead.
#[cfg(all(feature = "reqwest-client", target_family = "wasm"))]
compile_error!(
    "the `reqwest-client` feature cannot build for wasm targets. Depend on \
     certval_stores_* with default-features = false to embed trust material \
     without an HTTP client, and bring your own transport."
);

#[cfg(feature = "reqwest-client")]
use std::time::Duration;

use log::error;
#[cfg(feature = "reqwest-client")]
use reqwest::{Client, ClientBuilder, Identity};

use certval::{CertFile, CertSource, CertVector, Error, PkiEnvironment, TaSource};

/// Trust material for a single environment, carried by a [`TrustStoreProvider`].
///
/// All fields are `'static` because provider crates embed their material at
/// compile time via `include_bytes!`.
pub struct StoreEntry {
    /// Environment identifier this entry serves, e.g. `"NIPR"`, `"OM_SIPR"`, `"DEV"`.
    ///
    /// There is no fixed set: a provider names its own environments, and this
    /// crate only compares the label. `certval_stores_fpki` introduced `"FPKI"`
    /// and `"FPKI_LEGACY"` without any change here, and a new community does the
    /// same. The label is what [`prepare_certval_environment`] matches verbatim,
    /// so it must be unique across the providers a consumer loads together.
    pub env: &'static str,
    /// Trust anchors, DER-encoded.
    ///
    /// These reach `TaSource`, which parses each buffer as an RFC 5914
    /// `TrustAnchorChoice`, so any of its three alternatives would decode. They
    /// must nonetheless be the `certificate` alternative — a bare `Certificate`
    /// — because the same bytes are handed to `reqwest::Certificate::from_der`
    /// under the `reqwest-client` feature, and that takes only this one. Since
    /// the call logs and continues, a `taInfo` anchor would build paths normally
    /// while silently dropping out of every TLS client this crate configures.
    /// The constraint holds whether or not that feature is enabled: a consumer
    /// that builds without the client today may add one tomorrow.
    pub roots: &'static [&'static [u8]],
    /// Serialized certval [`CertSource`] (CBOR: intermediate CAs + partial
    /// paths), or `None` for anchors-only providers (e.g. webpki-style roots).
    pub cert_store_cbor: Option<&'static [u8]>,
}

/// A source of trust material for one or more environments.
///
/// Implemented by each `certval_stores_*` provider crate. A provider's library
/// is `include_bytes!` and a `Vec<StoreEntry>`: it depends on this crate alone,
/// linking neither certval nor reqwest, so every certval and reqwest call made
/// against the material at run time is made here. Its *tests* are another
/// matter — validating the material takes crypto, and which algorithms a
/// community signs with is the provider's business, so a provider crate depends
/// on certval directly to supply the environment `conformance` validates under.
/// The set of entries a provider returns depends on the features it was built
/// with.
pub trait TrustStoreProvider {
    /// The environments this provider serves, given its enabled features.
    fn entries(&self) -> Vec<StoreEntry>;
}

/// Populate `ta_store` (trust anchors) and `pe` (certificate sources) with the
/// material the given `providers` carry for environment `env`.
///
/// Preserves the historical `pb_pki::prepare_certval_environment` contract:
/// returns [`Error::Unrecognized`] if no provider serves `env`.
pub fn prepare_certval_environment(
    providers: &[&dyn TrustStoreProvider],
    pe: &mut PkiEnvironment,
    ta_store: &mut TaSource,
    env: &str,
) -> Result<(), Error> {
    let mut acted = false;
    for provider in providers {
        for entry in provider.entries() {
            if entry.env != env {
                continue;
            }
            acted = true;
            for der in entry.roots {
                ta_store.push(CertFile {
                    filename: format!("{env} root"),
                    bytes: der.to_vec(),
                });
            }
            if let Some(cbor) = entry.cert_store_cbor {
                let mut cert_source = CertSource::new_from_cbor(cbor)?;
                cert_source.initialize(&Default::default())?;
                pe.add_certificate_source(Box::new(cert_source));
            }
        }
    }

    if !acted {
        error!(
            "The environment value ({env}) passed to prepare_certval_environment did not match any provider."
        );
        Err(Error::Unrecognized)
    } else {
        ta_store.initialize()?;
        pe.add_trust_anchor_source(Box::new(ta_store.clone()));
        Ok(())
    }
}

/// Return every trust-anchor DER carried by `providers` (across all
/// environments they were built with). Makes no attempt to parse the values.
pub fn get_roots(providers: &[&dyn TrustStoreProvider]) -> Vec<Vec<u8>> {
    let mut retval = vec![];
    for provider in providers {
        for entry in provider.entries() {
            for der in entry.roots {
                retval.push(der.to_vec());
            }
        }
    }
    retval
}

/// Build a `reqwest` client trusting every root carried by `providers`, using
/// rustls. Pass `None` as `identity` for server-authenticated TLS.
#[cfg(feature = "reqwest-client")]
pub fn get_reqwest_client_rustls(
    providers: &[&dyn TrustStoreProvider],
    timeout_secs: u64,
    identity: Option<Identity>,
) -> Result<Client, reqwest::Error> {
    let builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .use_rustls_tls()
        .connection_verbose(true);
    get_reqwest_client(providers, builder, identity)
}

/// Build a `reqwest` client trusting every root carried by `providers`, using
/// native-tls. Pass `None` as `identity` for server-authenticated TLS.
///
/// Not available on Android — native-tls there would pull in cross-compiled
/// OpenSSL. Android consumers must use [`get_reqwest_client_rustls`].
#[cfg(all(feature = "reqwest-client", not(target_os = "android")))]
pub fn get_reqwest_client_native(
    providers: &[&dyn TrustStoreProvider],
    timeout_secs: u64,
    identity: Option<Identity>,
) -> Result<Client, reqwest::Error> {
    let builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .use_native_tls()
        .connection_verbose(true);
    get_reqwest_client(providers, builder, identity)
}

/// Attach the optional `identity` (mutual TLS) and every provider root to a
/// pre-configured `ClientBuilder`, then build. Callers pick the TLS backend
/// (`.use_rustls_tls()` / `.use_native_tls()`) on the builder they pass in.
#[cfg(feature = "reqwest-client")]
pub fn get_reqwest_client(
    providers: &[&dyn TrustStoreProvider],
    mut builder: ClientBuilder,
    identity: Option<Identity>,
) -> Result<Client, reqwest::Error> {
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    for provider in providers {
        for entry in provider.entries() {
            for der in entry.roots {
                match reqwest::Certificate::from_der(der) {
                    Ok(cert) => builder = builder.add_root_certificate(cert),
                    Err(e) => error!("Failed to parse a {} root: {e:?}", entry.env),
                }
            }
        }
    }
    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            error!("Failed to create HTTP Client: {e:?}");
            Err(e)
        }
    }
}

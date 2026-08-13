//! Core provider contract and environment-agnostic plumbing shared by the
//! `certval_stores_*` trust-store crates.
//!
//! A *provider* supplies trust material — trust-anchor certificates (DER) plus
//! an optional serialized certval [`CertSource`] (CBOR: intermediate CAs and
//! precomputed partial certification paths) — for one or more named
//! environments (`"DEV"`, `"NIPR"`, `"OM_NIPR"`, `"SIPR"`, `"OM_SIPR"`, …).
//!
//! This crate defines the [`TrustStoreProvider`] contract and the plumbing that
//! composes any set of providers into a certval [`PkiEnvironment`] or a
//! configured `reqwest` client. It is deliberately **environment-agnostic**:
//! it has no knowledge of NIPR/SIPR/etc. Providers *augment* these functions by
//! being passed in explicitly, so new communities (FPKI, webpki, …) are added
//! simply by writing a new provider crate — no change to this crate.
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

use std::time::Duration;

use log::error;
use reqwest::{Client, ClientBuilder, Identity};

use certval::{CertFile, CertSource, CertVector, Error, PkiEnvironment, TaSource};

/// Trust material for a single environment, carried by a [`TrustStoreProvider`].
///
/// All fields are `'static` because provider crates embed their material at
/// compile time via `include_bytes!`.
pub struct StoreEntry {
    /// Environment identifier this entry serves, e.g. `"NIPR"`, `"OM_SIPR"`, `"DEV"`.
    pub env: &'static str,
    /// Trust anchors, DER-encoded.
    ///
    /// These reach `TaSource`, which parses each buffer as an RFC 5914
    /// `TrustAnchorChoice`, so any of its three alternatives would decode. They
    /// must nonetheless be the `certificate` alternative — a bare `Certificate`
    /// — because the same bytes are handed to `reqwest::Certificate::from_der`
    /// in [`get_reqwest_client`], which takes only that one. Since that call
    /// logs and continues, a `taInfo` anchor would build paths normally while
    /// silently dropping out of every TLS client this crate configures.
    pub roots: &'static [&'static [u8]],
    /// Serialized certval [`CertSource`] (CBOR: intermediate CAs + partial
    /// paths), or `None` for anchors-only providers (e.g. webpki-style roots).
    pub cert_store_cbor: Option<&'static [u8]>,
}

/// A source of trust material for one or more environments.
///
/// Implemented by each `certval_stores_*` provider crate. Providers hold only
/// static bytes; all certval/reqwest work happens in this crate. The set of
/// entries a provider returns depends on the features it was built with.
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
#[cfg(not(target_os = "android"))]
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

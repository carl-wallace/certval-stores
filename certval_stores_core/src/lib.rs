#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
//!
//! # Example
//! ```
//! use certval::{PkiEnvironment, TaSource};
//! use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};
//!
//! let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! let mut ta_store = TaSource::new();
//!
//! // Assembled by the consumer from the provider crates it depends on.
//! let providers: Vec<&dyn TrustStoreProvider> = vec![certval_stores_nipr::provider()];
//! // The store id comes from the provider as a constant rather than as a literal, so a
//! // renamed store fails to compile instead of failing to match.
//! prepare_certval_environment(&providers, &mut pe, &mut ta_store, certval_stores_nipr::NIPR_PROD)?;
//! # Ok::<(), certval::Error>(())
//! ```

#[cfg(feature = "test-util")]
pub mod conformance;

// reqwest's wasm backend is a thin fetch() wrapper: no Identity, no Certificate,
// and no timeout/add_root_certificate on ClientBuilder. Enabling the client on a
// wasm target therefore fails deep inside this crate with a cascade of missing
// methods; say so once, here, instead.
#[cfg(all(
    any(feature = "reqwest-rustls", feature = "reqwest-native"),
    target_family = "wasm"
))]
compile_error!(
    "the `reqwest-rustls` and `reqwest-native` features cannot build for wasm targets. Depend on \
     certval_stores_core with default-features = false to use the providers \
     without an HTTP client, and bring your own transport."
);

#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
use std::time::Duration;

use log::error;
#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
use reqwest::{tls::Version, Client, ClientBuilder, Identity};

use certval::{
    CertFile, CertSource, CertVector, CertificationPathBuilderFormats, Error, PkiEnvironment,
    TaSource,
};

// Re-exported because both are part of this crate's public surface: the first is
// the type [`get_roots`] returns, and the second is how a caller narrows that to
// certificates. A consumer that depends on this crate and not on certval could
// otherwise name neither.
pub use certval::{get_certificate_from_trust_anchor, PDVTrustAnchorChoice};

// The provider contract lives in its own crate, which depends on nothing, so that a
// provider depends on it alone and a certval or reqwest release that moves this crate
// does not move the providers. Re-exported so a consumer names both types from here.
pub use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

/// Populate `ta_store` (trust anchors) and `pe` (certificate sources) with the
/// material the given `providers` carry for the store `id`.
///
/// Preserves the historical `pb_pki::prepare_certval_environment` contract:
/// returns [`Error::Unrecognized`] if no provider serves `id`.
pub fn prepare_certval_environment(
    providers: &[&dyn TrustStoreProvider],
    pe: &mut PkiEnvironment,
    ta_store: &mut TaSource,
    id: &str,
) -> Result<(), Error> {
    let mut acted = false;
    for provider in providers {
        for entry in provider.entries() {
            if entry.id != id {
                continue;
            }
            acted = true;
            for der in entry.roots {
                ta_store.push(CertFile {
                    filename: format!("{id} root"),
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
            "The store id ({id}) passed to prepare_certval_environment did not match any provider."
        );
        Err(Error::Unrecognized)
    } else {
        ta_store.initialize()?;
        pe.add_trust_anchor_source(Box::new(ta_store.clone()));
        Ok(())
    }
}

/// Return every trust anchor carried by `providers` (across all environments
/// they were built with), decoded as an RFC 5914 `TrustAnchorChoice`.
///
/// Decoded rather than handed back as bytes because a caller cannot tell from a
/// buffer which alternative it holds, and the alternatives are not
/// interchangeable — see [`StoreEntry::roots`]. A caller wanting certificates
/// narrows the result itself with `get_certificate_from_trust_anchor`, which is
/// what [`get_reqwest_client`] does.
///
/// An anchor that does not decode is logged and skipped, so a provider shipping
/// one loses that anchor rather than the whole set;
/// `conformance::check_roots_parse` is where that becomes a test failure.
pub fn get_roots(providers: &[&dyn TrustStoreProvider]) -> Vec<PDVTrustAnchorChoice> {
    let mut retval = vec![];
    for provider in providers {
        for entry in provider.entries() {
            for der in entry.roots {
                match PDVTrustAnchorChoice::try_from(*der) {
                    Ok(ta) => retval.push(ta),
                    Err(e) => error!(
                        "Skipping a {} anchor that is not a TrustAnchorChoice: {e:?}",
                        entry.id
                    ),
                }
            }
        }
    }
    retval
}

/// One environment's material in serialized form, as certval loads it back:
/// `ta_cbor` via `TaSource::new_from_cbor`, `ca_cbor` via
/// `CertSource::new_from_cbor`.
pub struct SerializedStore {
    /// [`StoreEntry::id`] for this environment, carried across so a consumer
    /// that serializes the material names the result what everyone else names
    /// it.
    pub id: &'static str,
    /// [`StoreEntry::label`] for this environment, carried across for the same
    /// reason.
    pub label: &'static str,
    /// Trust anchors, CBOR.
    pub ta_cbor: Vec<u8>,
    /// Intermediate CAs and partial paths, CBOR, or `None` for an anchors-only
    /// environment.
    pub ca_cbor: Option<Vec<u8>>,
    /// [`StoreEntry::published`] for this environment, carried across so a
    /// consumer that serializes the material rather than linking the provider
    /// can still say how current it is. The CBOR itself has nowhere to hold it.
    pub published: Option<&'static str>,
    /// [`StoreEntry::collected`] for this environment, carried across for the
    /// same reason.
    pub collected: Option<&'static str>,
}

/// Serialize what `providers` carry for the store `id`, for consumers that load
/// artifacts instead of linking a provider crate — a wasm frontend fetching
/// stores by URL, say, where embedding the bytes is not an option.
///
/// Returns [`Error::Unrecognized`] if no provider serves `id`, matching
/// [`prepare_certval_environment`].
///
/// A trust-anchor store is written as a `CertSource` holding the anchors and no
/// partial paths; that is the form `TaSource::new_from_cbor` reads, and why
/// there is no `TaSource::serialize` to call here.
///
/// Output is deterministic for given material, but is not expected to match a
/// store generated from the same certificates by other means byte for byte:
/// anchor labels are serialized alongside the certificates, and a provider
/// carries no filenames to reproduce.
pub fn serialize_environment(
    providers: &[&dyn TrustStoreProvider],
    id: &str,
) -> Result<SerializedStore, Error> {
    let mut ta_store = CertSource::new();
    let mut ca_cbor: Option<Vec<u8>> = None;
    // The matched entry's own `id`, which is `'static` where the parameter is
    // only borrowed, and is what the returned store is named by.
    let mut matched_id: Option<&'static str> = None;
    let mut label: Option<&'static str> = None;
    let mut published: Option<&'static str> = None;
    let mut collected: Option<&'static str> = None;
    let mut acted = false;

    for provider in providers {
        for entry in provider.entries() {
            if entry.id != id {
                continue;
            }
            acted = true;
            // First statement wins, which only matters if two providers carry one
            // store -- and that is already misuse, caught by the CA-store check
            // below and by `conformance::check_providers_compose`.
            matched_id = matched_id.or(Some(entry.id));
            label = label.or(Some(entry.label));
            published = published.or(entry.published);
            collected = collected.or(entry.collected);
            for (i, der) in entry.roots.iter().enumerate() {
                // The label is serialized into the store and surfaces in certval's
                // logs and reports; path building indexes by key identifier and
                // name, so it carries no other weight. Index it so the anchors are
                // told apart there — a provider has no filenames to borrow — and
                // keep it derived only from the entry, so regenerating the same
                // material twice produces the same bytes.
                let cf = CertFile {
                    filename: format!("{id} root {i}"),
                    bytes: der.to_vec(),
                };
                if !ta_store.contains(&cf) {
                    ta_store.push(cf);
                }
            }
            if let Some(cbor) = entry.cert_store_cbor {
                // Two CA stores under one id cannot be combined here — CBOR
                // documents do not concatenate, and merging would mean parsing
                // and rebuilding the partial-path graph. Ids are required to be
                // unique across the providers a consumer loads, so this is misuse
                // rather than a case to support.
                if ca_cbor.is_some() {
                    error!("More than one provider carries a CA store for store {id}.");
                    return Err(Error::Unrecognized);
                }
                ca_cbor = Some(cbor.to_vec());
            }
        }
    }

    if !acted {
        error!("The store id ({id}) passed to serialize_environment did not match any provider.");
        return Err(Error::Unrecognized);
    }

    // Both are set in the same breath as `acted`, so this arm is unreachable; it
    // is here rather than an unwrap because a library has no business panicking
    // over its own invariant, and `Unrecognized` is what the caller already
    // handles for "this id yielded nothing".
    let (Some(matched_id), Some(label)) = (matched_id, label) else {
        error!("Entries for store {id} carry no id or label.");
        return Err(Error::Unrecognized);
    };

    ta_store.initialize(&Default::default())?;
    let ta_cbor = ta_store.serialize(CertificationPathBuilderFormats::Cbor)?;
    Ok(SerializedStore {
        id: matched_id,
        label,
        ta_cbor,
        ca_cbor,
        published,
        collected,
    })
}

/// Why a client could not be built.
#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// `ids` was empty, so the client would trust nothing.
    NoStores,
    /// None of the providers passed in contains a store with this id: a misspelled id, or a
    /// provider built without the feature for that store.
    UnknownStore(String),
    /// reqwest could not build the client.
    Reqwest(reqwest::Error),
}

#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::NoStores => {
                write!(
                    f,
                    "no store ids were given, so the client would trust nothing"
                )
            }
            ClientError::UnknownStore(id) => {
                write!(f, "no provider contains a store with id {id:?}")
            }
            ClientError::Reqwest(e) => write!(f, "failed to build the HTTP client: {e}"),
        }
    }
}

#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Reqwest(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Reqwest(e)
    }
}

/// Build a `reqwest` client trusting the roots of the stores named in `ids`, and only those
/// roots, using rustls. Pass `None` as `identity` for server-authenticated TLS. See
/// [`get_reqwest_client`] for how `ids` selects stores, what "only those roots" excludes, and how
/// to opt back into the public web PKI.
///
/// `timeout_secs` bounds each request from connecting until the response body has been read;
/// 0 means no timeout.
///
/// The client refuses TLS versions below 1.2 and follows up to 10 redirects, which is reqwest's
/// default. It sets no limit on the size of a response body; reqwest has no such setting on the
/// client, so a limit belongs where the caller reads the body.
#[cfg(feature = "reqwest-rustls")]
pub fn get_reqwest_client_rustls(
    providers: &[&dyn TrustStoreProvider],
    ids: &[&str],
    timeout_secs: u64,
    identity: Option<Identity>,
) -> Result<Client, ClientError> {
    let builder = Client::builder()
        .tls_version_min(Version::TLS_1_2)
        .use_rustls_tls();
    get_reqwest_client(
        providers,
        ids,
        with_timeout(builder, timeout_secs),
        identity,
    )
}

/// Build a `reqwest` client trusting the roots of the stores named in `ids`, and only those
/// roots, using native-tls. Pass `None` as `identity` for server-authenticated TLS. See
/// [`get_reqwest_client`] for how `ids` selects stores, what "only those roots" excludes, and how
/// to opt back into the public web PKI; note in particular that this disables the platform's
/// native root store, which is the point rather than a side effect.
///
/// Like [`get_reqwest_client_rustls`], `timeout_secs` of 0 means no timeout, and the client refuses TLS versions below 1.2, follows up to 10
/// redirects and sets no limit on the size of a response body.
///
/// Not available on Android — native-tls there would pull in cross-compiled
/// OpenSSL. Android consumers must use [`get_reqwest_client_rustls`].
#[cfg(all(feature = "reqwest-native", not(target_os = "android")))]
pub fn get_reqwest_client_native(
    providers: &[&dyn TrustStoreProvider],
    ids: &[&str],
    timeout_secs: u64,
    identity: Option<Identity>,
) -> Result<Client, ClientError> {
    let builder = Client::builder()
        .tls_version_min(Version::TLS_1_2)
        .use_native_tls();
    get_reqwest_client(
        providers,
        ids,
        with_timeout(builder, timeout_secs),
        identity,
    )
}

// reqwest applies a zero timeout as a deadline that has already passed, so every request would
// fail; 0 is taken to mean no timeout, which is reqwest's own default.
#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
fn with_timeout(builder: ClientBuilder, timeout_secs: u64) -> ClientBuilder {
    if timeout_secs == 0 {
        builder
    } else {
        builder.timeout(Duration::from_secs(timeout_secs))
    }
}

/// Attach the optional `identity` (mutual TLS) and the roots of the stores named in `ids` to a
/// pre-configured `ClientBuilder`, then build. Callers pick the TLS backend
/// (`.use_rustls_tls()` / `.use_native_tls()`) on the builder they pass in.
///
/// # `ids` selects the stores
///
/// The client trusts the stores whose ids are in `ids`, from among the stores `providers`
/// return, and no others. Pass the provider's id constants, for example `&[MOZILLA_TLS]`. A
/// provider can return several stores, and which it returns depends on Cargo features that any
/// crate in the build can enable, so trusting every store a provider returns could put roots in
/// the client that the caller never chose: Mozilla's S/MIME roots beside its TLS roots, or a test
/// environment beside production. An id that no provider's store has is
/// [`ClientError::UnknownStore`], and an empty `ids` is [`ClientError::NoStores`], so a mistake
/// fails here rather than as a client that trusts less than intended.
///
/// # The resulting client trusts the named stores' roots and nothing else
///
/// This uses `ClientBuilder::tls_certs_only`, so the platform's native roots
/// and reqwest's built-in web-PKI bundle are **disabled**: the trust set is
/// exactly the roots of the stores named in `ids`. That is deliberate. A client built to reach the endpoints one community's anchors
/// serve has no reason to also accept every CA the host operating system
/// happens to ship, and accepting them means a misissued or mis-resolved host
/// can be authenticated by a CA that has nothing to do with the environment.
///
/// The rule is about provenance, not about any particular community: it holds
/// the same way for a consumer whose providers are Federal, DoD, or the public
/// web PKI itself. What changes is which stores `ids` names.
///
/// A consumer that genuinely needs the public web PKI should say so by naming a
/// store for it, such as `certval_stores_mozilla::MOZILLA_TLS`, rather than
/// relying on an ambient default. That keeps the trust set declared in one
/// place and auditable from `ids`.
///
/// Note the setting is sticky: `tls_certs_only` cannot be undone by a later
/// builder call, so the escape hatch is the `ids` argument (or building
/// a `reqwest::Client` directly), not a flag on the builder passed in here.
#[cfg(any(feature = "reqwest-rustls", feature = "reqwest-native"))]
pub fn get_reqwest_client(
    providers: &[&dyn TrustStoreProvider],
    ids: &[&str],
    mut builder: ClientBuilder,
    identity: Option<Identity>,
) -> Result<Client, ClientError> {
    if ids.is_empty() {
        return Err(ClientError::NoStores);
    }
    let entries: Vec<StoreEntry> = providers
        .iter()
        .flat_map(|provider| provider.entries())
        .filter(|entry| ids.contains(&entry.id))
        .collect();
    if let Some(missing) = ids
        .iter()
        .find(|id| !entries.iter().any(|entry| entry.id == **id))
    {
        return Err(ClientError::UnknownStore((*missing).to_string()));
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    // Collected rather than added one at a time because `tls_certs_only` is
    // what disables the built-in roots, and it takes the whole set. A root that
    // fails to parse is logged and skipped; the conformance suite's
    // `check_roots_parse` runs the same reqwest leg over every provider, so a
    // root reqwest rejects is a test failure rather than a silent trust-set
    // shrink discovered in production.
    let mut certs = vec![];
    for entry in &entries {
        for der in entry.roots {
            // Decode as a TrustAnchorChoice first so the three outcomes are
            // distinguishable. Handing the buffer straight to reqwest made a
            // certificate-less anchor indistinguishable from corrupt DER,
            // and both merely shrank the trust set `tls_certs_only` installs.
            let ta = match PDVTrustAnchorChoice::try_from(*der) {
                Ok(ta) => ta,
                Err(e) => {
                    error!(
                        "Skipping a {} root that is not a TrustAnchorChoice: {e:?}",
                        entry.id
                    );
                    continue;
                }
            };
            if get_certificate_from_trust_anchor(ta.decoded()).is_none() {
                error!(
                    "A {} anchor carries no certificate, so it is a trust anchor here and not in the TLS trust set",
                    entry.id
                );
                continue;
            }
            // `certificate` is the untagged alternative, so for it the buffer
            // is already the certificate DER. A certificate carried inside a
            // `taInfo` is not, and reqwest reports that itself.
            match reqwest::Certificate::from_der(der) {
                Ok(cert) => certs.push(cert),
                Err(e) => error!("Failed to parse a {} root: {e:?}", entry.id),
            }
        }
    }
    builder = builder.tls_certs_only(certs);
    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            error!("Failed to create HTTP Client: {e:?}");
            Err(ClientError::Reqwest(e))
        }
    }
}

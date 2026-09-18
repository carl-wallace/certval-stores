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
//! // The store id comes from the provider as a constant — `certval_stores_nipr::NIPR_PROD`
//! // here — rather than as a literal, so a renamed store fails to compile instead of
//! // failing to match.
//! if let Err(e) = prepare_certval_environment(&providers, &mut pe, &mut ta_store, "dod_nipr_prod") {
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

use certval::{
    CertFile, CertSource, CertVector, CertificationPathBuilderFormats, Error, PkiEnvironment,
    TaSource,
};

/// Trust material for a single environment, carried by a [`TrustStoreProvider`].
///
/// All fields are `'static` because provider crates embed their material at
/// compile time via `include_bytes!`.
pub struct StoreEntry {
    /// Identifier for this store, e.g. `"dod_nipr_prod"`, `"webpki"`.
    ///
    /// The one name a store has. [`prepare_certval_environment`] and
    /// [`serialize_environment`] match it verbatim, and it is what a consumer
    /// keys on to recognize two copies of the same material as the same store —
    /// an application that embeds a serialized copy and a service that serves
    /// one, which would otherwise offer a person the same trust anchors twice
    /// under two spellings. There is no fixed set: a provider names its own
    /// stores, and it must be unique across the providers a consumer loads
    /// together.
    ///
    /// Each provider exports its ids as public constants, which is what a caller
    /// should pass rather than a literal: the parameter is a `&str`, so a
    /// spelling that no longer matches anything compiles and fails at run time.
    ///
    /// Treat it as published: changing one renames a store that consumers,
    /// configuration and command lines may already refer to. Lowercase, with
    /// words separated by underscores, since it travels through URLs, file names
    /// and command lines.
    pub id: &'static str,
    /// Name for this store as a person choosing between them reads it, e.g.
    /// `"U.S. DoD (NIPR)"`.
    ///
    /// The provider states it because the material is the provider's: only it
    /// knows that `OM_NIPR` is what the department calls JITC, or that a root
    /// set carrying both trust bits is not the same offer as a TLS-only one.
    /// Free text, and expected to change as wording improves — unlike
    /// [`id`](StoreEntry::id), nothing keys on it.
    pub label: &'static str,
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
    /// The date the *source* states this material was published, `YYYY-MM-DD`,
    /// or `None` where it states none.
    ///
    /// Separate from [`collected`](StoreEntry::collected) because the two answer
    /// different questions and can be far apart: a DoD InstallRoot stream signed
    /// in February and fetched in September is nine months of anchor changes the
    /// fetch date would hide. This is the publisher's own statement — an
    /// InstallRoot stream's `signingTime`, a CCADB report date, the publication
    /// date of a crawler bundle — so it is the one that says how current the
    /// material is.
    ///
    /// Optional because most publishers state nothing: a provider that cannot
    /// answer honestly says nothing rather than offering a plausible-looking
    /// date. It is never the date the crate was built, released or committed;
    /// those describe this repository, not the trust material.
    pub published: Option<&'static str>,
    /// The date this material was collected from the source, `YYYY-MM-DD`, or
    /// `None` where the provider does not record one.
    ///
    /// The bound on staleness the provider *can* always give: whatever the
    /// publisher has done since this date is not in these bytes. For material
    /// generated by `certval-store-gen` both dates are written by the generator
    /// at generation time, so a refresh moves them without a hand edit.
    pub collected: Option<&'static str>,
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

/// Serialize what `providers` carry for `env`, for consumers that load
/// artifacts instead of linking a provider crate — a wasm frontend fetching
/// stores by URL, say, where embedding the bytes is not an option.
///
/// Returns [`Error::Unrecognized`] if no provider serves `env`, matching
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

/// Build a `reqwest` client trusting every root carried by `providers` — and
/// only those roots — using rustls. Pass `None` as `identity` for
/// server-authenticated TLS. See [`get_reqwest_client`] for what "only those
/// roots" excludes and how to opt back into the public web PKI.
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

/// Build a `reqwest` client trusting every root carried by `providers` — and
/// only those roots — using native-tls. Pass `None` as `identity` for
/// server-authenticated TLS. See [`get_reqwest_client`] for what "only those
/// roots" excludes and how to opt back into the public web PKI; note in
/// particular that this disables the platform's native root store, which is
/// the point rather than a side effect.
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
///
/// # The resulting client trusts the provider roots and nothing else
///
/// This uses `ClientBuilder::tls_certs_only`, so the platform's native roots
/// and reqwest's built-in web-PKI bundle are **disabled**: the trust set is
/// exactly what `providers` carries, whatever that happens to be. That is
/// deliberate. A client built to reach the endpoints one community's anchors
/// serve has no reason to also accept every CA the host operating system
/// happens to ship, and accepting them means a misissued or mis-resolved host
/// can be authenticated by a CA that has nothing to do with the environment.
///
/// The rule is about provenance, not about any particular community: it holds
/// the same way for a consumer whose providers are Federal, DoD, or the public
/// web PKI itself. What changes is the contents of `providers`.
///
/// A consumer that genuinely needs the public web PKI should say so by passing
/// a provider for it — `certval_stores_mozilla` carries the Mozilla root
/// program — rather than relying on an ambient default. That keeps the trust
/// set declared in one place and auditable from the `providers` list.
///
/// Note the setting is sticky: `tls_certs_only` cannot be undone by a later
/// builder call, so the escape hatch is the `providers` argument (or building
/// a `reqwest::Client` directly), not a flag on the builder passed in here.
#[cfg(feature = "reqwest-client")]
pub fn get_reqwest_client(
    providers: &[&dyn TrustStoreProvider],
    mut builder: ClientBuilder,
    identity: Option<Identity>,
) -> Result<Client, reqwest::Error> {
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
    for provider in providers {
        for entry in provider.entries() {
            for der in entry.roots {
                match reqwest::Certificate::from_der(der) {
                    Ok(cert) => certs.push(cert),
                    Err(e) => error!("Failed to parse a {} root: {e:?}", entry.id),
                }
            }
        }
    }
    builder = builder.tls_certs_only(certs);
    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            error!("Failed to create HTTP Client: {e:?}");
            Err(e)
        }
    }
}

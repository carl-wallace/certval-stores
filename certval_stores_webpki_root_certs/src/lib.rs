#![doc = include_str!("../README.md")]

use std::sync::LazyLock;

use certval_stores_core::{StoreEntry, TrustStoreProvider};

/// The roots in the shape [`StoreEntry`] takes: DER buffers borrowed from the
/// dependency's own `'static` data.
///
/// Built at first use rather than written out as a `static` array, because the
/// certificates live in `webpki-root-certs` as `CertificateDer` values and
/// there is no const path from those to `&'static [&'static [u8]]`. Nothing is
/// copied: each buffer is borrowed from a `'static` constant, so this holds
/// pointers and lengths and the certificates themselves are never duplicated.
///
/// Each is a bare `Certificate`, which is the `certificate` alternative of an
/// RFC 5914 `TrustAnchorChoice` and therefore carries the issuing CA's own
/// subject key identifier. That is the whole reason this crate takes
/// `webpki-root-certs` rather than `webpki-roots`: the latter ships name and
/// public key with the outer SEQUENCE stripped and no key identifier at all, so
/// a consumer has to synthesize one, and certval indexes anchors by that value
/// when it looks for the issuer of a certificate it is building a path for.
static ROOTS: LazyLock<Vec<&'static [u8]>> = LazyLock::new(|| {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|cert| cert.as_ref())
        .collect()
});

/// Trust-store provider for the Mozilla TLS server roots as `webpki-root-certs`
/// publishes them.
pub struct WebpkiRootCertsStores;

/// Store id for the TLS server root set, to pass to
/// `prepare_certval_environment` or `serialize_environment` rather than
/// spelling it out: the parameter is a `&str`, so a stale literal compiles and
/// fails at run time.
///
/// Deliberately not `webpki`, which `certval_stores_mozilla` already uses for
/// its combined TLS + S/MIME environment. The two carry overlapping material
/// from the same CCADB source, and a consumer that loads both should see two
/// clearly different names rather than a collision.
pub const WEBPKI_ROOT_CERTS: &str = "webpki_root_certs";

impl TrustStoreProvider for WebpkiRootCertsStores {
    fn entries(&self) -> Vec<StoreEntry> {
        // `published` and `collected` are both None because the source states
        // neither: `webpki-root-certs` exposes one constant and no report date,
        // and this crate collects nothing of its own. The staleness bound a
        // consumer has is the dependency version in Cargo.lock, which is a
        // better answer than a build date and the field documentation rules
        // that out anyway.
        vec![StoreEntry {
            id: WEBPKI_ROOT_CERTS,
            label: "Web PKI (Mozilla roots, TLS servers, via webpki-root-certs)",
            roots: ROOTS.as_slice(),
            cert_store_cbor: None,
            published: None,
            collected: None,
        }]
    }
}

/// The provider instance.
pub static PROVIDER: WebpkiRootCertsStores = WebpkiRootCertsStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}

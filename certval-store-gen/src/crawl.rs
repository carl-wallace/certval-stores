//! Building a store by following SIA links out from a committed anchor.
//!
//! Some PKIs publish no single artifact to generate from. The Federal PKI is one: it is a
//! cross-certified mesh whose membership is discoverable only by walking it, each CA naming what
//! it issued in its own `subjectInfoAccess` `caRepository` bundle. What a crawl produces is the
//! same thing the GSA crawler produces, obtained the same way, and its authority is the same --
//! each hop is the issuing CA's own statement about what it issued.
//!
//! **The committed anchor is what makes it trustworthy.** The walk starts there and nowhere else,
//! and generation afterwards keeps only what chains back to it. An SIA URI can name anything;
//! reaching a certificate is not a reason to trust it, and this module deliberately does not
//! decide that question -- it collects, and `core::generate` keeps what the anchor vouches for.
//!
//! **A partial crawl must never become a store.** A mesh walk is a union of many fetches, so one
//! unreachable host silently subtracts a subtree. That failure looks exactly like a CA having
//! been withdrawn, which is why [`Crawled::unreachable`] is reported separately and a caller
//! refreshing committed material should refuse to replace it when the list is non-empty. This is
//! the one place a crawl is meaningfully weaker than fetching a signed stream whole.

use std::collections::BTreeSet;

use const_oid::db::rfc5280::ID_AD_CA_REPOSITORY;
use der::{Decode, Encode};
use x509_cert::ext::pkix::{name::GeneralName, SubjectInfoAccessSyntax};
use x509_cert::Certificate;

use certval::CertFile;

/// Bounds on a walk. A mesh is not guaranteed to be small, acyclic, or well behaved, and a build
/// that never finishes is worse than one that reports it stopped early.
pub struct Limits {
    /// Most repositories to fetch. Cycles are already excluded by URI de-duplication, so this
    /// bounds breadth rather than loops.
    pub max_fetches: usize,
    /// Most certificates to collect.
    pub max_certificates: usize,
}

impl Default for Limits {
    /// Sized against the Federal PKI, the mesh this exists for: roughly 119 nodes and 134 edges
    /// as the GSA crawler reports it, so these leave several times the headroom without being
    /// unbounded.
    fn default() -> Self {
        Limits {
            max_fetches: 500,
            max_certificates: 2000,
        }
    }
}

/// What a walk found.
pub struct Crawled {
    /// Every distinct certificate reached, the anchors themselves excluded.
    pub certificates: Vec<CertFile>,
    /// Repositories fetched successfully.
    pub fetched: usize,
    /// Repositories whose server answered that there is nothing there (a 4xx).
    ///
    /// Not a reason to distrust the walk. A mesh outlives its own URIs, and a CA that has
    /// withdrawn a bundle is reporting a fact about itself -- the Federal PKI has at least one
    /// of these permanently, so treating it as blocking would mean never refreshing again.
    pub absent: Vec<String>,
    /// Repositories that gave no usable answer at all.
    ///
    /// Non-empty means the result may be a *subset* of the mesh, and a subset is indistinguishable
    /// from a set of CAs having been withdrawn. Treat it as a reason to keep whatever is already
    /// committed, not as a warning to pass over.
    pub unreachable: Vec<String>,
    /// True when a limit stopped the walk, so the result is short for that reason instead.
    pub truncated: bool,
}

/// Walk the mesh reachable from `anchors` by following `caRepository` SIA URIs.
///
/// Breadth-first from the anchors' own repositories. Each certificate found is queued for its own
/// repository, so a bundle reached at depth one contributes its issuees at depth two, and so on
/// until nothing new appears.
pub fn from_anchors(anchors: &[CertFile], limits: &Limits) -> Crawled {
    let mut queue: Vec<String> = vec![];
    let mut seen_uris: BTreeSet<String> = BTreeSet::new();
    let mut seen_certs: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut out = Crawled {
        certificates: vec![],
        fetched: 0,
        absent: vec![],
        unreachable: vec![],
        truncated: false,
    };

    // The anchors seed the walk but are not part of its output: they are already committed, and a
    // store that carried its own anchor as an intermediate would be wrong in a way path building
    // hides.
    for anchor in anchors {
        seen_certs.insert(anchor.bytes.clone());
        for uri in repositories(&anchor.bytes) {
            if seen_uris.insert(uri.clone()) {
                queue.push(uri);
            }
        }
    }

    let mut head = 0;
    while head < queue.len() {
        if out.fetched >= limits.max_fetches || out.certificates.len() >= limits.max_certificates {
            out.truncated = true;
            break;
        }
        let uri = queue[head].clone();
        head += 1;

        let bytes = match crate::refresh::fetch(&uri) {
            Ok(b) => b,
            Err(crate::refresh::FetchError::Absent(why)) => {
                out.absent.push(why);
                continue;
            }
            Err(crate::refresh::FetchError::Unreachable(why)) => {
                out.unreachable.push(why);
                continue;
            }
        };
        out.fetched += 1;

        let certs = match crate::ingest::certs_from_bytes(&bytes) {
            Ok(c) => c,
            Err(e) => {
                // Bytes arrived and were not a bundle. That is the publisher's doing, not the
                // network's, so it does not put the walk's completeness in doubt.
                out.absent.push(format!("{uri} did not read: {e}"));
                continue;
            }
        };
        log::info!("{uri}: {} certificate(s)", certs.len());

        for cf in certs {
            // A repository is free to publish whatever it likes, and several publish bundles
            // holding things that are not certificates. Dropping them here keeps them out of the
            // walk, out of the store, and out of the error log path building would otherwise
            // produce for each of them on every load.
            if Certificate::from_der(&cf.bytes).is_err() {
                log::info!("{uri}: skipping an entry that is not a certificate");
                continue;
            }
            if !seen_certs.insert(cf.bytes.clone()) {
                continue;
            }
            for uri in repositories(&cf.bytes) {
                if seen_uris.insert(uri.clone()) {
                    queue.push(uri);
                }
            }
            out.certificates.push(cf);
        }
    }

    out
}

/// The `caRepository` URIs a certificate names in its own SIA.
///
/// Only `caRepository`, and only `http`/`https`: the other access methods point at services
/// rather than at bundles, and a URI scheme this cannot fetch is not a failure worth reporting on
/// every hop.
fn repositories(der: &[u8]) -> Vec<String> {
    let Ok(cert) = Certificate::from_der(der) else {
        return vec![];
    };
    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return vec![];
    };

    let mut uris = vec![];
    for ext in extensions.iter() {
        if ext.extn_id != const_oid::db::rfc5280::ID_PE_SUBJECT_INFO_ACCESS {
            continue;
        }
        let Ok(sia) = SubjectInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) else {
            continue;
        };
        for desc in sia.0.iter() {
            if desc.access_method != ID_AD_CA_REPOSITORY {
                continue;
            }
            if let GeneralName::UniformResourceIdentifier(uri) = &desc.access_location {
                let uri = uri.as_str();
                if uri.starts_with("http://") || uri.starts_with("https://") {
                    uris.push(uri.to_string());
                }
            }
        }
    }
    uris
}

/// Re-encode certificates as [`CertFile`]s, for a caller assembling anchors to seed a walk.
pub fn anchor_files(ders: &[Vec<u8>]) -> Vec<CertFile> {
    ders.iter()
        .filter_map(|der| {
            let cert = Certificate::from_der(der).ok()?;
            let bytes = cert.to_der().ok()?;
            Some(CertFile {
                filename: "anchor".to_string(),
                bytes,
            })
        })
        .collect()
}

/// Turn a walk into generator inputs: the committed anchors, and the edges reached from them.
///
/// A self-signed certificate reached during the walk is dropped. Some repositories publish a
/// peer's root alongside the cross-certificate issued to it, and a root is a node rather than an
/// edge -- keeping it would add an anchor nobody committed, which is the one thing a crawl must
/// not be able to do. Self-*signed* rather than self-*issued*, because the mesh is full of
/// rollover certificates whose issuer equals their subject but whose signature comes from the
/// predecessor key; those are genuine edges and a bare name comparison would discard them.
pub fn into_inputs(
    pe: &certval::PkiEnvironment,
    anchors: Vec<CertFile>,
    crawled: Crawled,
) -> crate::core::StoreInputs {
    let mut intermediates = vec![];
    let mut roots_seen = 0usize;
    for cf in crawled.certificates {
        // Unverifiable counts as not self-signed. `is_self_signed_with_buffer` reports an error
        // for an algorithm certval was not built with, and the two ways to be wrong are not
        // symmetric: filing an edge as an edge costs a redundant certificate, while filing
        // something unreadable as a root would install an anchor on the strength of not being
        // able to check it.
        let self_signed = match certval::parse_cert(&cf.bytes, &cf.filename) {
            Ok(parsed) => certval::is_self_signed_with_buffer(pe, parsed.decoded(), &cf.bytes)
                .unwrap_or(false),
            Err(_) => false,
        };
        if self_signed {
            roots_seen += 1;
        } else {
            intermediates.push(cf);
        }
    }
    if roots_seen > 0 {
        log::info!("{roots_seen} self-signed certificate(s) reached and dropped: a crawl collects edges, and anchors are committed rather than discovered");
    }

    crate::core::StoreInputs {
        trust_anchors: anchors,
        intermediates,
        // A mesh states no publication date; the caller supplies the day it walked.
        published: None,
    }
}

/// Compare certificates about to be written against those a committed CBOR store already holds.
///
/// Returns `(added, removed)` as subject-and-serial descriptions. By certificate rather than by
/// subject, so a re-issued CA -- same name, same key, new serial -- shows as one of each instead
/// of as no change at all.
///
/// Here rather than in `provider::diff` because that compares against a directory of DER files,
/// which a crawl-sourced crate does not keep: its generator input is the mesh, not a folder.
pub fn diff_against_store(
    certificates: &[CertFile],
    committed: &[u8],
) -> (Vec<String>, Vec<String>) {
    let Ok(source) = certval::CertSource::new_from_cbor(committed) else {
        return (
            certificates.iter().map(|cf| describe(&cf.bytes)).collect(),
            vec![],
        );
    };
    let held: BTreeSet<Vec<u8>> = source
        .get_buffers()
        .into_iter()
        .map(|cf| cf.bytes)
        .collect();
    let fresh: BTreeSet<Vec<u8>> = certificates.iter().map(|cf| cf.bytes.clone()).collect();

    let added = fresh.difference(&held).map(|d| describe(d)).collect();
    let removed = held.difference(&fresh).map(|d| describe(d)).collect();
    (added, removed)
}

/// Subject and serial, which is what makes a re-issued certificate legible in a diff.
fn describe(der: &[u8]) -> String {
    match Certificate::from_der(der) {
        Ok(cert) => format!(
            "{} (serial {})",
            certval::get_leaf_rdn(cert.tbs_certificate().subject()),
            cert.tbs_certificate().serial_number()
        ),
        Err(_) => "<unparseable>".to_string(),
    }
}

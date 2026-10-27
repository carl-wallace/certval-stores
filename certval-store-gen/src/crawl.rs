//! Building a store by following SIA and AIA links out from a committed anchor.
//!
//! Some PKIs publish no single artifact to generate from. The Federal PKI is one: it is a
//! cross-certified mesh whose membership is discoverable only by walking it: a certificate's SIA
//! `caRepository` names a bundle of what its subject issued, and its AIA `caIssuers` a bundle of
//! what was issued to its issuer. The walk follows both, as certval's graph builder does, since
//! SIA is the less common of the two. Each hop is a CA's own statement about the certificates
//! around it.
//!
//! **The committed anchor is what makes it trustworthy.** The walk starts there and nowhere else,
//! and generation afterwards keeps only what chains back to it. An SIA or AIA URI can name anything;
//! reaching a certificate is not a reason to trust it, and this module deliberately does not
//! decide that question -- it collects, and `core::generate` keeps what the anchor vouches for.
//!
//! **A host that does not answer should not cost its subtree.** A mesh walk is a union of many
//! fetches, so one unreachable host silently subtracts everything reached only through it, which
//! looks exactly like CAs having been withdrawn. The Federal PKI's repositories are not reliably
//! up, so a caller with a copy from an earlier walk can supply it through [`from_anchors_with`],
//! and the walk continues through that copy; what it fell back for is reported in
//! [`Crawled::fell_back`]. What it could neither fetch nor stand in for is reported in
//! [`Crawled::unreachable`].

use std::collections::BTreeSet;

use const_oid::db::rfc5280::{
    ID_AD_CA_ISSUERS, ID_AD_CA_REPOSITORY, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use der::{Decode, Encode};
use x509_cert::ext::pkix::{name::GeneralName, AuthorityInfoAccessSyntax, SubjectInfoAccessSyntax};
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
    /// Repositories that gave no usable answer and had no earlier copy to stand in for them.
    ///
    /// What only these lead to is missing from the result. A caller whose fallback covers every
    /// repository it walked before loses nothing it had, since a repository with no earlier copy
    /// contributed nothing to the earlier result either.
    pub unreachable: Vec<String>,
    /// Repositories that gave no usable answer and were read from the caller's earlier copy
    /// instead, so the walk continued through them.
    pub fell_back: Vec<String>,
    /// True when a limit stopped the walk, so the result is short for that reason instead.
    pub truncated: bool,
    /// What each repository served, as `(uri, bytes)`, for every fetch that read as a bundle.
    ///
    /// The bytes as published rather than the certificates decoded from them, so a committed walk
    /// is the publishers' own artifacts and a refresh diff names the repository that changed.
    /// [`certificates`](Self::certificates) is what these yield, the anchors and anything that is
    /// not a certificate excluded.
    pub bundles: Vec<(String, Vec<u8>)>,
}

/// Walk the mesh reachable from `anchors` by following SIA `caRepository` and AIA `caIssuers`
/// URIs.
///
/// Breadth-first from the anchors' own repositories. Each certificate found has its own bundle URIs
/// queued, so a bundle reached at depth one contributes what it links to at depth two, and so on
/// until nothing new appears.
pub fn from_anchors(anchors: &[CertFile], limits: &Limits) -> Crawled {
    from_anchors_with(anchors, limits, |_| None)
}

/// [`from_anchors`], with `fallback` supplying an earlier copy of a repository that does not
/// answer, so the walk continues through it rather than losing what lies beyond it.
pub fn from_anchors_with(
    anchors: &[CertFile],
    limits: &Limits,
    fallback: impl Fn(&str) -> Option<Vec<u8>>,
) -> Crawled {
    let mut queue: Vec<String> = vec![];
    let mut seen_uris: BTreeSet<String> = BTreeSet::new();
    let mut seen_certs: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut out = Crawled {
        certificates: vec![],
        fetched: 0,
        absent: vec![],
        unreachable: vec![],
        fell_back: vec![],
        truncated: false,
        bundles: vec![],
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

        let bytes = match fetch_with_retries(&uri) {
            Ok(b) => b,
            Err(crate::refresh::FetchError::Absent(why)) => {
                out.absent.push(why);
                continue;
            }
            Err(crate::refresh::FetchError::Unreachable(why)) => match fallback(&uri) {
                Some(earlier) => {
                    log::warn!("{why}; using the copy from an earlier walk");
                    out.fell_back.push(why);
                    earlier
                }
                None => {
                    out.unreachable.push(why);
                    continue;
                }
            },
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
        out.bundles.push((uri.clone(), bytes));

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

/// Retries for a repository that gave no answer, before falling back to an earlier copy or going
/// without. A momentary DNS or connection hiccup is common among dozens of fetches; observed
/// 2026-10-27, when a lookup for `crl.disa.mil` failed once and answered minutes later.
const RETRIES: u64 = 2;

/// Fetch `uri`, asking again after a pause when nothing answered. A 4xx is the publisher's answer
/// about its own repository and asking again cannot change it, so it is returned at once.
fn fetch_with_retries(uri: &str) -> Result<Vec<u8>, crate::refresh::FetchError> {
    let mut attempt = 0;
    loop {
        let why = match crate::refresh::fetch(uri) {
            Err(crate::refresh::FetchError::Unreachable(why)) => why,
            other => return other,
        };
        if attempt == RETRIES {
            return Err(crate::refresh::FetchError::Unreachable(why));
        }
        attempt += 1;
        log::info!("{why}; asking again ({attempt} of {RETRIES})");
        std::thread::sleep(std::time::Duration::from_secs(5 * attempt));
    }
}

/// The bundle URIs a certificate names: SIA `caRepository` and AIA `caIssuers`.
///
/// Both directions, because neither alone covers a mesh. `caRepository` points down, at what the
/// certificate's subject issued; `caIssuers` points up, at what was issued to the certificate's
/// issuer, which in a mesh includes cross-certificates from other bridges. SIA is the rarer of the
/// two: of the 158 certificates a SIA-only walk of the FPKI reached on 2026-10-27, 58 carried it
/// and 155 carried `caIssuers`, so a walk that read SIA alone found a CA only where the CA above it
/// happened to publish one. What the extra reach brings in that does not validate back to the
/// anchor is dropped at generation, so following more links can widen the store but not loosen it.
///
/// Only those two access methods, and only `http`/`https`: OCSP and the other methods point at
/// services rather than at bundles, and a URI scheme this cannot fetch is not a failure worth
/// reporting on every hop.
fn repositories(der: &[u8]) -> Vec<String> {
    let Ok(cert) = Certificate::from_der(der) else {
        return vec![];
    };
    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return vec![];
    };

    let mut descriptions = vec![];
    for ext in extensions.iter() {
        match ext.extn_id {
            ID_PE_SUBJECT_INFO_ACCESS => {
                if let Ok(sia) = SubjectInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) {
                    descriptions.extend(
                        sia.0
                            .into_iter()
                            .filter(|d| d.access_method == ID_AD_CA_REPOSITORY),
                    );
                }
            }
            ID_PE_AUTHORITY_INFO_ACCESS => {
                if let Ok(aia) = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) {
                    descriptions.extend(
                        aia.0
                            .into_iter()
                            .filter(|d| d.access_method == ID_AD_CA_ISSUERS),
                    );
                }
            }
            _ => {}
        }
    }

    let mut uris = vec![];
    for desc in descriptions {
        if let GeneralName::UniformResourceIdentifier(uri) = &desc.access_location {
            let uri = uri.as_str();
            if uri.starts_with("http://") || uri.starts_with("https://") {
                uris.push(uri.to_string());
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
/// A self-signed certificate reached during the walk is dropped; see
/// [`crate::ingest::drop_self_signed`].
pub fn into_inputs(
    pe: &certval::PkiEnvironment,
    anchors: Vec<CertFile>,
    crawled: Crawled,
) -> crate::core::StoreInputs {
    let (intermediates, roots_seen) = crate::ingest::drop_self_signed(pe, crawled.certificates);
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

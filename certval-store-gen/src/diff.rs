//! Comparing two stores by content: which certificates and which partial paths one has that the
//! other does not.
//!
//! A store is a binary blob, and the questions asked of a refresh are about its contents: which
//! cross-certificates arrived, which left, and whether the path graph moved even where the
//! certificate set did not, which is what a regeneration produces. A count says that something
//! moved; this says what.
//!
//! Certificates are compared as a set, keyed by the SHA-256 of their DER, so neither order nor
//! duplicates read as a change. Partial paths are compared by the certificates they run through
//! rather than by their indices, since an index is a position in one store's buffers and means
//! nothing in the other.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use certval::{name_to_string, BuffersAndPaths};

/// A certificate as the diff names it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertSummary {
    /// The subject, or the SHA-256 of the DER when the buffer does not parse as a certificate.
    pub subject: String,
    /// The issuer, empty when the buffer does not parse.
    pub issuer: String,
    /// The serial number in hex, empty when the buffer does not parse.
    pub serial: String,
}

/// What differs between two stores.
#[derive(Debug, Default)]
pub struct StoreDiff {
    /// Distinct certificates in the old store.
    pub old_certificates: usize,
    /// Distinct certificates in the new store.
    pub new_certificates: usize,
    /// Certificates the new store has and the old one does not, sorted by subject.
    pub added: Vec<CertSummary>,
    /// Certificates the old store has and the new one does not, sorted by subject.
    pub removed: Vec<CertSummary>,
    /// Distinct partial paths in the old store.
    pub old_paths: usize,
    /// Distinct partial paths in the new store.
    pub new_paths: usize,
    /// Paths only the new store has, each as the subjects it runs through, leaf CA last.
    pub paths_added: Vec<Vec<String>>,
    /// Paths only the old store has, each as the subjects it runs through, leaf CA last.
    pub paths_removed: Vec<Vec<String>>,
}

impl StoreDiff {
    /// Whether the two stores hold the same certificates and the same partial paths.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.paths_added.is_empty()
            && self.paths_removed.is_empty()
    }

    /// The difference as text for a person or a commit message. Paths are listed only when
    /// `list_paths` is set, since a regenerated mesh can move hundreds of them; their counts are
    /// always given.
    pub fn render(&self, list_paths: bool) -> String {
        let mut out = String::new();
        if self.is_empty() {
            let _ = writeln!(
                out,
                "no difference: {} certificates, {} partial paths",
                self.new_certificates, self.new_paths
            );
            return out;
        }

        let _ = writeln!(
            out,
            "certificates: {} -> {} ({} added, {} removed)",
            self.old_certificates,
            self.new_certificates,
            self.added.len(),
            self.removed.len()
        );
        for (sign, certs) in [("+", &self.added), ("-", &self.removed)] {
            for c in certs {
                match c.issuer.is_empty() {
                    true => {
                        let _ = writeln!(out, "  {sign} {} (does not parse)", c.subject);
                    }
                    false => {
                        let _ = writeln!(
                            out,
                            "  {sign} {}\n      issued by {}, serial {}",
                            c.subject, c.issuer, c.serial
                        );
                    }
                }
            }
        }

        let _ = writeln!(
            out,
            "partial paths: {} -> {} ({} added, {} removed)",
            self.old_paths,
            self.new_paths,
            self.paths_added.len(),
            self.paths_removed.len()
        );
        if list_paths {
            for (sign, paths) in [("+", &self.paths_added), ("-", &self.paths_removed)] {
                for p in paths {
                    let _ = writeln!(out, "  {sign} {}", p.join(" -> "));
                }
            }
        }
        out
    }
}

/// Read and compare the stores at two paths.
pub fn diff_files(old: &Path, new: &Path) -> Result<StoreDiff> {
    let read =
        |p: &Path| std::fs::read(p).with_context(|| format!("failed to read {}", p.display()));
    diff_bytes(&read(old)?, &read(new)?)
        .with_context(|| format!("comparing {} with {}", old.display(), new.display()))
}

/// Compare two serialized stores.
pub fn diff_bytes(old: &[u8], new: &[u8]) -> Result<StoreDiff> {
    let parse = |b: &[u8], which: &str| -> Result<BuffersAndPaths> {
        ciborium::de::from_reader(b)
            .map_err(|e| anyhow!("the {which} store is not a certval CBOR store: {e}"))
    };
    diff_stores(&parse(old, "old")?, &parse(new, "new")?)
}

/// Compare two decoded stores.
pub fn diff_stores(old: &BuffersAndPaths, new: &BuffersAndPaths) -> Result<StoreDiff> {
    let old_certs = certificates(old);
    let new_certs = certificates(new);
    let old_paths = paths(old, "old")?;
    let new_paths = paths(new, "new")?;

    // Every certificate either store holds, so a path can be named whichever side it came from.
    let mut by_digest: BTreeMap<[u8; 32], &[u8]> = BTreeMap::new();
    by_digest.extend(old_certs.iter().map(|(d, b)| (*d, *b)));
    by_digest.extend(new_certs.iter().map(|(d, b)| (*d, *b)));
    let subject_of = |d: &[u8; 32]| summarize(by_digest[d]).subject;

    let summaries = |only: Vec<&[u8; 32]>| {
        let mut v: Vec<CertSummary> = only.into_iter().map(|d| summarize(by_digest[d])).collect();
        v.sort();
        v
    };
    let named = |only: Vec<&Vec<[u8; 32]>>| {
        let mut v: Vec<Vec<String>> = only
            .into_iter()
            .map(|p| p.iter().map(subject_of).collect())
            .collect();
        v.sort();
        v
    };

    Ok(StoreDiff {
        old_certificates: old_certs.len(),
        new_certificates: new_certs.len(),
        added: summaries(
            new_certs
                .keys()
                .filter(|d| !old_certs.contains_key(*d))
                .collect(),
        ),
        removed: summaries(
            old_certs
                .keys()
                .filter(|d| !new_certs.contains_key(*d))
                .collect(),
        ),
        old_paths: old_paths.len(),
        new_paths: new_paths.len(),
        paths_added: named(new_paths.difference(&old_paths).collect()),
        paths_removed: named(old_paths.difference(&new_paths).collect()),
    })
}

/// A store's distinct certificates, keyed by the SHA-256 of their DER.
fn certificates(store: &BuffersAndPaths) -> BTreeMap<[u8; 32], &[u8]> {
    store
        .buffers
        .iter()
        .map(|b| (Sha256::digest(&b.bytes).into(), b.bytes.as_slice()))
        .collect()
}

/// A store's distinct partial paths, each as the digests of the certificates it runs through.
fn paths(store: &BuffersAndPaths, which: &str) -> Result<BTreeSet<Vec<[u8; 32]>>> {
    let digests: Vec<[u8; 32]> = store
        .buffers
        .iter()
        .map(|b| Sha256::digest(&b.bytes).into())
        .collect();
    let mut out = BTreeSet::new();
    for by_key in &store.partial_paths {
        for rows in by_key.values() {
            for row in rows {
                let mut path = Vec::with_capacity(row.len());
                for &i in row {
                    let d = digests.get(i).ok_or_else(|| {
                        anyhow!(
                            "the {which} store's partial paths name buffer {i}, and it holds {}",
                            digests.len()
                        )
                    })?;
                    path.push(*d);
                }
                out.insert(path);
            }
        }
    }
    Ok(out)
}

/// Name a certificate by subject, issuer and serial; a buffer that does not parse is named by its
/// digest instead, since it is still a difference worth reporting.
fn summarize(der: &[u8]) -> CertSummary {
    match Certificate::from_der(der) {
        Ok(c) => CertSummary {
            subject: name_to_string(c.tbs_certificate().subject()),
            issuer: name_to_string(c.tbs_certificate().issuer()),
            serial: hex(c.tbs_certificate().serial_number().as_bytes()),
        },
        Err(_) => CertSummary {
            subject: format!("sha256:{}", hex(&Sha256::digest(der))),
            issuer: String::new(),
            serial: String::new(),
        },
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    const ROOT3: &[u8] = include_bytes!("../anchors/DoD_Root_CA_3.der");
    const ROOT5: &[u8] = include_bytes!("../anchors/DoD_Root_CA_5.der");
    const SECTIGO: &[u8] = include_bytes!("../anchors/Sectigo_Public_Time_Stamping_Root_R46.der");

    /// A serialized store holding `certs`, with `paths` as rows of buffer indices. Built as a CBOR
    /// value because `BuffersAndPaths` cannot be constructed outside certval.
    fn store(certs: &[&[u8]], paths: &[&[usize]]) -> Vec<u8> {
        let buffers = certs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                Value::Map(vec![
                    (Value::Text("filename".into()), Value::Text(format!("{i}"))),
                    (Value::Text("bytes".into()), Value::Bytes(c.to_vec())),
                ])
            })
            .collect();
        let rows = paths
            .iter()
            .map(|p| Value::Array(p.iter().map(|&i| Value::Integer(i.into())).collect()))
            .collect();
        let partial_paths = Value::Array(vec![Value::Map(vec![(
            Value::Text("key".into()),
            Value::Array(rows),
        )])]);
        let v = Value::Map(vec![
            (Value::Text("buffers".into()), Value::Array(buffers)),
            (Value::Text("partial_paths".into()), partial_paths),
        ]);
        let mut out = vec![];
        ciborium::ser::into_writer(&v, &mut out).unwrap();
        out
    }

    /// The same certificates in a different order, with paths renumbered to match, are no
    /// difference: indices are positions, not identities.
    #[test]
    fn order_and_indices_are_not_a_difference() {
        let a = store(&[ROOT3, ROOT5, SECTIGO], &[&[0, 1], &[1, 2]]);
        let b = store(&[SECTIGO, ROOT3, ROOT5], &[&[1, 2], &[2, 0]]);
        let d = diff_bytes(&a, &b).unwrap();
        assert!(d.is_empty(), "{}", d.render(true));
        assert_eq!(d.new_certificates, 3);
        assert_eq!(d.new_paths, 2);
    }

    /// An added and a removed certificate are named by subject, and a path that moved is reported
    /// even where the certificate set did not.
    #[test]
    fn certificates_and_paths_that_moved_are_named() {
        let a = store(&[ROOT3, ROOT5], &[&[0, 1]]);
        let b = store(&[ROOT5, SECTIGO], &[&[0, 1]]);
        let d = diff_bytes(&a, &b).unwrap();
        assert_eq!(d.added.len(), 1);
        assert!(d.added[0].subject.contains("Sectigo"), "{:?}", d.added);
        assert_eq!(d.removed.len(), 1);
        assert!(
            d.removed[0].subject.contains("DoD Root CA 3"),
            "{:?}",
            d.removed
        );
        assert_eq!(d.paths_added.len(), 1);
        assert_eq!(d.paths_removed.len(), 1);

        // Same certificates, different graph: what regeneration produces.
        let c = store(&[ROOT3, ROOT5], &[&[1, 0]]);
        let d = diff_bytes(&a, &c).unwrap();
        assert!(d.added.is_empty() && d.removed.is_empty());
        assert_eq!((d.paths_added.len(), d.paths_removed.len()), (1, 1));
        let text = d.render(true);
        assert!(
            text.contains("certificates: 2 -> 2 (0 added, 0 removed)"),
            "{text}"
        );
        assert!(
            text.contains("partial paths: 1 -> 1 (1 added, 1 removed)"),
            "{text}"
        );
    }

    /// A path naming a buffer the store does not hold is an error, not a silent skip.
    #[test]
    fn a_path_beyond_the_buffers_is_refused() {
        let a = store(&[ROOT3], &[&[0, 5]]);
        let err = diff_bytes(&a, &a).unwrap_err().to_string();
        assert!(err.contains("buffer 5"), "{err}");
    }
}

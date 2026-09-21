//! CCADB intermediate-certificate ingest.
//!
//! Reads the Common CA Database "All Intermediate Certs (with PEM)" CSV export — the
//! canonical Web PKI intermediate set — and yields the certificates as [`CertFile`]s for
//! the intermediate (`ca.cbor`) store.
//!
//! Report:
//! `https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV`
//!
//! Each row's `PEM Info` column holds a single PEM certificate wrapped in single quotes
//! inside the CSV field. The CSV crate handles the quoted multi-line field; we strip the
//! surrounding single quotes and decode the PEM to DER (preserving the original signed
//! bytes rather than re-encoding). The export retains long-expired intermediates, which are
//! dead weight in a preload, so by default only currently-valid certs are kept.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use base64ct::{Base64, Encoding};
use certval::CertFile;
use der::Decode;
use x509_cert::certificate::{CertificateInner, Raw};

/// The CSV column holding the PEM certificate.
const PEM_COL: &str = "PEM Info";
/// The CSV column holding a human-readable certificate name (used as the label).
const NAME_COL: &str = "Certificate Name";

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Read CCADB intermediates from the CSV at `path`. When `include_expired` is false, certs
/// whose validity window does not contain `now_unix` (seconds since the Unix epoch) are
/// skipped.
pub fn read_ccadb_csv(path: &Path, include_expired: bool, now_unix: u64) -> Result<Vec<CertFile>> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("failed to open CCADB CSV {}", path.display()))?;

    let headers = rdr
        .headers()
        .context("CCADB CSV has no header row")?
        .clone();
    let pem_idx = col(&headers, PEM_COL)?;
    let name_idx = col(&headers, NAME_COL).ok();

    let mut out = Vec::new();
    let (mut skipped_empty, mut skipped_bad, mut skipped_expired) = (0usize, 0usize, 0usize);

    for rec in rdr.records() {
        let rec = rec.context("failed to read CCADB CSV record")?;
        let raw = rec.get(pem_idx).unwrap_or("").trim();
        if raw.is_empty() {
            skipped_empty += 1;
            continue;
        }

        let der = match pem_to_der(raw) {
            Some(der) => der,
            None => {
                skipped_bad += 1;
                continue;
            }
        };

        if !include_expired {
            match CertificateInner::<Raw>::from_der(&der) {
                Ok(cert) if !within_validity(&cert, now_unix) => {
                    skipped_expired += 1;
                    continue;
                }
                Err(_) => {
                    skipped_bad += 1;
                    continue;
                }
                _ => {}
            }
        }

        let filename = name_idx
            .and_then(|i| rec.get(i))
            .filter(|s| !s.is_empty())
            .unwrap_or("ccadb-intermediate")
            .to_string();
        out.push(CertFile {
            filename,
            bytes: der,
        });
    }

    log::info!(
        "CCADB CSV: {} intermediates ({} empty, {} unparsable, {} outside validity)",
        out.len(),
        skipped_empty,
        skipped_bad,
        skipped_expired
    );
    Ok(out)
}

/// Decode a certificate PEM to DER leniently: locate the certificate guards (ignoring any
/// surrounding quoting), strip all whitespace from the base64 body, and decode. Deliberately
/// tolerant of non-RFC-7468 line wrapping — a chunk of the CCADB export wraps base64 at 65
/// characters, which a strict RFC 7468 reader rejects outright.
fn pem_to_der(field: &str) -> Option<Vec<u8>> {
    let start = field.find(PEM_BEGIN)? + PEM_BEGIN.len();
    let rest = &field[start..];
    let end = rest.find(PEM_END)?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    Base64::decode_vec(&body).ok()
}

/// True if `now_unix` falls within the certificate's validity window.
fn within_validity(cert: &CertificateInner<Raw>, now_unix: u64) -> bool {
    let v = cert.tbs_certificate().validity();
    let nb = v.not_before.to_unix_duration().as_secs();
    let na = v.not_after.to_unix_duration().as_secs();
    nb <= now_unix && now_unix <= na
}

/// Index of the column named `name` in the header row.
fn col(headers: &csv::StringRecord, name: &str) -> Result<usize> {
    headers
        .iter()
        .position(|h| h == name)
        .ok_or_else(|| anyhow!("CCADB CSV missing expected column '{name}'"))
}

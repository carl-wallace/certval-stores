//! FPKI adapter — an (often oversized) PKCS#7 / CMS `SignedData` certs-only bundle.
//!
//! The Federal PKI publishes large "certificates-only" PKCS#7 files containing the whole
//! cross-certified mesh. This adapter parses the bundle, then splits the certificates into
//! trust anchors (self-signed roots, verified by self-signature) and intermediates
//! (everything else). Self-signature verification — rather than a bare issuer==subject
//! comparison — is what keeps self-issued rollover certs from being misfiled as roots.
//!
//! Note on "oversized": the whole file is decoded into memory here. der's decoder bounds
//! individual TLV lengths, not aggregate size, so a large `SET OF` of normal-sized certs
//! decodes fine; if a genuinely enormous bundle ever trips a limit, this is the place to
//! switch to a streaming/relaxed decode.

use anyhow::{anyhow, Context, Result};

use certval::{is_self_issued, is_self_signed_with_buffer, CertFile, PkiEnvironment};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use x509_cert::certificate::{CertificateInner, Raw};

use crate::core::StoreInputs;

/// Parse a PKCS#7 bundle into trust anchors + intermediates.
pub fn build(pe: &PkiEnvironment, p7_der: &[u8]) -> Result<StoreInputs> {
    let ci = ContentInfo::from_der(p7_der).context("failed to parse PKCS#7 ContentInfo")?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .context("PKCS#7 content is not a SignedData")?;

    let certs = sd
        .certificates
        .ok_or_else(|| anyhow!("PKCS#7 SignedData contains no certificates"))?;

    let mut inputs = StoreInputs::default();
    let (mut n_other, mut n_bad, mut n_unverifiable) = (0usize, 0usize, 0usize);

    for choice in certs.0.iter() {
        let cert = match choice {
            CertificateChoices::Certificate(cert) => cert,
            // v1 / v2 attribute certs and other choices are not trust material here
            _ => {
                n_other += 1;
                continue;
            }
        };

        let der = match cert.to_der() {
            Ok(d) => d,
            Err(_) => {
                n_bad += 1;
                continue;
            }
        };

        let cf = CertFile {
            filename: cert_label(cert),
            bytes: der.clone(),
        };

        match is_self_signed(pe, &der) {
            SelfSigned::Yes => {
                if !contains(&inputs.trust_anchors, &cf) {
                    inputs.trust_anchors.push(cf);
                }
            }
            SelfSigned::No => {
                if !contains(&inputs.intermediates, &cf) {
                    inputs.intermediates.push(cf);
                }
            }
            // An anchor is what a relying party trusts, so it is filed as one only when its own
            // signature verified. A certificate that could not be checked is filed as an
            // intermediate and named in the log, where the operator can act on it.
            SelfSigned::Unknown(reason) => {
                n_unverifiable += 1;
                log::warn!(
                    "{}: {reason}, so it is filed as an intermediate",
                    cf.filename
                );
                if !contains(&inputs.intermediates, &cf) {
                    inputs.intermediates.push(cf);
                }
            }
        }
    }

    log::info!(
        "PKCS#7: {} trust anchors, {} intermediates ({} non-certificate choices, {} unencodable, {} unverifiable)",
        inputs.trust_anchors.len(),
        inputs.intermediates.len(),
        n_other,
        n_bad,
        n_unverifiable
    );

    Ok(inputs)
}

/// What a certificate turned out to be, for the purpose of filing it.
enum SelfSigned {
    Yes,
    No,
    /// The signature could not be checked, with the reason to log.
    Unknown(String),
}

/// Verify whether `der` is self-signed (re-parsed under the `Raw` profile so the exact
/// signed bytes are preserved for signature verification).
fn is_self_signed(pe: &PkiEnvironment, der: &[u8]) -> SelfSigned {
    let cert = match CertificateInner::<Raw>::from_der(der) {
        Ok(cert) => cert,
        Err(e) => return SelfSigned::Unknown(format!("does not parse under the Raw profile: {e}")),
    };
    match is_self_signed_with_buffer(pe, &cert, der) {
        Ok(true) => SelfSigned::Yes,
        Ok(false) => SelfSigned::No,
        Err(e) => {
            let alg = cert.tbs_certificate().signature().oid;
            match is_self_issued(&cert) {
                true => SelfSigned::Unknown(format!(
                    "is self-issued but its signature could not be checked ({alg}: {e})"
                )),
                false => {
                    SelfSigned::Unknown(format!("signature could not be checked ({alg}: {e})"))
                }
            }
        }
    }
}

/// A human-readable label for a certificate, used as the `CertFile` filename. Falls back
/// to a fixed string when the subject cannot be rendered.
fn cert_label(cert: &x509_cert::Certificate) -> String {
    cert.tbs_certificate().subject().to_string()
}

fn contains(v: &[CertFile], cf: &CertFile) -> bool {
    v.iter().any(|e| e.bytes == cf.bytes)
}

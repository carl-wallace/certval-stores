//! Certificate ingest helpers shared by the adapters.

use anyhow::{anyhow, Result};

use std::path::Path;

use crate::core::StoreInputs;
use der::Decode;
use x509_cert::Certificate;

use certval::{
    cert_folder_to_vec, certs_from_signed_data, decode_pem_to_ders, parse_cert, ta_folder_to_vec,
    CertFile, CertSource, PkiEnvironment, TaSource, TimeOfInterest,
};

/// Read a folder of DER/PEM CA certificates into a vector of [`CertFile`] destined for
/// the intermediate (`ca.cbor`) store.
///
/// Delegates to certval's `cert_folder_to_vec`, which recurses the directory, accepts
/// `.der` / `.cer` / `.crt` files, drops anything that will not parse, drops certs not
/// valid at `toi`, and — importantly for the intermediate store — drops self-signed
/// certificates. Any roots mixed into the folder are therefore filtered out here rather
/// than polluting the partial-path graph.
pub fn read_intermediates_dir(
    pe: &PkiEnvironment,
    dir: &str,
    toi: TimeOfInterest,
) -> Result<Vec<CertFile>> {
    let mut store = CertSource::new();
    cert_folder_to_vec(pe, dir, &mut store, toi)
        .map_err(|e| anyhow!("failed to read intermediates from {dir}: {e:?}"))?;
    Ok(store.get_buffers())
}

/// Read a folder of DER/PEM trust-anchor certificates into a vector of [`CertFile`]
/// destined for the `ta.cbor` store.
///
/// Delegates to certval's `ta_folder_to_vec`, which recurses the directory, accepts
/// `.der` / `.cer` / `.crt` / `.ta` files, and keeps only those that parse as a
/// `TrustAnchorChoice::Certificate` valid at `toi`. Unlike the intermediates path this
/// does not drop self-signed certs — roots are expected to be self-signed.
pub fn read_ta_dir(pe: &PkiEnvironment, dir: &str, toi: TimeOfInterest) -> Result<Vec<CertFile>> {
    let mut store = TaSource::new();
    ta_folder_to_vec(pe, dir, &mut store, toi)
        .map_err(|e| anyhow!("failed to read trust anchors from {dir}: {e:?}"))?;
    Ok(store.get_tas())
}

/// Read one certificate file named on the command line: a single DER or PEM certificate,
/// a concatenated PEM file, or a certs-only PKCS#7 bundle (`.p7c` / `.p7b`) as a CA
/// publishes at its own SIA.
///
/// Containers are expanded here rather than left to a DER-only parse. A `.p7c` is a
/// SignedData, and a DER-only parse takes one for a single unparseable certificate --
/// which is how a bundle of five silently becomes nothing.
///
/// Unlike the folder helpers above this applies no validity filter: the caller supplies
/// these deliberately, and `generate` records what a PKI published rather than what is
/// current today.
pub fn read_cert_file(path: &Path) -> Result<Vec<CertFile>> {
    let bytes =
        std::fs::read(path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    certs_from_bytes(&bytes).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// As [`read_cert_file`], for bytes already in hand -- something fetched rather than read.
///
/// The container check comes first, for the reason in [`read_cert_file`]'s comment: a `.p7c`
/// parsed as a bare DER certificate is one unparseable certificate rather than the five it
/// holds.
pub fn certs_from_bytes(bytes: &[u8]) -> Result<Vec<CertFile>> {
    if let Some(ders) = certs_from_signed_data(bytes) {
        return Ok(ders.into_iter().map(named).collect());
    }
    if let Ok(ders) = decode_pem_to_ders(bytes) {
        if !ders.is_empty() {
            return Ok(ders.into_iter().map(named).collect());
        }
    }
    // A bare DER certificate. Parsed rather than trusted, so bytes that are neither a
    // certificate nor a container fail here rather than at serialization.
    parse_cert(bytes, "").map_err(|e| {
        anyhow!("not a certificate, a PEM file or a certs-only PKCS#7 bundle: {e:?}")
    })?;
    Ok(vec![named(bytes.to_vec())])
}

/// Wrap DER in a [`CertFile`] labelled from its own subject, falling back to the digest
/// prefix when it will not parse -- a certificate with no readable name still needs a
/// distinct one, and the caller's file name is the wrong answer.
fn named(bytes: Vec<u8>) -> CertFile {
    // Parsed through x509-cert rather than certval here: `label_for` works on the RFC 5280
    // profile, and certval's parse hands back the raw-profile view.
    let filename = Certificate::from_der(&bytes)
        .map(|c| label_for(&c))
        .unwrap_or_else(|_| "unparseable".to_string());
    CertFile { filename, bytes }
}

/// Drop any self-issued certificate from a set destined for the intermediate store,
/// returning what survives and reporting what did not.
///
/// The folder helper gets this from certval's `cert_folder_to_vec`; material named file by
/// file bypasses that, and a root landing in `ca.cbor` gives the partial-path graph a node
/// whose issuer is itself.
pub fn reject_self_issued(certs: Vec<CertFile>) -> Vec<CertFile> {
    certs
        .into_iter()
        .filter(|cf| match parse_cert(&cf.bytes, &cf.filename) {
            Ok(cert) => {
                let tbs = cert.decoded().tbs_certificate();
                if tbs.issuer() == tbs.subject() {
                    log::warn!(
                        "skipping {}: self-issued, so it belongs in the trust anchors rather than the CA store",
                        cf.filename
                    );
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                log::warn!("skipping {}: will not parse ({e:?})", cf.filename);
                false
            }
        })
        .collect()
}

/// A filesystem-safe label for a certificate, from its common name.
///
/// The same convention the InstallRoot adapter uses, so material merged in from a file
/// lands beside stream material under names of the same shape. Deriving it from the
/// subject rather than from the source file also keeps a supplied file's name -- and a
/// container's, and the index within it -- out of the store and out of the repository.
pub fn label_for(cert: &Certificate) -> String {
    let subject = cert.tbs_certificate().subject().to_string();
    let cn = subject
        .split(',')
        .find_map(|rdn| rdn.trim().strip_prefix("CN="))
        .unwrap_or(&subject);
    cn.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Merge material named file by file into inputs an adapter produced.
///
/// For what a stream cannot carry: DoD Interoperability Root CA 2 appears in no `.ir4`
/// message, so an interoperability environment has to be handed it, along with the bundle
/// that root publishes at its own SIA.
///
/// Merged before the partial-path graph is built, so the extras take part in it rather
/// than being appended to a finished store. `generate` dedupes, so naming a certificate
/// the stream already carries costs nothing.
pub fn merge_extras(
    inputs: &mut StoreInputs,
    extra_roots: &[impl AsRef<Path>],
    extra_cas: &[impl AsRef<Path>],
) -> Result<()> {
    for path in extra_roots {
        let path = path.as_ref();
        let certs = read_cert_file(path)?;
        log::info!(
            "merging {} trust anchor(s) from {}",
            certs.len(),
            path.display()
        );
        inputs.trust_anchors.extend(certs);
    }
    for path in extra_cas {
        let path = path.as_ref();
        let certs = reject_self_issued(read_cert_file(path)?);
        log::info!(
            "merging {} CA certificate(s) from {}",
            certs.len(),
            path.display()
        );
        inputs.intermediates.extend(certs);
    }
    Ok(())
}

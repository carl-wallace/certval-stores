//! Microsoft root program adapter — `authrootstl.cab` → `authroot.stl` → one `.crt` per thumbprint.
//!
//! Microsoft publishes its root program as a **certificate trust list**: a signed list of SHA-1
//! thumbprints with per-root metadata, and no certificates at all. The certificates are served
//! individually, each at a URL named after its own thumbprint. So collecting this program is three
//! steps rather than one bundle fetch:
//!
//! ```text
//! authrootstl.cab              Authenticode-signed cabinet, ~80 KB
//!   authroot.stl               CMS SignedData wrapping a CTL: ~562 TrustedSubject entries
//!     <THUMBPRINT>.crt         one GET each, ~1-2 KB
//! ```
//!
//! **The cabinet is not signed, and the list inside it is.** Measured: `authrootstl.cab` has
//! `flags` `0x0000`, so it carries no reserved area and therefore no Authenticode signature — it is
//! packaging (`TrustedTpm.cab`, by contrast, is `0x0004`). What is signed is `authroot.stl` itself,
//! a CMS `SignedData` whose signer is `Microsoft Certificate Trust List Publisher`, chaining
//! through `Microsoft Certificate List CA 2024` to `Microsoft Root Certificate Authority 2010`.
//! So this adapter takes [`crate::cab::members`], not `open_verified`, and calls [`verify_stl`].
//!
//! **Two checks, and both are needed.** [`verify_stl`] establishes that the *list* is Microsoft's;
//! the thumbprint comparison in [`build`] establishes that each *certificate* is the one the list
//! named. Neither implies the other: the certificates are fetched one by one over plain HTTP and
//! are not signed by anybody, and a signed list of thumbprints says nothing about what a CDN
//! actually served. So do not assemble a store from [`fetch_certificates`] output by hand, and do
//! not read a list that has not been through `verify_stl`.
//!
//! **Per-entry EKUs are what split this program into environments.** Each entry carries the
//! purposes Microsoft grants that root, which is the metadata CCADB gives Mozilla consumers through
//! a CSV. Filtering on it here is why `msft_tls` can mean "the roots Microsoft trusts for servers"
//! rather than "every root, and you sort out the purpose".
//!
//! **The list is an inventory, not a trust decision, and two kinds of entry in it are not
//! trustworthy.** Expired roots stay listed -- `CDD4EEAE…` has been expired since 2021, and a
//! VeriSign timestamping root since 2004 -- and a root can remain listed while the program
//! distrusts it from a date, carried as [`ATTR_DISALLOWED_AFTER`]. [`build`] drops both, so what
//! it yields is what the program trusts on the day it runs. Carrying either would mean shipping
//! `DigiCert Baltimore Root` as trusted after Microsoft retired it on 2026-09-15.
//!
//! ## The published list, measured 2026-09-22
//!
//! ```text
//! subjectUsage      1.3.6.1.4.1.311.10.3.9 (szOID_ROOT_LIST_SIGNER)
//! listIdentifier    absent
//! thisUpdate        2026-08-25
//! subjectAlgorithm  1.3.14.3.2.26 (SHA-1)
//! trustedSubjects   562 entries, 197,648 bytes
//! ```
//!
//! Per-entry properties, by how many of the 562 entries carry them — the ones this adapter reads
//! are `…11.9` and `…11.11`, and the rest are left alone rather than guessed at:
//!
//! ```text
//! 562  …10.11.29    562  …10.11.20    562  …10.11.98    562  …10.11.11  friendly name
//! 556  …10.11.9     EKUs             302  …10.11.126   207  …10.11.104
//! 166  …10.11.83    166  …10.11.127    27  …10.11.122     8  …10.11.105
//! ```
//!
//! Six entries carry no EKU property at all, so an entry granting nothing is a real shape and not
//! a parse failure — which is why [`Entry::ekus`] being empty means *unstated* rather than *none*.

use std::collections::BTreeSet;
#[cfg(feature = "fetch")]
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    PDVCertificate, PkiEnvironment, TaSource, TimeOfInterest,
};
use cms::attr::MessageDigest;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
use const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
use const_oid::db::rfc5912::{ID_SHA_256, RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, SetOfVec, Uint};
use der::{Decode, Encode, Sequence};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_cert::attr::Attribute;
use x509_cert::ext::Extensions;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::core::StoreInputs;

/// The cabinet carrying the trusted-root list.
pub const CAB_URL: &str =
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";

/// Where a single root is served, by uppercase hex SHA-1 thumbprint: `{PREFIX}{THUMBPRINT}.crt`.
pub const CERT_URL_PREFIX: &str =
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/";

/// The only member of `authrootstl.cab` worth reading.
pub const STL_MEMBER: &str = "authroot.stl";

/// `szOID_CTL` — the content type of a certificate trust list.
pub const ID_CTL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");

/// `CERT_ENHKEY_USAGE_PROP_ID` (9) as a CTL entry attribute: the EKUs Microsoft grants the root.
const ATTR_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.11.9");

/// `CERT_FRIENDLY_NAME_PROP_ID` (11): the name Microsoft shows for the root, UTF-16LE.
const ATTR_FRIENDLY_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.11.11");

/// `CERT_DISALLOWED_FILETIME_PROP_ID` (104): the date after which the program stops trusting this
/// root, as a Windows `FILETIME`. A root carrying one is still listed -- the list is an inventory,
/// and this is how Microsoft retires a root without removing it.
///
/// Read as a restriction rather than guessed at: of the 205 entries carrying it, the roots are
/// 129 SHA-1 and 8 MD5 against a program that is otherwise modern, the 2026 ML-DSA pilot roots
/// carry none, and the most recent values are `DigiCert Baltimore Root` and `GeoTrust Universal
/// CA` on 2026-09-15. A date-added property would look like none of that.
const ATTR_DISALLOWED_AFTER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.11.104");

/// Seconds between the `FILETIME` epoch (1601-01-01) and the Unix epoch.
const FILETIME_TO_UNIX: u64 = 11_644_473_600;

/// Signature algorithms certval cannot verify, so a root using one is not carried.
///
/// certval's RSA list begins at SHA-1 (`pdv_utilities::is_signature_alg_supported`): MD2, MD4 and
/// MD5 are absent, and no feature adds them. A root signed with one could be carried -- an
/// anchor's own signature is never checked during path validation -- but nothing it issued could
/// be verified either, so it would be an anchor that can anchor nothing.
///
/// A denylist of obsolete digests rather than an allowlist of supported algorithms, deliberately:
/// this list has seven ML-DSA-87 pilot roots in it today and will gain more, and an allowlist would
/// silently drop each new algorithm until someone updated it. This way a new algorithm arrives, and
/// only a provably dead one leaves.
const UNVERIFIABLE_SIGNATURE_ALGORITHMS: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.2"), // md2WithRSAEncryption
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.3"), // md4WithRSAEncryption
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4"), // md5WithRSAEncryption
];

/// `szOID_ROOT_LIST_SIGNER`, which is both the `subjectUsage` this list declares and the EKU its
/// signer's certificate must carry. Required during verification for the same reason
/// `tpm_cab_verify` requires code signing of a CAB signer: a Microsoft-chained key issued for some
/// other purpose must not be able to sign the root program.
pub const EKU_ROOT_LIST_SIGNER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.9");

/// `id-kp-serverAuth`, the TLS environment's filter.
pub const EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// `id-kp-codeSigning`.
pub const EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
/// `id-kp-emailProtection`, the S/MIME environment's filter.
pub const EKU_EMAIL_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

/// `CertificateTrustList`, as Microsoft documents it.
///
/// Decoded with `der`'s derive rather than read loosely, because the fields this adapter needs —
/// the entries and `this_update` — sit after three optional ones, and skipping to them by hand is
/// how a format change becomes a silently short list.
#[derive(Debug, Sequence)]
pub struct CertificateTrustList {
    /// What the list is for. `szOID_CTL_TRUSTED_SUBJECTS` for this one; a different value means a
    /// different list (the disallowed-certificate list is one).
    pub subject_usage: Vec<ObjectIdentifier>,
    /// e.g. `AuthRoot`.
    pub list_identifier: Option<OctetString>,
    pub sequence_number: Option<Uint>,
    /// When the publisher says it issued this list. Becomes `StoreInputs::published`.
    pub this_update: Time,
    pub next_update: Option<Time>,
    /// The digest the entries' `subject_identifier` values are computed with — SHA-1 here, and
    /// checked rather than assumed, since a future list could move and every thumbprint
    /// comparison in this module depends on it.
    pub subject_algorithm: AlgorithmIdentifierOwned,
    pub trusted_subjects: Option<Vec<TrustedSubject>>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub ctl_extensions: Option<Extensions>,
}

/// One root in the list: its thumbprint, and Microsoft's properties for it.
#[derive(Debug, Sequence)]
pub struct TrustedSubject {
    /// The SHA-1 digest of the certificate's DER, which is also how the certificate is addressed.
    pub subject_identifier: OctetString,
    pub subject_attributes: Option<SetOfVec<Attribute>>,
}

/// One entry, read into the shape a caller can act on.
pub struct Entry {
    /// SHA-1 of the certificate's DER, 20 bytes.
    pub thumbprint: Vec<u8>,
    /// The purposes Microsoft grants this root. Empty means the entry states none, which is not
    /// the same as "none are granted" — treat it as unknown rather than as a denial.
    pub ekus: Vec<ObjectIdentifier>,
    /// Microsoft's display name for the root, where it gives one.
    pub friendly_name: Option<String>,
    /// Unix seconds after which the program no longer trusts this root, where it says so.
    pub disallowed_after: Option<u64>,
}

impl Entry {
    /// Uppercase hex, which is both how Microsoft writes a thumbprint and how the `.crt` URL
    /// spells it.
    pub fn hex(&self) -> String {
        self.thumbprint
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    }

    /// Where this root's certificate is served.
    pub fn url(&self) -> String {
        format!("{CERT_URL_PREFIX}{}.crt", self.hex())
    }

    /// Whether Microsoft grants this root `eku`.
    pub fn grants(&self, eku: ObjectIdentifier) -> bool {
        self.ekus.contains(&eku)
    }
}

/// The list itself, once read.
pub struct Ctl {
    /// `this_update`, `YYYY-MM-DD`, for `StoreInputs::published`.
    pub published: String,
    /// The list's own version, uppercase hex. Compared against the committed copy to tell a
    /// republished-but-identical list from a changed one, which an HTTP validator cannot.
    pub sequence_number: Option<String>,
    pub entries: Vec<Entry>,
}

/// Read `authroot.stl` — a CMS `SignedData` whose encapsulated content is the CTL.
pub fn parse_stl(stl_der: &[u8]) -> Result<Ctl> {
    let ci = ContentInfo::from_der(stl_der).context("authroot.stl is not a CMS ContentInfo")?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .context("authroot.stl's content is not a SignedData")?;

    if sd.encap_content_info.econtent_type != ID_CTL {
        return Err(anyhow!(
            "authroot.stl encapsulates {} rather than a certificate trust list ({ID_CTL})",
            sd.encap_content_info.econtent_type
        ));
    }
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| anyhow!("authroot.stl carries no encapsulated content"))?;

    parse_ctl(&encapsulated(&econtent)?)
}

/// The `CertificateTrustList` bytes out of a `SignedData`'s encapsulated content, which are also
/// the bytes its signature is computed over.
///
/// CMS says eContent is `[0] EXPLICIT OCTET STRING`, and Microsoft does not write one: measured on
/// the published file, `[0]` holds the `CertificateTrustList` SEQUENCE itself. It is the same
/// deviation Authenticode makes with `SpcIndirectDataContent`, from the same publisher. Both
/// shapes are read -- the conformant one is what a reader expects and the non-conformant one is
/// what arrives -- and in the conformant shape the digest covers the octet string's contents,
/// which is what unwrapping yields.
fn encapsulated(econtent: &der::Any) -> Result<Vec<u8>> {
    let der = econtent
        .to_der()
        .context("encapsulated content is unreadable")?;
    Ok(match OctetString::from_der(&der) {
        Ok(wrapped) => wrapped.as_bytes().to_vec(),
        Err(_) => der,
    })
}

/// Verify that `authroot.stl` is Microsoft's, against pinned anchors.
///
/// The cabinet around it is unsigned, so this is the only signature in the chain of custody and
/// everything the adapter goes on to do rests on it. Four things are checked:
///
/// 1. the signed `messageDigest` attribute matches a digest of the encapsulated list;
/// 2. the signer's signature over the signed attributes verifies under the signer's key;
/// 3. the signer's certificate builds a path to one of `anchors`;
/// 4. that path is valid at the list's own `thisUpdate`, with [`EKU_ROOT_LIST_SIGNER`] required
///    across it.
///
/// **`anchors` must be pinned by the caller and never read out of the list.** The chain ends at
/// `Microsoft Root Certificate Authority 2010`, which this list carries as one of its own entries,
/// so verifying the list with a root taken from it would be circular. The provider crate commits
/// it as a generator input instead.
///
/// The time of interest is `thisUpdate` rather than now, for the reason `tpm_cab_verify` validates
/// a CAB signer at its timestamped signing time: the signing certificate is short-lived -- the
/// current one runs a year -- and a list stays current past its signer's expiry.
pub fn verify_stl(stl_der: &[u8], anchors: &[&[u8]]) -> Result<()> {
    let ci = ContentInfo::from_der(stl_der).context("authroot.stl is not a CMS ContentInfo")?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .context("authroot.stl's content is not a SignedData")?;

    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("the SignedData carries no SignerInfo"))?;
    if signer.digest_alg.oid != ID_SHA_256 {
        return Err(anyhow!(
            "the list is digested with {}; only SHA-256 is supported here",
            signer.digest_alg.oid
        ));
    }

    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("the SignedData carries no encapsulated content"))?;
    let content = encapsulated(econtent)?;

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("the SignerInfo carries no signed attributes"))?;
    // The digest covers the encapsulated content's *value* octets, not its full TLV: the tag and
    // length of the `CertificateTrustList` SEQUENCE are outside it. That is the Authenticode
    // convention, which this publisher follows here too -- `authenticode`'s own
    // `encapsulated_content()` hands `tpm_cab_verify` exactly these bytes -- and it is also what
    // CMS asks for in the conformant shape, where the value octets of the OCTET STRING are the
    // content. So one expression is right for both shapes, and hashing the TLV is right for
    // neither.
    let expected = Sha256::digest(econtent.value());
    let md = signed_attrs
        .iter()
        .find(|a| a.oid == ID_MESSAGE_DIGEST)
        .and_then(|a| a.values.get(0))
        .ok_or_else(|| anyhow!("the signed attributes carry no messageDigest"))?;
    let md = MessageDigest::from_der(&md.to_der()?).context("messageDigest did not decode")?;
    if md.as_bytes() != expected.as_slice() {
        return Err(anyhow!(
            "the signed messageDigest does not match the list it is supposed to cover"
        ));
    }

    let certs: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    CertificateChoices::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let signer_cert = certs
        .iter()
        .find(|c| matches_signer(&signer.sid, c))
        .ok_or_else(|| anyhow!("the signer's certificate is not in the SignedData"))?;

    // Some Microsoft signatures name the key algorithm where the signature algorithm belongs, the
    // same shape `tpm_cab_verify` handles for CAB signers.
    let sig_alg = match signer.signature_algorithm.oid == RSA_ENCRYPTION {
        true => AlgorithmIdentifierOwned {
            oid: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: signer.signature_algorithm.parameters.clone(),
        },
        false => signer.signature_algorithm.clone(),
    };

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.verify_signature_message(
        &pe,
        &signed_attrs.to_der()?,
        signer.signature.as_bytes(),
        &sig_alg,
        signer_cert.tbs_certificate().subject_public_key_info(),
    )
    .map_err(|e| anyhow!("the list signer's signature did not verify: {e:?}"))?;

    let ctl = CertificateTrustList::from_der(&content)
        .context("the encapsulated content is not a CertificateTrustList")?;
    let this_update = match ctl.this_update {
        Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };

    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(this_update)?);
    cps.set_extended_key_usage(vec![EKU_ROOT_LIST_SIGNER.to_string()]);
    cps.set_extended_key_usage_path(true);

    let mut ta_store = TaSource::new();
    for (i, anchor) in anchors.iter().enumerate() {
        ta_store.push(CertFile {
            filename: format!("pinned anchor {i}"),
            bytes: anchor.to_vec(),
        });
    }
    ta_store
        .initialize()
        .map_err(|e| anyhow!("the pinned anchors did not load: {e:?}"))?;
    pe.add_trust_anchor_source(Box::new(ta_store));

    let mut cert_source = CertSource::default();
    for cert in &certs {
        if cert != signer_cert {
            cert_source.push(CertFile {
                filename: "from the signed list".to_string(),
                bytes: cert.to_der()?,
            });
        }
    }
    cert_source
        .initialize(&cps)
        .map_err(|e| anyhow!("the signer's chain did not load: {e:?}"))?;
    cert_source.find_all_partial_paths(&pe, &cps);
    pe.add_certificate_source(Box::new(cert_source));

    let target = PDVCertificate::try_from(signer_cert.to_der()?.as_slice())
        .map_err(|e| anyhow!("the signer's certificate did not decode: {e:?}"))?;
    let mut paths = vec![];
    pe.get_paths_for_target(&target, &mut paths, 0, cps.get_time_of_interest())
        .map_err(|e| anyhow!("no path could be built for the list signer: {e:?}"))?;
    for path in paths {
        let mut results = CertificationPathResults::new();
        if pe.validate_path(&pe, &cps, &path, &mut results).is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!(
        "the list signer does not validate to a pinned anchor as a {EKU_ROOT_LIST_SIGNER} signer"
    ))
}

/// Whether `cert` is the certificate a `SignerIdentifier` names.
fn matches_signer(sid: &SignerIdentifier, cert: &Certificate) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => {
            isn.issuer == *cert.tbs_certificate().issuer()
                && isn.serial_number == *cert.tbs_certificate().serial_number()
        }
        SignerIdentifier::SubjectKeyIdentifier(skid) => cert
            .tbs_certificate()
            .extensions()
            .and_then(|exts| {
                exts.iter()
                    .find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
            })
            .is_some_and(|ext| ext.extn_value.as_bytes() == skid.0.as_bytes()),
    }
}

/// Read a bare `CertificateTrustList`.
pub fn parse_ctl(ctl_der: &[u8]) -> Result<Ctl> {
    let ctl =
        CertificateTrustList::from_der(ctl_der).context("failed to decode CertificateTrustList")?;

    // Every thumbprint comparison below assumes SHA-1 because the list says so. If Microsoft ever
    // moves, the entries stop being addressable the way this adapter addresses them, and a wrong
    // digest would look like 562 certificates that all fail to match.
    if ctl.subject_algorithm.oid != const_oid::db::rfc5912::ID_SHA_1 {
        return Err(anyhow!(
            "the list identifies its subjects with {} rather than SHA-1; the .crt URLs and the \
             thumbprint check in this adapter both assume SHA-1",
            ctl.subject_algorithm.oid
        ));
    }

    let published = match ctl.this_update {
        Time::UtcTime(t) => t.to_date_time(),
        Time::GeneralTime(t) => t.to_date_time(),
    };
    let published = format!(
        "{:04}-{:02}-{:02}",
        published.year(),
        published.month(),
        published.day()
    );

    let sequence_number = ctl
        .sequence_number
        .as_ref()
        .map(|n| n.as_bytes().iter().map(|b| format!("{b:02X}")).collect());

    let mut entries = vec![];
    for subject in ctl.trusted_subjects.unwrap_or_default() {
        let thumbprint = subject.subject_identifier.as_bytes().to_vec();
        let mut ekus = vec![];
        let mut friendly_name = None;
        let mut disallowed_after = None;
        for attr in subject
            .subject_attributes
            .map(|s| s.into_vec())
            .unwrap_or_default()
        {
            // An unreadable property is skipped rather than failing the list: Microsoft carries
            // more of them than this adapter names, and a new one must not cost the whole program.
            if attr.oid == ATTR_EKU {
                // Doubly wrapped, measured on the published list: the attribute value is an OCTET
                // STRING whose contents are a SEQUENCE OF OID. Reading it as the sequence directly
                // yields no purposes for any root, which is the empty-store failure `build` guards.
                if let Some(v) = attr.values.iter().next() {
                    if let Ok(wrapped) = v.decode_as::<OctetString>() {
                        if let Ok(list) = Vec::<ObjectIdentifier>::from_der(wrapped.as_bytes()) {
                            ekus = list;
                        }
                    }
                }
            } else if attr.oid == ATTR_FRIENDLY_NAME {
                if let Some(v) = attr.values.iter().next() {
                    if let Ok(s) = v.decode_as::<OctetString>() {
                        friendly_name = utf16le(s.as_bytes());
                    }
                }
            } else if attr.oid == ATTR_DISALLOWED_AFTER {
                if let Some(v) = attr.values.iter().next() {
                    if let Ok(s) = v.decode_as::<OctetString>() {
                        disallowed_after = filetime_to_unix(s.as_bytes());
                    }
                }
            }
        }
        entries.push(Entry {
            thumbprint,
            ekus,
            friendly_name,
            disallowed_after,
        });
    }

    Ok(Ctl {
        published,
        sequence_number,
        entries,
    })
}

/// A Windows `FILETIME` -- 100-nanosecond ticks since 1601 -- as Unix seconds. `None` for a zero
/// value, which the list uses to mean "no date", and for anything that is not eight bytes.
fn filetime_to_unix(bytes: &[u8]) -> Option<u64> {
    let ticks = u64::from_le_bytes(bytes.try_into().ok()?);
    if ticks == 0 {
        return None;
    }
    (ticks / 10_000_000).checked_sub(FILETIME_TO_UNIX)
}

/// Microsoft writes friendly names as UTF-16LE with a trailing NUL. Returns `None` rather than
/// lossy text, since the name is decoration and a mangled one is worse than none.
fn utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16(&units).ok()
}

/// What a caller wants out of the program.
pub struct Options {
    /// Keep only roots Microsoft grants this purpose. `None` takes every root the program still
    /// trusts -- which is not every root it lists.
    pub eku: Option<ObjectIdentifier>,
    /// Seconds since the epoch. Both exclusions are relative to it, so a generation is a statement
    /// about a moment, which is what `StoreEntry::collected` then records.
    pub now_unix: u64,
}

/// Build the store inputs from a list and the certificates fetched for it.
///
/// `fetched` is keyed by the same thumbprint the entry carries. Each certificate is admitted only
/// if its SHA-1 matches that key, which is the check the whole pipeline rests on: the list is
/// signed, the certificates are not.
///
/// Returns the inputs plus the entries that produced nothing, so a caller can report a short
/// collection rather than quietly shipping one.
pub fn build(
    ctl: &Ctl,
    fetched: &[(Vec<u8>, Vec<u8>)],
    opts: &Options,
) -> Result<(StoreInputs, Vec<String>)> {
    let mut inputs = StoreInputs {
        published: Some(ctl.published.clone()),
        ..Default::default()
    };
    let mut missing = vec![];
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();

    for entry in &ctl.entries {
        if let Some(eku) = opts.eku {
            if !entry.grants(eku) {
                continue;
            }
        }
        let Some((_, der)) = fetched.iter().find(|(tp, _)| *tp == entry.thumbprint) else {
            missing.push(format!("{} (not fetched)", entry.hex()));
            continue;
        };

        let digest = Sha1::digest(der).to_vec();
        if digest != entry.thumbprint {
            // Served bytes that are not what the signed list asked for. Never admitted, and worth
            // saying loudly: it is either a corrupted transfer or a substitution.
            missing.push(format!(
                "{} (served a certificate whose SHA-1 is {})",
                entry.hex(),
                digest
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<String>()
            ));
            continue;
        }

        let cert = match Certificate::from_der(der) {
            Ok(c) => c,
            Err(e) => {
                missing.push(format!("{} (not a certificate: {e})", entry.hex()));
                continue;
            }
        };
        // Expired, and restricted, are dropped alike. Neither is a removal by the publisher, and
        // both would otherwise accumulate: a root that expires is never mentioned again, and a
        // root that is retired stays in the list indefinitely carrying the date it stopped being
        // trustworthy. A consumer verifying an old signature under a since-retired root needs the
        // opposite of this, and would need an environment of its own.
        let not_after = cert
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs();
        if not_after < opts.now_unix {
            continue;
        }
        if entry.disallowed_after.is_some_and(|t| t < opts.now_unix) {
            continue;
        }
        // Said out loud rather than dropped quietly: this one is the publisher offering something
        // this consumer cannot use, which is worth a line in a refresh log, unlike an expiry.
        let sig_alg = cert.signature_algorithm().oid;
        if UNVERIFIABLE_SIGNATURE_ALGORITHMS.contains(&sig_alg) {
            log::info!(
                "{} is signed with {sig_alg}, which certval cannot verify; not carried",
                entry.hex()
            );
            continue;
        }
        if !seen.insert(der.clone()) {
            continue;
        }

        let name = entry
            .friendly_name
            .clone()
            .unwrap_or_else(|| entry.hex())
            .replace(['/', '\\', ':'], "_");
        inputs.trust_anchors.push(CertFile {
            filename: format!("{name}.der"),
            bytes: der.clone(),
        });
    }

    // An EKU-filtered environment that matched nothing, from a list that does carry entries, is
    // the failure this adapter is most likely to have: the purposes are read from a Microsoft
    // property OID, and a property this does not recognize is skipped rather than reported, so a
    // renamed or misidentified one leaves every entry granting nothing. That reads as "Microsoft
    // trusts no root for this purpose", which is never true -- and it would ship as an empty
    // store rather than as an error.
    if opts.eku.is_some() && inputs.trust_anchors.is_empty() && !ctl.entries.is_empty() {
        return Err(anyhow!(
            "no root in a list of {} grants {}; the per-entry purposes are read from {ATTR_EKU}, \
             so check that property before believing this",
            ctl.entries.len(),
            opts.eku.unwrap_or(EKU_SERVER_AUTH)
        ));
    }

    Ok((inputs, missing))
}

/// Fetch the cabinet, verify it, and read the list out of it.
#[cfg(all(feature = "fetch", feature = "cab"))]
pub fn fetch_ctl() -> Result<Ctl> {
    let cab = crate::refresh::fetch(CAB_URL).map_err(|e| anyhow!("{CAB_URL}: {e}"))?;
    let members = crate::cab::open_verified(&cab)?;
    let stl = members
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case(STL_MEMBER))
        .ok_or_else(|| anyhow!("{CAB_URL} holds no {STL_MEMBER}"))?;
    parse_stl(&stl.bytes)
}

/// What a fetch of the whole program came back with: each certificate paired with the thumbprint
/// that asked for it, then the URLs the publisher answered 4xx for, then the ones that gave no
/// answer at all. The last two are kept apart because only the first is a statement about the
/// program.
#[cfg(feature = "fetch")]
pub type Fetched = (Vec<(Vec<u8>, Vec<u8>)>, Vec<String>, Vec<String>);

/// Fetch one certificate per entry.
///
/// Returns what arrived, plus the URLs that gave nothing. A 4xx is the publisher's answer about
/// that thumbprint and is reported separately from an unreachable host, for the reason
/// [`crate::crawl`] draws the same distinction: one is a fact about the program, the other is a
/// fact about this machine's morning.
#[cfg(feature = "fetch")]
pub fn fetch_certificates(entries: &[Entry]) -> Fetched {
    /// Passes over what is still unreachable, after the first. A whole program is fetched
    /// all-or-nothing, so one flaky response in five hundred would otherwise discard every good
    /// one -- which is what happened on the first real run, 550 of 562 thrown away over 12.
    const RETRIES: usize = 3;
    /// Grows with each pass. Short, because this is a CDN having a moment, not a server asking to
    /// be left alone.
    const BACKOFF: Duration = Duration::from_secs(2);

    let mut out = vec![];
    let mut absent = vec![];
    let mut pending: Vec<&Entry> = entries.iter().collect();

    for attempt in 0..=RETRIES {
        if attempt > 0 {
            log::info!(
                "retrying {} certificate(s) that gave no answer (attempt {attempt} of {RETRIES})",
                pending.len()
            );
            std::thread::sleep(BACKOFF * attempt as u32);
        }
        let mut again = vec![];
        for entry in pending {
            match crate::refresh::fetch(&entry.url()) {
                Ok(der) => out.push((entry.thumbprint.clone(), der)),
                // A 4xx is the publisher's own answer about that thumbprint, so it is never
                // retried: asking again cannot change it, and doing so would turn one missing
                // certificate into four requests.
                Err(crate::refresh::FetchError::Absent(why)) => absent.push(why),
                Err(crate::refresh::FetchError::Unreachable(_)) => again.push(entry),
            }
        }
        pending = again;
        if pending.is_empty() {
            break;
        }
    }

    // Whatever is still pending gave no answer across every attempt. Re-fetched once more only to
    // report why, since the reason from the last attempt is the one worth showing.
    let unreachable = pending
        .into_iter()
        .map(|entry| match crate::refresh::fetch(&entry.url()) {
            Err(e) => e.to_string(),
            Ok(_) => format!("{} answered on a later attempt", entry.url()),
        })
        .collect();

    (out, absent, unreachable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thumbprint_is_uppercase_hex_and_names_its_url() {
        let e = Entry {
            thumbprint: vec![0xcd, 0xd4, 0xee, 0xae],
            ekus: vec![EKU_SERVER_AUTH],
            friendly_name: None,
            disallowed_after: None,
        };
        assert_eq!(e.hex(), "CDD4EEAE");
        assert!(e.url().ends_with("/CDD4EEAE.crt"));
        assert!(e.grants(EKU_SERVER_AUTH));
        assert!(!e.grants(EKU_EMAIL_PROTECTION));
    }

    /// The name is decoration; mangled text would travel into file names and a store's labels.
    #[test]
    fn a_friendly_name_is_utf16le_and_stops_at_the_nul() {
        let bytes = b"M\x00S\x00\x00\x00";
        assert_eq!(utf16le(bytes).as_deref(), Some("MS"));
        assert_eq!(utf16le(b"\x01").as_deref(), None);
    }

    /// The check the pipeline rests on: bytes that do not hash to the entry are never admitted.
    #[test]
    fn a_certificate_that_does_not_match_its_thumbprint_is_refused() {
        let ctl = Ctl {
            published: "2026-09-21".to_string(),
            sequence_number: None,
            entries: vec![Entry {
                thumbprint: vec![0u8; 20],
                ekus: vec![],
                friendly_name: Some("not what was asked for".to_string()),
                disallowed_after: None,
            }],
        };
        let fetched = vec![(vec![0u8; 20], b"not a certificate either".to_vec())];
        let (inputs, missing) = build(
            &ctl,
            &fetched,
            &Options {
                eku: None,
                now_unix: 0,
            },
        )
        .unwrap();
        assert!(inputs.trust_anchors.is_empty());
        assert_eq!(missing.len(), 1);
        assert!(missing[0].contains("SHA-1"));
    }

    /// A Windows FILETIME, and the two shapes the list uses for "no date".
    #[test]
    fn a_filetime_becomes_unix_seconds() {
        // 2016-04-19T00:00:00Z, the SHA-1 deprecation cohort's date.
        let ticks: u64 = (1_461_024_000 + FILETIME_TO_UNIX) * 10_000_000;
        assert_eq!(filetime_to_unix(&ticks.to_le_bytes()), Some(1_461_024_000));
        assert_eq!(filetime_to_unix(&0u64.to_le_bytes()), None);
        assert_eq!(filetime_to_unix(&[0, 1, 2]), None);
    }

    #[test]
    fn something_that_is_not_a_signed_list_is_refused() {
        assert!(parse_stl(b"not a ContentInfo").is_err());
        assert!(parse_ctl(b"not a CTL").is_err());
    }
}

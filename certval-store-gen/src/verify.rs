//! Signature verification for the CMS `SignedData` wrapping each TAMP message.
//!
//! An InstallRoot stream is an RFC 4073 content collection whose members are signed, and every
//! caller that reads material out of one checks those signatures first: [`stream`] on its own,
//! and `adapters::tamp::build` as part of the parse, which refuses a stream any of whose members
//! fails.
//!
//! Three questions, all answered. [`verify_member_signature`] asks whether the bytes are
//! internally consistent -- signed by a key whose certificate travels with them.
//! [`crate::timestamp::verified_gen_time`] asks when that signature demonstrably existed, from a
//! timestamp it verifies before believing. `chain_signer` asks whether the signing key is one to
//! trust, by chaining it under the code-signing EKU to the `INSTALLROOT_ANCHORS` pinned in this
//! module and never taken from the stream, as of the time the timestamp established.
//! [`verify_member`] is all three, and is what callers should use.

use anyhow::{anyhow, Context, Result};

use cms::signed_data::{CertificateSet, SignerIdentifier, SignerInfo};
use const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
use const_oid::db::rfc5912::{ID_CE_SUBJECT_KEY_IDENTIFIER, ID_KP_CODE_SIGNING};
use const_oid::db::rfc5912::{
    ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, spki::AlgorithmIdentifierOwned, Certificate};

use certval::{
    check_revocation_local, parse_cert, CertFile, CertSource, CertVector, CertificationPath,
    CertificationPathResults, CertificationPathSettings, ObjectIdentifierSet, PkiEnvironment,
    TaSource, TimeOfInterest,
};
use rfc5934::signed::{RevocationInfo, SignedData};
use rfc5934::ContentCollection;

/// The anchors an InstallRoot stream's signature is chained to.
///
/// Pinned in the generator rather than taken from the crate being generated, because the anchor
/// set is a property of InstallRoot as a *publication channel* and does not vary with the payload:
/// DISA signs DoD, ECA, JITC and WCF from one code-signing population, so `ECA.ir4` is signed by a
/// certificate chaining to a DoD root that `certval_stores_eca` has no reason to publish.
///
/// All four current DoD roots, not only the one today's signer happens to chain through. The DoD
/// profile authorizes *any* code-signing certificate that chains to a DoD root, so pinning one
/// would encode an accident of the present signer rather than the rule. Adjust the list up or down
/// as DoD's root set moves.
///
/// Never the stream's own `Root` message, which would let a stream authorize its own replacement.
/// Changing this list is a deliberate human act, and that is the point.
pub(crate) static INSTALLROOT_ANCHORS: &[&[u8]] = &[
    include_bytes!("../anchors/DoD_Root_CA_3.der"),
    include_bytes!("../anchors/DoD_Root_CA_4.der"),
    include_bytes!("../anchors/DoD_Root_CA_5.der"),
    include_bytes!("../anchors/DoD_Root_CA_6.der"),
];

/// Chain a verified signer to one of the pinned `INSTALLROOT_ANCHORS` under the code-signing EKU.
///
/// The intermediates come from the stream's own `certificates` field, which is sound because the
/// anchor does not: a chain is only as good as what terminates it, and that is pinned. This is
/// what turns "the bytes are internally consistent" into "DISA published these bytes".
///
/// `toi` is the time the stream's own verified timestamp established, so the signer is validated as
/// of when its signature demonstrably existed rather than as of now: a stream stays published long
/// after the certificate that signed it expires -- `JITC.ir4` is timestamped 2025-02-03 -- and an
/// expired signer means the material is old, not that it is forged. Whether a stream is *current*
/// is a different question, answered by the publication-date comparison in [`crate::refresh`].
///
/// `stapled` is the revocation information the stream carries, and the reason the time of interest
/// matters twice: DISA staples OCSP responses produced within days of signing, so they answer as of
/// the timestamp and are long stale as of now. Requiring a determined status is what makes that
/// stapled data do work -- without it a revoked signer would pass, and the responses DISA takes the
/// trouble to publish would be bytes nobody reads.
fn chain_signer(
    signer: &Certificate,
    carried: Option<&CertificateSet>,
    stapled: &[Vec<u8>],
    toi: TimeOfInterest,
) -> Result<()> {
    chain_to(
        signer,
        carried,
        ChainCheck {
            anchors: INSTALLROOT_ANCHORS,
            eku: ID_KP_CODE_SIGNING,
            // Not required across the path: DoD's code-signing issuers do not all assert the EKU,
            // and demanding it of them would refuse streams DISA in fact publishes. The timestamp
            // chain, whose issuers do assert it, is held to the stricter rule.
            eku_across_path: false,
            toi,
            stapled,
            require_revocation: true,
            // Never fetched, whatever the caller's policy. This chain is validated as of the
            // timestamp, and a response fetched today is about today: certval would refuse it as
            // produced after the time of interest, which is correct and useless. Only what DISA
            // stapled can answer as of when DISA signed.
            fetch_missing: false,
            what: "the stream's signer",
        },
    )
}

/// How far a verification may go to settle a revocation status.
///
/// The distinction is not how much rigour is wanted -- both settle everything they can -- but
/// whether *this* caller is one that may reach the network. A stream carries the status of its own
/// signing chain and nothing else, so the timestamp authority's chain is the one that needs a
/// responder asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// Only what the stream staples, which settles its signer's chain and not the timestamp
    /// authority's.
    ///
    /// For the regeneration check a provider crate runs in its own tests: it compares the
    /// committed store against what the committed stream generates, and a test that depends on a
    /// responder being up is a test nobody trusts. This is that policy stated rather than left as
    /// an omission. The stream is still refused if what it staples fails or is missing, and the
    /// gate that does ask a responder runs upstream, on these same committed bytes.
    Stapled,
    /// What the stream staples, plus what certval fetches for the chain nothing staples.
    ///
    /// For `verify --stream`, for generation, and for a source checkout refreshing its inputs --
    /// callers already reaching the network, where refusing to ask is the only way to fail.
    StapledAndFetched,
}

impl Revocation {
    /// Whether a chain with nothing stapled for it may have its status fetched.
    pub(crate) fn fetches(&self) -> bool {
        matches!(self, Revocation::StapledAndFetched)
    }
}

/// What one chain check is: where it terminates, what it must be good for, and when.
///
/// A struct rather than seven positional arguments because the two chains a stream needs differ in
/// every one of these fields, and `chain_to(&signer, carried, ANCHORS, OID, toi, false, true, "…")`
/// says nothing at a call site about which `bool` is which.
pub(crate) struct ChainCheck<'a> {
    /// Where the chain must terminate. Pinned in this crate, never taken from the stream.
    pub anchors: &'a [&'a [u8]],
    /// The extended key usage the signer must be good for.
    pub eku: ObjectIdentifier,
    /// Whether that EKU is required of every certificate in the path, not only the signer.
    pub eku_across_path: bool,
    /// The time to validate as of.
    pub toi: TimeOfInterest,
    /// OCSP responses to file against the certificates they answer about, DER, from whatever
    /// carried the signature. Empty where nothing was supplied.
    pub stapled: &'a [Vec<u8>],
    /// Whether every certificate's revocation status must be *determined* for the chain to pass.
    ///
    /// With `stapled` as the only source, "determined" means the supplied responses answer about
    /// every position and are current as of [`toi`](Self::toi). That is the check that makes the
    /// stapled data load-bearing rather than decoration.
    pub require_revocation: bool,
    /// Whether certval may fetch what is not stapled, from the URIs the certificates name.
    ///
    /// certval's own ladder does the fetching -- `check_revocation` rather than
    /// `check_revocation_local` -- so what asks a responder here is the same code that asks one in
    /// pittv3, rather than a second client assembled beside it.
    pub fetch_missing: bool,
    /// Names the subject in an error: "chains to none of the pinned anchors" is useless without it.
    pub what: &'a str,
}

/// Build and validate a path from `signer` to one of the check's anchors.
///
/// Shared by the two chains a stream needs -- its signer to a pinned DoD root, and its timestamp
/// authority to a pinned Sectigo root.
///
/// The intermediates come from the `certificates` field of whatever carried the signature. That is
/// sound for the same reason in both cases: the anchor comes from this crate, and a chain is only
/// as good as what terminates it.
pub(crate) fn chain_to(
    signer: &Certificate,
    carried: Option<&CertificateSet>,
    check: ChainCheck<'_>,
) -> Result<()> {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(check.toi);
    let mut ekus = ObjectIdentifierSet::new();
    ekus.insert(check.eku);
    cps.set_extended_key_usage_from_oid_set(ekus);
    cps.set_extended_key_usage_path(check.eku_across_path);
    cps.set_check_revocation_status(check.require_revocation);

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut tas = TaSource::new();
    for (i, der) in check.anchors.iter().enumerate() {
        tas.push(CertFile {
            filename: format!("pinned anchor {i}"),
            bytes: der.to_vec(),
        });
    }
    tas.initialize()
        .map_err(|e| anyhow!("the pinned anchors did not load: {e:?}"))?;
    pe.add_trust_anchor_source(Box::new(tas));

    let mut cas = CertSource::new();
    for (i, cert) in carried.into_iter().flat_map(|c| c.0.iter()).enumerate() {
        let der = cert
            .to_der()
            .context("a certificate carried alongside the signature does not re-encode")?;
        cas.push(CertFile {
            filename: format!("carried certificate {i}"),
            bytes: der,
        });
    }
    cas.initialize(&cps).map_err(|e| {
        anyhow!("the certificates carried alongside the signature did not load: {e:?}")
    })?;
    cas.find_all_partial_paths(&pe, &cps);
    pe.add_certificate_source(Box::new(cas));

    let der = signer
        .to_der()
        .with_context(|| format!("{}'s certificate does not re-encode", check.what))?;
    let target = parse_cert(&der, "signer")
        .map_err(|e| anyhow!("{}'s certificate does not parse: {e:?}", check.what))?;

    let mut paths = vec![];
    pe.get_paths_for_target(&target, &mut paths, 0, cps.get_time_of_interest())
        .map_err(|e| anyhow!("building a path for {} failed: {e:?}", check.what))?;
    if paths.is_empty() {
        return Err(anyhow!(
            "{} chains to none of the {} pinned anchors",
            check.what,
            check.anchors.len()
        ));
    }

    let mut last = None;
    for path in paths.iter_mut() {
        let mut results = CertificationPathResults::new();
        if let Err(e) = pe.validate_path(&pe, &cps, path, &mut results) {
            last = Some(format!("{e:?}"));
            continue;
        }
        if !check.require_revocation {
            return Ok(());
        }
        // Stapled onto the path rather than registered with the environment: certval files
        // revocation data per position, and a response is about one certificate.
        let filed = staple_ocsp(path, check.stapled)?;
        // Either half of certval's own ladder: `check_revocation` walks cache, no-check extension,
        // stapled data, CRL sources and then the responders and CRL DPs the certificates name;
        // `check_revocation_local` stops before the fetching. It is async, and this is a build
        // script and a CLI, so a current-thread runtime drives it.
        let determined = match check.fetch_missing {
            true => runtime().and_then(|rt| {
                rt.block_on(certval::check_revocation(&pe, &cps, path, &mut results))
                    .map_err(|e| anyhow!("{e:?}"))
            }),
            false => {
                check_revocation_local(&pe, &cps, path, &mut results).map_err(|e| anyhow!("{e:?}"))
            }
        };
        match determined {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(format!(
                    "{e} (with {filed} of {} stapled response(s) filed against this path)",
                    check.stapled.len()
                ))
            }
        }
    }
    Err(anyhow!(
        "{} builds {} path(s) to a pinned anchor but none is good for {}: {}",
        check.what,
        paths.len(),
        check.eku,
        last.unwrap_or_else(|| "no reason recorded".to_string())
    ))
}

/// The runtime certval's asynchronous revocation checking is driven on.
///
/// Current-thread and built where it is needed rather than kept: a verification asks a responder
/// once or twice, and a runtime held for the life of a build script would outlive every use of it.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("a runtime for certval's revocation checking could not be started")
}

/// File each stapled OCSP response against the certificate on `path` it answers about.
///
/// Returns how many were filed, which is what an error message needs: "undetermined with 0 of 2
/// filed" is a matching problem and "undetermined with 2 of 2 filed" is a stale-data problem, and
/// they send a reader to different places.
///
/// The match is by `CertID`, and the request certval itself would send is what supplies the
/// comparison -- `build_ocsp_request` hashes the issuer name and key the way certval does, so this
/// is certval's own notion of identity rather than a second one invented here. DoD's responses key
/// on SHA-1, which is what RFC 6960 specifies by default and what certval builds.
fn staple_ocsp(path: &mut CertificationPath, stapled: &[Vec<u8>]) -> Result<usize> {
    if stapled.is_empty() {
        return Ok(0);
    }
    // The positions certval files revocation data for: the intermediates in order, then the
    // target, each paired with the certificate that issued it.
    let mut wanted: Vec<Option<Vec<u8>>> = vec![];
    for i in 0..path.intermediates.len() + 1 {
        let cert = match path.intermediates.get(i) {
            Some(intermediate) => intermediate.decoded(),
            None => path.target.decoded(),
        };
        let req = match i {
            0 => certval::build_ocsp_request(cert, &path.trust_anchor.decoded_ta, None),
            _ => certval::build_ocsp_request(cert, path.intermediates[i - 1].decoded(), None),
        };
        // A position whose request cannot be built cannot be matched, and that is not an error
        // here: it leaves the slot empty, and `check_revocation_local` reports the position as
        // undetermined with the rest.
        wanted.push(req.ok().and_then(|der| requested_cert_id(&der)));
    }

    let mut filed = 0;
    for response in stapled {
        for answered in answered_cert_ids(response) {
            for (i, want) in wanted.iter().enumerate() {
                if want.as_deref() == Some(answered.as_slice()) && path.ocsp_responses[i].is_none()
                {
                    path.ocsp_responses[i] = Some(response.clone());
                    filed += 1;
                }
            }
        }
    }
    Ok(filed)
}

/// The encoded `CertID` out of an OCSP request certval built.
///
/// Encoded rather than structural: a `CertID` is a hash algorithm, two hashes and a serial, and
/// comparing the encodings compares all four at once without this having to decide which
/// differences matter.
fn requested_cert_id(request: &[u8]) -> Option<Vec<u8>> {
    // Decoded under `Raw`, because `build_ocsp_request` encodes under `Raw`: the Rfc5280 profile
    // constrains serial-number length in a way that would silently drop a certificate whose serial
    // is longer than the RFC allows -- and such certificates are in service.
    let request = x509_ocsp::OcspRequest::<x509_cert::certificate::Raw>::from_der(request).ok()?;
    let first = request.tbs_request.request_list.first()?;
    first.req_cert.to_der().ok()
}

/// The encoded `CertID`s an OCSP response answers about.
fn answered_cert_ids(response: &[u8]) -> Vec<Vec<u8>> {
    let Ok(response) = x509_ocsp::OcspResponse::from_der(response) else {
        return vec![];
    };
    let Some(bytes) = response.response_bytes else {
        return vec![];
    };
    let Ok(basic) = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
        return vec![];
    };
    basic
        .tbs_response_data
        .responses
        .iter()
        .filter_map(|single| single.cert_id.to_der().ok())
        .collect()
}

/// One member, verified: who signed it and when, both established rather than assumed.
#[derive(Clone, Debug)]
pub struct VerifiedMember {
    /// The certificate whose key made the signature, from the stream's own `certificates`.
    pub signer: Certificate,
    /// `TSTInfo.genTime` from the member's verified timestamp, and the time its signer was
    /// validated at. [`None`] for a member carrying no timestamp at all -- which no published
    /// stream does, but nothing in RFC 5934 forbids.
    pub timestamped_at: Option<TimeOfInterest>,
}

/// Verify one member fully: its signature, its timestamp, and its signer's chain to a pinned
/// anchor as of the time that timestamp establishes.
///
/// The entry point every caller that reads material out of a stream should use.
/// [`verify_member_signature`] stops at internal consistency and is kept separate only because
/// the questions are genuinely different; answering just the first is not enough to act on.
pub fn verify_member(
    pe: &PkiEnvironment,
    sd: &SignedData,
    revocation: Revocation,
) -> Result<VerifiedMember> {
    let signer = verify_member_signature(pe, sd)?;
    let stapled = stapled_ocsp(sd)?;
    let timestamped_at =
        crate::timestamp::verified_gen_time(pe, sole_signer_info(sd)?, revocation)?;
    let toi = match timestamped_at {
        Some(toi) => toi,
        None => {
            log::warn!(
                "a member carries no RFC 3161 timestamp, so its signer's validity cannot be \
                 checked at the time it signed and is not checked at all"
            );
            TimeOfInterest::disabled()
        }
    };
    chain_signer(&signer, sd.certificates.as_ref(), &stapled, toi)?;
    Ok(VerifiedMember {
        signer,
        timestamped_at,
    })
}

/// The OCSP responses a member staples, as DER.
///
/// A stream carries the status of its own signing chain, which is what lets an offline verifier
/// answer a question it could otherwise only answer over the network -- and lets it answer as of
/// the timestamp, which is when those responses were current.
///
/// A member that staples nothing is refused rather than validated without revocation: every member
/// of every published stream carries two responses, so an absence is a stream unlike any DISA has
/// published, and the quiet reading of it would be a signer whose revocation went unchecked.
/// Revocation information in the conformant `RevocationInfoChoice` shape -- CRLs -- is refused for
/// the same reason: it is not what is consumed here, and treating an unread field as nothing to
/// check is how a check stops being one.
fn stapled_ocsp(sd: &SignedData) -> Result<Vec<Vec<u8>>> {
    let info = sd
        .revocation_info()
        .map_err(|e| anyhow!("a member's revocation information does not decode: {e}"))?;
    match info {
        Some(RevocationInfo::BareOcspResponses(responses)) => responses
            .iter()
            .map(|r| {
                r.to_der()
                    .context("a stapled OCSP response does not re-encode")
            })
            .collect(),
        Some(RevocationInfo::Conformant(_)) => Err(anyhow!(
            "a member staples revocation information as CRLs, which this does not consume; its \
             signer's revocation status would go unchecked"
        )),
        None => Err(anyhow!(
            "a member staples no revocation information, so its signer's revocation status cannot \
             be determined without the network"
        )),
    }
}

/// Verify every member of a stream, returning what each member established.
///
/// Population-independent, and deliberately so: a signature covers one member, and which of the
/// PKIs a stream carries you would go on to generate from has no bearing on whether the bytes
/// are authentic. That makes this the right check to gate a *repository* on -- it answers
/// "may this file be committed", not "can this environment be built" -- and it needs no
/// network, since both the signer's certificate and the timestamp travel inside the stream.
pub fn stream(
    pe: &PkiEnvironment,
    ir4: &[u8],
    revocation: Revocation,
) -> Result<Vec<VerifiedMember>> {
    let collection = ContentCollection::from_der(ir4)
        .context("the stream is not an RFC 4073 content collection")?;

    let mut verified: Vec<VerifiedMember> = vec![];
    let mut failures: Vec<String> = vec![];
    for (i, ci) in collection.0.iter().enumerate() {
        let sd: SignedData = ci
            .content
            .decode_as()
            .with_context(|| format!("member {i} is not a SignedData"))?;
        match verify_member(pe, &sd, revocation) {
            Ok(member) => verified.push(member),
            Err(e) => failures.push(format!("member {i}: {e}")),
        }
    }

    if !failures.is_empty() {
        return Err(anyhow!(
            "{} of {} members failed verification: {}",
            failures.len(),
            collection.0.len(),
            failures.join("; ")
        ));
    }
    Ok(verified)
}

/// The distinct signers of a verified stream, by leaf RDN, in the order first seen.
pub fn signer_names(members: &[VerifiedMember]) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    for member in members {
        let name = certval::get_leaf_rdn(member.signer.tbs_certificate().subject());
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Verify the signature on one collection member, returning the certificate that made it.
///
/// What is checked, in the order a failure is most likely:
///
/// 1. There is exactly one `SignerInfo`. A stream with several signers is a shape nobody
///    has published and guessing which one matters would be worse than refusing.
/// 2. Signed attributes are present, and the `messageDigest` attribute equals the digest of
///    the encapsulated content, under the digest algorithm the `SignerInfo` declares. Without
///    this the signature covers the attributes but says nothing about the TAMP message they
///    accompany.
/// 3. The signature verifies over the DER-encoded signed attributes, under the public key of
///    the signer's certificate taken from the stream's own `certificates` field.
pub fn verify_member_signature(pe: &PkiEnvironment, sd: &SignedData) -> Result<Certificate> {
    verify_signed_data(pe, sd, "a stream member")
}

/// The sole `SignerInfo` of a `SignedData`.
///
/// A stream member with several signers is a shape nobody has published, and guessing which one
/// matters would be worse than refusing. The same holds of a timestamp token.
fn sole_signer_info(sd: &SignedData) -> Result<&SignerInfo> {
    let signers: Vec<&SignerInfo> = sd.signer_infos.0.iter().collect();
    let [signer] = signers[..] else {
        return Err(anyhow!(
            "expected exactly one SignerInfo, found {}",
            signers.len()
        ));
    };
    Ok(signer)
}

/// [`verify_member_signature`] over any CMS `SignedData`, `what` naming it in errors.
///
/// Also used for a timestamp token, which is a `SignedData` needing exactly these checks: the
/// content it encapsulates is digested into a `messageDigest` attribute and the signature is over
/// the attributes, whether that content is a TAMP message or a `TSTInfo`.
pub(crate) fn verify_signed_data(
    pe: &PkiEnvironment,
    sd: &SignedData,
    what: &str,
) -> Result<Certificate> {
    let signer = sole_signer_info(sd)?;

    let content = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("{what} carries no encapsulated content to sign"))?;
    // The digest is over the content octets, not over the tag and length that wrap them.
    //
    // The whole SHA-2 family, because two publishers in one stream do not agree: DISA signs its
    // TAMP messages with SHA-256 and the timestamp authority signs its tokens with SHA-384.
    let digest: Vec<u8> = match signer.digest_alg.oid {
        ID_SHA_256 => Sha256::digest(content.value()).to_vec(),
        ID_SHA_384 => Sha384::digest(content.value()).to_vec(),
        ID_SHA_512 => Sha512::digest(content.value()).to_vec(),
        other => {
            return Err(anyhow!(
                "unsupported digest algorithm {other} on {what}; SHA-256, SHA-384 and SHA-512 are \
                 implemented"
            ))
        }
    };

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("{what} has no signed attributes"))?;
    check_message_digest(&digest, signer, what)?;

    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow!("{what} carries no certificates, so its signer is unknown"))?;
    let signer_cert = find_signer(&signer.sid, certs).ok_or_else(|| {
        let form = match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(isn) => {
                format!("issuer and serial ({}, {})", isn.issuer, isn.serial_number)
            }
            SignerIdentifier::SubjectKeyIdentifier(_) => "subject key identifier".to_string(),
        };
        anyhow!(
            "the certificate of {what}'s signer is not among the {} carried with it; it is named \
             by {form}",
            certs.0.len()
        )
    })?;

    // Signed attributes are signed as a DER SET OF, not with the [0] IMPLICIT tag they carry
    // inside the SignerInfo. `to_der` on the SignedAttributes type produces the former.
    let enc_signed_attrs = signed_attrs
        .to_der()
        .context("failed to re-encode the signed attributes for verification")?;

    // Some publishers name the bare key algorithm where the signature algorithm belongs -- both
    // DISA and its timestamp authority do. Pair it with the digest the SignerInfo declares rather
    // than refusing a stream over a convention nothing in CMS forbids.
    let sig_alg = if signer.signature_algorithm.oid == RSA_ENCRYPTION {
        let oid = match signer.digest_alg.oid {
            ID_SHA_384 => SHA_384_WITH_RSA_ENCRYPTION,
            ID_SHA_512 => SHA_512_WITH_RSA_ENCRYPTION,
            _ => SHA_256_WITH_RSA_ENCRYPTION,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: signer.signature_algorithm.parameters.clone(),
        }
    } else {
        signer.signature_algorithm.clone()
    };

    pe.verify_signature_message(
        pe,
        &enc_signed_attrs,
        signer.signature.as_bytes(),
        &sig_alg,
        signer_cert.tbs_certificate().subject_public_key_info(),
    )
    .map_err(|e| anyhow!("the signature on {what} does not verify: {e:?}"))?;

    Ok(signer_cert)
}

/// Confirm the `messageDigest` signed attribute equals the digest of the content.
fn check_message_digest(digest: &[u8], signer: &SignerInfo, what: &str) -> Result<()> {
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("{what} has no signed attributes"))?;
    let attr = attrs
        .iter()
        .find(|a| a.oid == ID_MESSAGE_DIGEST)
        .ok_or_else(|| anyhow!("{what}'s signed attributes carry no messageDigest"))?;
    let value = attr
        .values
        .get(0)
        .ok_or_else(|| anyhow!("the messageDigest attribute is empty"))?;
    let stated = der::asn1::OctetString::from_der(&value.to_der()?)
        .context("the messageDigest attribute is not an OCTET STRING")?;
    if stated.as_bytes() != digest {
        return Err(anyhow!(
            "{what}'s messageDigest attribute does not match the encapsulated content, so the \
             signature does not cover the content it accompanies"
        ));
    }
    Ok(())
}

/// The value of a certificate's `subjectKeyIdentifier` extension, if it carries one.
fn skid_of(cert: &Certificate) -> Option<Vec<u8>> {
    let tbs = cert.tbs_certificate();
    // Bound to a local: `extensions()` hands back an owned Option, so borrowing through it
    // in one expression borrows a temporary.
    let exts = tbs.extensions();
    let exts = exts.as_ref()?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)?;
    let skid = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(skid.0.as_bytes().to_vec())
}

/// Find the signer's certificate in the set the stream carries.
fn find_signer(
    sid: &SignerIdentifier,
    certs: &cms::signed_data::CertificateSet,
) -> Option<Certificate> {
    certs.0.iter().find_map(|c| {
        let cms::cert::CertificateChoices::Certificate(cert) = c else {
            return None;
        };
        let matches = match sid {
            SignerIdentifier::IssuerAndSerialNumber(isn) => {
                isn.issuer == *cert.tbs_certificate().issuer()
                    && isn.serial_number == *cert.tbs_certificate().serial_number()
            }
            // DoD's streams use this form, so it is the one that matters in practice. The
            // comparison is against the certificate's own subjectKeyIdentifier extension,
            // not a recomputed digest: a SignerInfo names the value the issuer published,
            // and a certificate whose SKID was derived some other way would not match a
            // hash we chose.
            SignerIdentifier::SubjectKeyIdentifier(skid) => {
                skid_of(cert).is_some_and(|published| published == skid.0.as_bytes())
            }
        };
        matches.then(|| cert.clone())
    })
}

#[cfg(test)]
mod tests {
    //! Why the time of interest is the timestamp's and not the machine's.
    //!
    //! `chain_signer` is private, and these reach it directly rather than through
    //! [`verify_member`]: the point is to run the *same* checks at a time `verify_member` would
    //! never choose, which is the only way to show that the choice does anything.

    use super::*;
    use rfc5934::ContentCollection;

    /// `JITC.ir4`: the oldest of the committed streams, timestamped 2025-02-03, and so the one
    /// where "when it was signed" and "now" are furthest apart.
    const JITC: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../certval_stores_nipr/inputs/JITC.ir4"
    );

    /// The first member of `JITC.ir4`, with its signature already verified.
    fn signed_member() -> (PkiEnvironment, SignedData, Certificate) {
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        let bytes = std::fs::read(JITC).expect("JITC.ir4 is readable");
        let collection = ContentCollection::from_der(&bytes).expect("a content collection");
        let sd: SignedData = collection.0[0]
            .content
            .decode_as()
            .expect("member 0 is a SignedData");
        let signer = verify_member_signature(&pe, &sd).expect("member 0's signature verifies");
        (pe, sd, signer)
    }

    /// Validating a stream as of *now* fails, because the revocation information it staples went
    /// stale long ago -- and validating it as of its verified timestamp succeeds on that same data.
    ///
    /// This is the whole argument for taking the time from the timestamp, and the reason the
    /// stapled responses are worth reading. DISA publishes a stream with OCSP responses produced
    /// within days of signing: `JITC.ir4`'s say `good` from 2025-02-03 to 2025-02-10. As of the
    /// timestamp they settle both positions in the signer's chain without a network. As of any
    /// later date they settle nothing, and an offline verifier that asked at the wrong moment would
    /// have to choose between refusing material DISA published and never withdrew, or accepting a
    /// signer whose status it never determined.
    ///
    /// The filed count is asserted alongside the failure on purpose: "undetermined with 2 of 2
    /// filed" is stale data, while "undetermined with 0 of 2 filed" would be a `CertID` matcher
    /// that had stopped matching -- the same failure for a completely different reason, and a test
    /// that could not tell them apart would pass while the matcher rotted.
    #[test]
    fn a_current_time_of_interest_fails_on_stale_stapled_revocation() {
        let (pe, sd, signer) = signed_member();
        let stapled = stapled_ocsp(&sd).expect("JITC.ir4 staples revocation information");
        assert_eq!(
            2,
            stapled.len(),
            "every published member staples a response for each position in the signer's chain"
        );

        // As of the verified timestamp, on exactly this data: the member verifies whole.
        verify_member(&pe, &sd, Revocation::Stapled)
            .expect("the member verifies as of its own timestamp");

        let err = chain_signer(
            &signer,
            sd.certificates.as_ref(),
            &stapled,
            TimeOfInterest::now(),
        )
        .expect_err("a stream must not validate at the current time on stale revocation data")
        .to_string();
        assert!(
            err.contains("RevocationStatusNotDetermined"),
            "expected an undetermined revocation status, got: {err}"
        );
        assert!(
            err.contains("2 of 2 stapled response(s) filed"),
            "the stapled responses must still match the chain, so that the failure is their age \
             and not the CertID matcher: {err}"
        );
    }

    /// Revocation checking is not decoration: with nothing stapled there is nothing to determine a
    /// status from, and the chain fails even as of the timestamp that dates its signature.
    ///
    /// Together with the test above this pins both halves of what the stapled data does -- it is
    /// consulted, and it is required.
    #[test]
    fn a_member_without_stapled_revocation_data_does_not_chain() {
        let (pe, sd, signer) = signed_member();
        let timestamp = crate::timestamp::verified_gen_time(
            &pe,
            sole_signer_info(&sd).unwrap(),
            Revocation::Stapled,
        )
        .expect("the timestamp verifies")
        .expect("JITC.ir4 is timestamped");

        let err = chain_signer(&signer, sd.certificates.as_ref(), &[], timestamp)
            .expect_err("without revocation data no status can be determined")
            .to_string();
        assert!(
            err.contains("RevocationStatusNotDetermined") && err.contains("0 of 0"),
            "expected an undetermined status with nothing filed, got: {err}"
        );
    }
}

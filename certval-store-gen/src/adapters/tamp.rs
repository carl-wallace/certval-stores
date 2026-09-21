//! DoD adapter — an InstallRoot `.ir4` stream.
//!
//! A stream is a bare RFC 4073 `ContentCollection` of separately signed CMS messages, each
//! carrying an RFC 5934 `TAMPUpdate`. The message's kind comes from its target URI
//! (`<url>;<stream>;<kind>`), and the two that hold trust material are `Root` and `CA`.
//!
//! Only `add` entries are read. A TAMP update is being used here as a trust store rather than
//! applied as an update, so `remove` and `change` describe transitions this adapter has no prior
//! state to apply. The `RemoveCertificateHintList` message is skipped for the same reason and one
//! more: its entries are structurally `add`, but every one of them shares a public key with a
//! `remove` elsewhere in the same file, so reading it would install exactly the certificates the
//! publisher is withdrawing.
//!
//! One stream carries more than one PKI. `JITC.ir4` publishes DoD JITC/O&M anchors alongside NSS
//! and ECA ones, which belong to different store crates, so the caller names the population it
//! wants and the rest is reported rather than silently dropped.
//!
//! Each member is verified before any of its material is read, and a member that fails is refused:
//! the whole stream is rejected rather than generated from in part. Four things are checked, in
//! `crate::verify` and `crate::timestamp` — that the signature holds against the certificate the
//! stream carries for its signer, named by subject key identifier; that the RFC 3161 timestamp on
//! that signature verifies and chains to a pinned timestamping root; that the signer chains under
//! the code-signing EKU to one of the DoD roots pinned in this crate, as of the time the timestamp
//! establishes; and that no certificate in that chain was revoked, from the OCSP responses the
//! stream staples for exactly this purpose. The third is what makes the first mean something: the
//! anchor comes from here, never from the stream's own `Root` message.
//!
//! A stream is self-contained by design, and the checks are correspondingly offline: the signer's
//! certificate, its chain, the timestamp and the revocation status of every position all travel in
//! the file. Nothing is fetched to verify one.
//!
//! The stream's publication date comes out of that same verified timestamp, so the date a store
//! reports is one a timestamp authority attested rather than one the file asserts about itself.

use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};
use const_oid::db::rfc5911::ID_SIGNING_TIME;
use der::{DateTime, Decode, Encode};
use rfc5934::dod::StreamTarget;
use rfc5934::message::{MessageType, TampMessage};
use rfc5934::signed::SignedData;
use rfc5934::{ContentCollection, TampUpdate, TrustAnchorUpdate};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::time::Time;
use x509_cert::Certificate;

use certval::{CertFile, PkiEnvironment};

use crate::verify::Revocation;

use crate::core::StoreInputs;

/// Which of the PKIs published in one stream to generate a store for.
///
/// A stream is a publication channel, not a PKI: `JITC.ir4` carries three. The distinguishing
/// mark is in the anchors' own names — NSS anchors sit under `OU=NSS`, ECA anchors under `OU=ECA`,
/// WCF anchors under `OU=WCF PKI`
/// — and the CAs follow whichever anchor they chain to rather than being classified themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Population {
    /// DoD proper: the `nipr` and `om_nipr` environments.
    Dod,
    /// National Security Systems, which `certval_stores_sipr` carries.
    Nss,
    /// The External Certification Authority program.
    Eca,
    /// The WCF PKI, which `WCF.ir4` publishes on its own.
    ///
    /// A DoD sub-PKI rather than a separate community -- its anchors sit under `OU=DoD` like the
    /// rest -- and it is named here for the same reason NSS and ECA are: so a store generated
    /// from one stream cannot quietly acquire anchors from another. `WCF.ir4` carries nothing but
    /// this population today, and `DoD.ir4` carries none of it; were DISA to publish a WCF root
    /// in `DoD.ir4`, the `Dod` population would otherwise absorb it into `certval_stores_nipr`.
    Wcf,
}

impl Population {
    /// The population an anchor belongs to, read from its subject.
    fn of(cert: &Certificate) -> Population {
        let subject = cert.tbs_certificate().subject().to_string();
        if subject.contains("OU=NSS") {
            Population::Nss
        } else if subject.contains("OU=ECA") {
            Population::Eca
        } else if subject.contains("OU=WCF PKI") {
            Population::Wcf
        } else {
            Population::Dod
        }
    }

    /// The name this is spelled with, the inverse of [`Population::parse`].
    pub fn name(&self) -> &'static str {
        match self {
            Population::Dod => "dod",
            Population::Nss => "nss",
            Population::Eca => "eca",
            Population::Wcf => "wcf",
        }
    }

    /// The name accepted on the command line.
    pub fn parse(s: &str) -> Result<Population> {
        match s.to_ascii_lowercase().as_str() {
            "dod" => Ok(Population::Dod),
            "nss" => Ok(Population::Nss),
            "eca" => Ok(Population::Eca),
            "wcf" => Ok(Population::Wcf),
            other => Err(anyhow!(
                "unknown population {other:?} (expected one of: dod, nss, eca, wcf)"
            )),
        }
    }
}

/// Parse an InstallRoot stream and return the trust material for one population.
pub fn build(
    pe: &PkiEnvironment,
    ir4: &[u8],
    population: Population,
    revocation: Revocation,
) -> Result<StoreInputs> {
    let collection = ContentCollection::from_der(ir4)
        .context("the stream is not an RFC 4073 content collection")?;

    let mut anchors: Vec<Certificate> = vec![];
    let mut cas: Vec<Certificate> = vec![];
    let mut dates: Vec<DateTime> = vec![];
    let mut signers: Vec<String> = vec![];
    // Collected rather than returned on the first failure, so a person sees every member that
    // is wrong instead of fixing them one build at a time.
    let mut unverified: Vec<String> = vec![];

    for ci in collection.0.iter() {
        let sd: SignedData = ci
            .content
            .decode_as()
            .context("a collection member is not a SignedData")?;
        match crate::verify::verify_member(pe, &sd, revocation) {
            Ok(member) => {
                let name = certval::get_leaf_rdn(member.signer.tbs_certificate().subject());
                if !signers.contains(&name) {
                    signers.push(name);
                }
                // Every member, not only the two the material comes from: they are signed in one
                // run, seconds apart, so the latest date among them is when the stream was
                // published. The timestamp is the date that matters and the one DoD states; a
                // `signingTime` is read as well for a publisher that includes one.
                dates.extend(member.timestamped_at.map(|t| t.0));
                dates.extend(signing_times(&sd));
            }
            Err(e) => unverified.push(e.to_string()),
        }
        let message = TampMessage::from_encapsulated(&sd.encap_content_info)
            .map_err(|e| anyhow!("a member's encapsulated TAMP message does not decode: {e:?}"))?;
        if message.message_type() != MessageType::Update {
            continue;
        }
        let TampMessage::Update(update) = message else {
            unreachable!("just checked the type")
        };
        let target = StreamTarget::parse(&update.msg_ref.target).ok_or_else(|| {
            anyhow!("a member's target URI is not the InstallRoot three-field form")
        })?;
        match target.kind.label() {
            "Root" => anchors.extend(added_certificates(&update)),
            "CA" => cas.extend(added_certificates(&update)),
            _ => {}
        }
    }

    // Refused before any of the material is used. A member fails here because the TAMP content no
    // longer matches what was signed under the key the stream names as its signer -- corruption or
    // tampering, with no benign reading -- or because that signer does not chain to a pinned DoD
    // root under the code-signing EKU, which says DISA did not publish it, or because a
    // certificate in that chain was revoked or its status could not be settled from what the
    // stream staples. None
    // leaves anything worth generating from, and a stream is taken whole or not at all: a
    // partially trustworthy trust store is a contradiction.
    if !unverified.is_empty() {
        return Err(anyhow!(
            "{} of the stream's {} members failed signature verification, so none of its material \
             is usable: {}",
            unverified.len(),
            collection.0.len(),
            unverified.join("; ")
        ));
    }

    if anchors.is_empty() {
        return Err(anyhow!(
            "the stream published no trust anchors; it is not an InstallRoot stream this can generate from"
        ));
    }

    report_populations(&anchors, population);

    let selected: Vec<Certificate> = anchors
        .iter()
        .filter(|c| Population::of(c) == population)
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err(anyhow!(
            "the stream publishes no {population:?} anchors; check the population against the log line above"
        ));
    }

    let reachable = chains_to(&selected, &cas);

    let mut inputs = StoreInputs {
        published: published_date(&dates),
        ..Default::default()
    };
    match &inputs.published {
        Some(date) => log::info!("the stream was published {date}"),
        None => log::info!(
            "the stream's messages state no date, so the store will report no publication date"
        ),
    }
    for cert in &selected {
        push_unique(&mut inputs.trust_anchors, cert)?;
    }
    for cert in &reachable {
        push_unique(&mut inputs.intermediates, cert)?;
    }

    // States what was checked, in the terms a reader of a build log would want: who signed the
    // material, that the signer is one this crate pins rather than one the stream nominates, and
    // when -- the timestamp being what makes "chained" mean anything for a stream that has been
    // published for a year.
    log::info!(
        "InstallRoot ({population:?}): {} trust anchors, {} intermediates — every member \
         signed by {}, chained to a pinned DoD root under the code-signing EKU as of the \
         verified timestamp, with no position revoked per the stapled OCSP",
        inputs.trust_anchors.len(),
        inputs.intermediates.len(),
        signers.join(", ")
    );

    Ok(inputs)
}

/// Any `signingTime` this message's signer asserted.
///
/// DoD asserts none: its `SignerInfo` carries `contentType` and `messageDigest` and nothing
/// else, and the date on a DoD stream comes from the RFC 3161 timestamp instead -- verified,
/// in `crate::timestamp`, which is why it is the date this adapter prefers. This is here for a
/// publisher that does include one; nothing in RFC 5934 requires either.
///
/// Unlike the timestamp, a `signingTime` is only the signer's own claim about itself. It is a
/// signed attribute, so it cannot be altered without breaking the signature -- but the signer
/// could have written anything there to begin with, which is why it is never used to decide what
/// time to validate that signer at.
fn signing_times(sd: &SignedData) -> Vec<DateTime> {
    let mut dates = vec![];
    for si in sd.signer_infos.0.iter() {
        for attr in si.signed_attrs.iter().flat_map(|a| a.iter()) {
            if attr.oid != ID_SIGNING_TIME {
                continue;
            }
            for value in attr.values.iter() {
                match value.decode_as::<Time>() {
                    Ok(t) => dates.push(t.to_date_time()),
                    // Not worth failing a generation over: the store is built from the
                    // certificates, and the consequence of dropping this is a store that
                    // states no publication date rather than one that states a wrong date.
                    Err(e) => log::warn!(
                        "a signingTime attribute does not decode to a date and was ignored: {e:?}"
                    ),
                }
            }
        }
    }
    dates
}

/// The latest of `dates` as `YYYY-MM-DD`, which is the date the stream as a whole was
/// published: its messages are signed one after another in a single run, seconds apart.
///
/// The latest rather than the earliest because that is the one a reader would check a
/// store's freshness against, and taking the earliest would age the store by the length of
/// the publisher's signing run.
fn published_date(dates: &[DateTime]) -> Option<String> {
    let latest = dates.iter().max()?;
    Some(format!(
        "{:04}-{:02}-{:02}",
        latest.year(),
        latest.month(),
        latest.day()
    ))
}

/// The certificates carried by this message's `add` entries.
///
/// Every published entry has been `add(taInfo)` with the certificate present; an `add` in any
/// other form carries no certificate to store, so it is counted in the log rather than failing
/// the run.
fn added_certificates(update: &TampUpdate) -> Vec<Certificate> {
    let mut certs = vec![];
    let mut without_certificate = 0usize;
    for entry in &update.updates {
        match entry {
            TrustAnchorUpdate::Add(TrustAnchorChoice::TaInfo(info)) => {
                match info.cert_path.as_ref().and_then(|p| p.certificate.as_ref()) {
                    Some(cert) => certs.push(cert.clone()),
                    None => without_certificate += 1,
                }
            }
            TrustAnchorUpdate::Add(_) => without_certificate += 1,
            TrustAnchorUpdate::Remove(_) | TrustAnchorUpdate::Change(_) => {}
        }
    }
    if without_certificate > 0 {
        log::info!("{without_certificate} add entries carried no certificate and were skipped");
    }
    certs
}

/// Says what else the stream published, so material destined for another crate is visible in the
/// run rather than discovered later by someone diffing stores.
fn report_populations(anchors: &[Certificate], selected: Population) {
    for population in [
        Population::Dod,
        Population::Nss,
        Population::Eca,
        Population::Wcf,
    ] {
        let names: Vec<String> = anchors
            .iter()
            .filter(|c| Population::of(c) == population)
            .map(|c| c.tbs_certificate().subject().to_string())
            .collect();
        if names.is_empty() {
            continue;
        }
        let disposition = if population == selected {
            "generating"
        } else {
            "not this store"
        };
        log::info!(
            "stream publishes {} {population:?} anchor(s) [{disposition}]: {}",
            names.len(),
            names.join(", ")
        );
    }
}

/// The CAs that chain to one of `anchors`, directly or through another CA in the stream.
///
/// Chaining is by name here, not by signature: this decides which store a certificate belongs in,
/// and the populations are disjoint name spaces. Whether each certificate is genuinely signed by
/// its issuer is a validation question, and answering it is what the deferred signature
/// verification covers.
fn chains_to(anchors: &[Certificate], cas: &[Certificate]) -> Vec<Certificate> {
    let mut issuers: BTreeSet<String> = anchors
        .iter()
        .map(|c| c.tbs_certificate().subject().to_string())
        .collect();

    let mut reachable: Vec<Certificate> = vec![];
    let mut remaining: Vec<&Certificate> = cas.iter().collect();

    // A CA can be issued by another CA in the same stream, so keep sweeping until a pass adds
    // nothing: one pass in publication order would drop a subordinate listed before its issuer.
    loop {
        let mut added = false;
        remaining.retain(|cert| {
            if issuers.contains(&cert.tbs_certificate().issuer().to_string()) {
                issuers.insert(cert.tbs_certificate().subject().to_string());
                reachable.push((*cert).clone());
                added = true;
                false
            } else {
                true
            }
        });
        if !added {
            break;
        }
    }

    if !remaining.is_empty() {
        log::info!(
            "{} CA certificate(s) chain to anchors outside this population and were left out",
            remaining.len()
        );
    }
    reachable
}

/// Add a certificate to `dest` under a label derived from its subject, skipping exact duplicates.
///
/// The label becomes the `CertFile` filename, which is also the filename the provider crate
/// commits, so it has to be deterministic and unique: the common name with anything outside
/// `[A-Za-z0-9._-]` replaced by `_`, and the serial appended when two certificates share a name.
/// That last case is real — a stream can publish two generations of one CA, and a subject alone
/// would silently overwrite one with the other.
fn push_unique(dest: &mut Vec<CertFile>, cert: &Certificate) -> Result<()> {
    let der = cert
        .to_der()
        .context("a published certificate does not re-encode")?;
    if dest.iter().any(|c| c.bytes == der) {
        return Ok(());
    }
    let base = label(cert);
    let filename = if dest.iter().any(|c| c.filename == base) {
        format!("{base}_{}", serial_hex(cert))
    } else {
        base
    };
    dest.push(CertFile {
        filename,
        bytes: der,
    });
    Ok(())
}

/// A filesystem-safe label from the certificate's common name, falling back to the whole subject.
fn label(cert: &Certificate) -> String {
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

fn serial_hex(cert: &Certificate) -> String {
    cert.tbs_certificate()
        .serial_number()
        .to_string()
        .replace(':', "")
}

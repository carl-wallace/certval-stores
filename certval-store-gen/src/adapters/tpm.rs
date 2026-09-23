//! TPM vendor roots adapter — `TrustedTpm.cab`.
//!
//! Microsoft redistributes the root and intermediate CAs of every TPM vendor whose attestation
//! keys Windows will accept, as one Authenticode-signed cabinet. Unlike the root program's trust
//! list ([`super::authroot`]), this cabinet *is* the material: 2,209 members, of which 2,158 are
//! intermediate CAs, 48 are roots and three are packaging.
//!
//! **It is [`crate::cab`]'s first route: the cabinet vouches for its members.** `TrustedTpm.cab`
//! has `flags 0x0004`, so its reserved area carries an Authenticode signature covering everything
//! inside, and none of the certificates is signed on its own. That is the opposite of
//! `authrootstl.cab`, and the reason both routes exist.
//!
//! **The publisher's own folder names classify the material**, and nothing here second-guesses
//! them:
//!
//! ```text
//! <vendor>\RootCA\<name>.crt            48, the trust anchors
//! <vendor>\IntermediateCA\<name>.crt  2158, the CAs beneath them
//! version.txt, setup.cmd, setup.ps1     packaging
//! ```
//!
//! Splitting by self-signature -- what the PKCS#7 adapters do -- would be wrong twice over here: a
//! vendor root that will not verify under an algorithm certval supports would be filed as an
//! intermediate, and a self-signed *intermediate* would be promoted to an anchor. Microsoft has
//! already said which is which, in the only place that can know.
//!
//! **Vendors here are not a taxonomy.** Ten top-level folders (Microsoft alone holds 1,831
//! members, then Infineon, AMD, Intel, NationZ, STMicro, Nuvoton, Atmel, QC), but they are one
//! trust set: an attestation key chains to whichever vendor made the part, and a consumer cannot
//! know in advance which that is. So this yields one environment, and the vendor survives only in
//! the per-certificate label.

use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};

use certval::CertFile;

use crate::cab::Member;
use crate::core::StoreInputs;

/// Where Microsoft serves the cabinet. A `go.microsoft.com` redirector rather than a direct URL,
/// which is what their own documentation gives.
pub const CAB_URL: &str = "https://go.microsoft.com/fwlink/?linkid=2097925";

/// The member naming the date the contents were last changed.
pub const VERSION_MEMBER: &str = "version.txt";

/// The path segment marking a trust anchor, as the cabinet spells it.
const ROOT_SEGMENT: &str = r"\RootCA\";
/// The path segment marking an intermediate CA.
const INTERMEDIATE_SEGMENT: &str = r"\IntermediateCA\";

/// What a cabinet held, once classified.
pub struct Contents {
    /// Anchors and intermediates as the cabinet held them, before pruning: everything the
    /// publisher shipped, including CAs that reach no anchor in it and CAs it had already
    /// outlived. See [`crate::core::prune_unvalidated`], which decides what the store carries.
    pub inputs: StoreInputs,
    /// Members that named a certificate location and did not yield one, with the reason. Never
    /// silently discarded: a vendor folder that stops parsing is how a store quietly shrinks.
    pub skipped: Vec<String>,
}

/// Classify a verified cabinet's members into trust anchors and intermediate CAs.
///
/// `members` must come from [`crate::cab::open_verified`]. This function checks no signature and
/// cannot: the certificates inside carry none, which is the whole reason the cabinet does.
pub fn build(members: &[Member]) -> Result<Contents> {
    let mut inputs = StoreInputs {
        published: members
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(VERSION_MEMBER))
            .and_then(|m| published_date(&String::from_utf8_lossy(&m.bytes))),
        ..Default::default()
    };
    let mut skipped = vec![];

    for member in members {
        let is_root = member.name.contains(ROOT_SEGMENT);
        let is_intermediate = member.name.contains(INTERMEDIATE_SEGMENT);
        if !is_root && !is_intermediate {
            continue; // packaging, or a folder shape this does not claim to understand
        }
        // A vendor folder holds more than certificates -- `AMD\IntermediateCA\readme.txt` is in
        // there -- so what does not claim to be one is passed over rather than reported as a
        // failure to parse.
        if !names_a_certificate(&member.name) {
            continue;
        }
        // Read through the shared reader, not as bare DER: measured, this cabinet mixes encodings
        // within a single vendor folder. Several hundred `.crt` and `.cer` members are PEM (their
        // first byte is `0x2d`, the `-` of a BEGIN line), and reading them as DER reports a store
        // that has quietly lost a vendor's whole intermediate set.
        match crate::ingest::certs_from_bytes(&member.bytes) {
            Ok(certs) if !certs.is_empty() => {
                for cert in certs {
                    let cf = CertFile {
                        filename: label(&member.name),
                        bytes: cert.bytes,
                    };
                    match is_root {
                        true => inputs.trust_anchors.push(cf),
                        false => inputs.intermediates.push(cf),
                    }
                }
            }
            Ok(_) => skipped.push(format!("{}: held no certificate", member.name)),
            Err(e) => skipped.push(format!("{}: {e}", member.name)),
        }
    }

    // Vendors share certificates: `Microsoft Pluton Root CA 2021` ships under AMD\RootCA as well
    // as Microsoft\RootCA, and the same happens among the intermediates. `core::generate`
    // deduplicates when it builds the store, but a provider crate writes one file per input and
    // embeds one `include_bytes!` per file -- so a duplicate reaching here becomes two files, two
    // embedded anchors, and a conformance failure saying two roots are the same anchor. First
    // occurrence wins, which keeps the label of whichever vendor folder sorts first.
    dedup_by_bytes(&mut inputs.trust_anchors);
    dedup_by_bytes(&mut inputs.intermediates);

    if inputs.trust_anchors.is_empty() {
        return Err(anyhow!(
            "the cabinet holds no {ROOT_SEGMENT} member, so it is not the TPM root cabinet"
        ));
    }
    Ok(Contents { inputs, skipped })
}

/// The date `version.txt` states, as `YYYY-MM-DD`.
///
/// The file opens "The certificates were last updated on:" and then a line like `27-August-2025`,
/// followed by a hundred and fifty kilobytes of per-release notes. Only the first such date is
/// read: it is the one the header introduces, and the rest belong to earlier releases.
///
/// This is the publisher's own statement of when the material changed, which makes it both the
/// `published` date and the rollback guard -- a refresh that fetches something dated earlier than
/// what is committed is looking at a stale mirror, not an update.
pub fn published_date(version_txt: &str) -> Option<String> {
    for line in version_txt.lines() {
        let line = line.trim();
        let mut parts = line.split('-');
        let (Some(day), Some(month), Some(year), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (Ok(day), Ok(year)) = (day.parse::<u8>(), year.parse::<u16>()) else {
            continue;
        };
        let Some(month) = month_number(month) else {
            continue;
        };
        if (1..=31).contains(&day) && (2000..=2100).contains(&year) {
            return Some(format!("{year:04}-{month:02}-{day:02}"));
        }
    }
    None
}

/// Drop repeats, comparing the certificates rather than their labels: the same bytes under two
/// vendor folders are one certificate with two names.
fn dedup_by_bytes(certs: &mut Vec<CertFile>) {
    let mut seen = BTreeSet::new();
    certs.retain(|cf| seen.insert(cf.bytes.clone()));
}

/// A file name for a member, from the Windows archive path it has inside the cabinet.
///
/// `AMD\RootCA\AMD-Root-CA.crt` becomes `AMD_AMD-Root-CA`. Three things this has to do, each of
/// which went wrong on the first attempt at using the member name directly:
///
/// * **Drop the backslashes.** They are legal in a POSIX file name, so the files wrote happily on
///   this machine -- and would be path separators on Windows, and are an escape sequence inside
///   the `include_bytes!` string the crate embeds them with.
/// * **Keep the vendor.** It is the only place the vendor survives (the store is one environment),
///   and without it two vendors shipping `root.crt` would collide.
/// * **Drop the original extension**, since the writer appends `.der` and `x.crt.der` reads as a
///   mistake rather than a re-encoding.
fn label(member_name: &str) -> String {
    let mut parts = member_name.split('\\');
    let vendor = parts.next().unwrap_or_default();
    let file = member_name.rsplit('\\').next().unwrap_or(member_name);
    let stem = match file.rfind('.') {
        Some(i) => &file[..i],
        None => file,
    };
    match vendor.is_empty() || vendor == file {
        true => stem.to_string(),
        false => format!("{vendor}_{stem}"),
    }
}

/// Whether a member's name claims to be a certificate at all.
///
/// The extensions this cabinet actually uses, measured, plus `.der` and `.pem` for the day it
/// does. Anything else in a vendor folder is documentation.
fn names_a_certificate(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".crt", ".cer", ".der", ".pem"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// English month names as the file spells them, full and unabbreviated.
fn month_number(name: &str) -> Option<u8> {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(name))
        .map(|i| i as u8 + 1)
}

/// Read the cabinet, verify it, and classify what it holds.
#[cfg(all(feature = "fetch", feature = "cab"))]
pub fn fetch_contents() -> Result<Contents> {
    let cab = crate::refresh::fetch(CAB_URL).map_err(|e| anyhow!("{e}"))?;
    let members = crate::cab::open_verified(&cab).context("the TPM cabinet was refused")?;
    build(&members)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published file's own shape, and the two ways a line can look like a date and not be
    /// one. Worth pinning because this date is the rollback guard: reading the wrong one would
    /// either block every refresh or accept a stale mirror.
    #[test]
    fn the_first_full_date_is_the_published_one() {
        let version = "The certificates were last updated on:\n\
                       27-August-2025\n    Added the following AIK Certificates\n\
                       01-January-2020\n";
        assert_eq!(published_date(version).as_deref(), Some("2025-08-27"));
        assert_eq!(published_date("no date here\n27-Smarch-2025\n"), None);
        assert_eq!(published_date("99-August-2025\n"), None);
        assert_eq!(published_date("2025-08-27\n"), None);
    }

    /// A cabinet with no roots is not this cabinet, and yielding an anchorless store from it would
    /// fail much later with much less to go on.
    #[test]
    fn a_cabinet_without_roots_is_refused() {
        let members = vec![Member {
            name: r"Vendor\IntermediateCA\something.crt".to_string(),
            bytes: vec![0x30, 0x00],
        }];
        assert!(build(&members).is_err());
    }

    /// The label has to survive a Windows archive path, because the name it yields becomes both a
    /// file on disk and a string inside an `include_bytes!`.
    #[test]
    fn a_label_drops_the_path_and_keeps_the_vendor() {
        assert_eq!(label(r"AMD\RootCA\AMD-Root-CA.crt"), "AMD_AMD-Root-CA");
        assert_eq!(
            label(r"Microsoft\IntermediateCA\amd-keyid-12fb.cer"),
            "Microsoft_amd-keyid-12fb"
        );
        assert_eq!(label("bare.crt"), "bare");
        assert!(!label(r"AMD\RootCA\x.crt").contains('\\'));
    }

    /// Documentation inside a vendor folder is not a broken certificate.
    #[test]
    fn a_member_that_does_not_claim_to_be_a_certificate_is_passed_over() {
        assert!(names_a_certificate(r"AMD\IntermediateCA\x.crt"));
        assert!(names_a_certificate(r"AMD\IntermediateCA\x.CER"));
        assert!(!names_a_certificate(r"AMD\IntermediateCA\readme.txt"));
        assert!(!names_a_certificate("version.txt"));
    }
}

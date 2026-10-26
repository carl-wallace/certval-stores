//! Without the `tpm` feature this crate serves no environment, so the whole file compiles to
//! nothing -- which is what `cargo test --no-default-features` builds in CI. Note that it then
//! reports zero tests rather than failing, so a gate that is wrong in the other direction is
//! silent; the feature-on run is what proves these execute.
#![cfg(feature = "tpm")]

//! Per-vendor path validation over the intermediates in the committed cabinet.
//!
//! A second route to what the generator records in `provenance/tpm/dropped.txt`. The generator
//! decides what the store carries by validating every intermediate against the shipped roots as of
//! the cabinet's publication date; these build and validate a path for each intermediate one at a
//! time, through the environment a consumer gets from this crate, and require the two to agree
//! exactly, vendor by vendor, on which intermediates fail. A disagreement in either direction is
//! a bug in one of them.
//!
//! Beyond that, one remedy the cabinet cannot supply: AMD's fTPM intermediates chain to two AMD
//! engineering roots Microsoft does not ship, committed as `tests/examples/*.crt`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use certval::{
    buffer_to_hex, CertFile, CertSource, CertVector, CertificationPath, CertificationPathResults,
    CertificationPathSettings, PDVCertificate, PkiEnvironment, TaSource,
};

/// Authenticode digest of `inputs/TrustedTpm.cab`, the cabinet this crate's material came from.
const EXPECTED_CAB_DIGEST: &str =
    "1B22B9A8225C066B31AAD5A559B3588CCDDFF74F833AA4912313150D1431C035";

const CABINET: &[u8] = include_bytes!("../inputs/TrustedTpm.cab");

/// The cabinet's members, unpacked once per test binary: decompressing it is most of what a test
/// here would otherwise spend, and every test reads the same cabinet.
fn members() -> &'static [certval_store_gen::cab::Member] {
    static MEMBERS: OnceLock<Vec<certval_store_gen::cab::Member>> = OnceLock::new();
    MEMBERS.get_or_init(|| {
        certval_store_gen::cab::members(CABINET).expect("the committed cabinet must read")
    })
}

/// The cabinet's intermediates, labelled `<Vendor>_<stem>` as the generator labels them.
///
/// Read through the generator's own classification so the two cannot disagree about which members
/// are intermediates or how a PEM member decodes; what is under test is the validation, not the
/// unpacking.
fn intermediates() -> &'static [CertFile] {
    static INTERMEDIATES: OnceLock<Vec<CertFile>> = OnceLock::new();
    INTERMEDIATES.get_or_init(|| {
        certval_store_gen::adapters::tpm::build(members())
            .expect("the committed cabinet must classify")
            .inputs
            .intermediates
    })
}

/// The labels `provenance/tpm/dropped.txt` records, whatever the reason.
///
/// Each line is `unrooted     <label>` or `unvalidated  <label>  <reason>`; a label may contain
/// single spaces but not the double space that separates it from the reason.
fn dropped() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("provenance/tpm/dropped.txt");
    let body = std::fs::read_to_string(&path).expect("dropped.txt must exist");
    body.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let rest = l
                .strip_prefix("unrooted")
                .or_else(|| l.strip_prefix("unvalidated"))
                .unwrap_or_else(|| panic!("unrecognized line in dropped.txt: {l}"))
                .trim_start();
            rest.split("  ").next().unwrap_or(rest).to_string()
        })
        .collect()
}

/// The environment this crate serves, at the cabinet's publication date -- the date the store is
/// pruned at -- with `extra_anchors` beside the shipped roots.
fn environment(extra_anchors: &[&[u8]]) -> (PkiEnvironment, CertificationPathSettings) {
    let entry = certval_stores_tpm::provider()
        .entries()
        .into_iter()
        .find(|e| e.id == certval_stores_tpm::TPM)
        .expect("the tpm environment must be served");

    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(
        certval_store_gen::core::published_as_time_of_interest(
            entry
                .published
                .expect("the tpm entry states a publication date"),
        )
        .expect("the publication date must convert"),
    );

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut ta_source = TaSource::new();
    for (ii, der) in entry.roots.iter().chain(extra_anchors).enumerate() {
        ta_source.push(CertFile {
            filename: format!("anchor #{ii}"),
            bytes: der.to_vec(),
        });
    }
    ta_source.initialize().expect("the anchors must load");

    let mut cert_source =
        CertSource::new_from_cbor(entry.cert_store_cbor.expect("the tpm store carries CAs"))
            .expect("the CA store must load");
    cert_source
        .initialize(&cps)
        .expect("the CA store must initialize");

    pe.add_trust_anchor_source(Box::new(ta_source));
    pe.add_certificate_source(Box::new(cert_source));
    (pe, cps)
}

/// The labels among `targets` for which no path validates in `pe`, including those that do not
/// parse as a certificate certval accepts.
fn failures(
    targets: &[&CertFile],
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
) -> BTreeSet<String> {
    let mut failed = BTreeSet::new();
    for target in targets {
        let Ok(cert) = PDVCertificate::try_from(target.bytes.as_slice()) else {
            failed.insert(target.filename.clone());
            continue;
        };
        let mut paths: Vec<CertificationPath> = vec![];
        let _ = pe.get_paths_for_target(&cert, &mut paths, 0, cps.get_time_of_interest());
        let validates = paths.iter_mut().any(|path| {
            let mut cpr = CertificationPathResults::new();
            pe.validate_path(pe, cps, path, &mut cpr).is_ok()
        });
        if !validates {
            failed.insert(target.filename.clone());
        }
    }
    failed
}

/// Validate one vendor's intermediates and require the failures to be exactly that vendor's
/// entries in `dropped.txt`. Returns the failures, for a vendor with a remedy to try.
fn agrees_with_dropped(vendor: &str) -> BTreeSet<String> {
    let prefix = format!("{vendor}_");
    let targets: Vec<&CertFile> = intermediates()
        .iter()
        .filter(|cf| cf.filename.starts_with(&prefix))
        .collect();
    assert!(
        !targets.is_empty(),
        "the cabinet holds no {vendor} intermediates"
    );

    let (pe, cps) = environment(&[]);
    let failed = failures(&targets, &pe, &cps);
    let expected: BTreeSet<String> = dropped()
        .into_iter()
        .filter(|label| label.starts_with(&prefix))
        .collect();
    assert_eq!(
        failed,
        expected,
        "{vendor}: the intermediates that fail here are not the ones dropped.txt records\n\
         fail here, not dropped: {:?}\ndropped, validate here: {:?}",
        failed.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&failed).collect::<Vec<_>>(),
    );
    println!(
        "{vendor}: {} intermediates, {} fail, as dropped.txt records",
        targets.len(),
        failed.len()
    );
    failed
}

/// AMD's fTPM intermediates reach no root the cabinet carries. They chain to two AMD engineering
/// roots instead, and with those added every AMD intermediate has to validate.
#[test]
fn validate_cas_amd() {
    let failed = agrees_with_dropped("AMD");
    let amd_engineering_roots: [&[u8]; 2] = [
        include_bytes!("examples/23452201D41C5AB064032BD23F158FEF.crt"),
        include_bytes!("examples/264D39A23CEB5D5B49D610044EEBD121.crt"),
    ];
    let targets: Vec<&CertFile> = intermediates()
        .iter()
        .filter(|cf| failed.contains(&cf.filename))
        .collect();
    let (pe, cps) = environment(&amd_engineering_roots);
    let still_failing = failures(&targets, &pe, &cps);
    assert!(
        still_failing.is_empty(),
        "AMD intermediates that do not validate even with the engineering roots: {still_failing:?}"
    );
}

#[test]
fn validate_cas_atmel() {
    agrees_with_dropped("Atmel");
}

#[test]
fn validate_cas_infineon() {
    agrees_with_dropped("Infineon");
}

#[test]
fn validate_cas_intel() {
    agrees_with_dropped("Intel");
}

#[test]
fn validate_cas_microsoft() {
    agrees_with_dropped("Microsoft");
}

#[test]
fn validate_cas_nationz() {
    agrees_with_dropped("NationZ");
}

#[test]
fn validate_cas_nuvoton() {
    agrees_with_dropped("Nuvoton");
}

#[test]
fn validate_cas_qc() {
    agrees_with_dropped("QC");
}

#[test]
fn validate_cas_stmicro() {
    agrees_with_dropped("STMicro");
}

/// Every vendor folder in the cabinet has a test above. A new vendor fails here until it gets one.
#[test]
fn fail_on_new_folders() {
    let expected_folders = [
        "AMD",
        "Atmel",
        "Infineon",
        "Intel",
        "Microsoft",
        "NationZ",
        "Nuvoton",
        "QC",
        "STMicro",
    ];
    let skip = ["setup.cmd", "setup.ps1", "version.txt"];

    for member in members() {
        if skip.contains(&member.name.as_str()) {
            continue;
        }
        // Only the leading path component, the vendor folder, is checked.
        let vendor = member.name.split('\\').next().unwrap_or_default();
        assert!(
            expected_folders.contains(&vendor),
            "{vendor} is an unexpected folder. Please add a test to validate CAs in this folder."
        );
    }
}

/// The committed cabinet is the one this crate's material was generated from.
///
/// Offline: `CabVerifyParts::new` computes the Authenticode digest without touching the network.
/// Pinned so that swapping the cabinet without regenerating is caught here rather than as a
/// puzzling diff in the store.
#[test]
fn the_committed_cabinet_has_the_expected_digest() {
    use tpm_cab_verify::CabVerifyParts;
    let cvp = CabVerifyParts::new(std::io::Cursor::new(CABINET))
        .expect("the committed cabinet must parse");
    certval_stores_core::pin!(EXPECTED_CAB_DIGEST, buffer_to_hex(&cvp.digest));
}

/// The committed cabinet's Authenticode signature verifies.
///
/// `#[ignore]` because verification reaches a timestamp authority to settle the signer's
/// revocation status, and a test that fails when a responder is down is a test nobody trusts —
/// the same reason `the_store_is_what_the_committed_cabinet_generates` uses `cab::members` rather
/// than `cab::open_verified`. The signature is checked for real where the material enters the
/// repository, in the refresh. Run it deliberately with `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "reaches a timestamp authority; the refresh is where this is enforced"]
async fn the_committed_cabinet_verifies() {
    use tpm_cab_verify::CabVerifyParts;
    let cvp = CabVerifyParts::new(std::io::Cursor::new(CABINET)).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    // No time of interest is set here: tpm_cab_verify validates the signing certificates at the
    // genTime from the verified timestamp, so verification does not break as they expire.
    let cps = CertificationPathSettings::default();
    cvp.verify(&mut pe, &cps).await.unwrap();
}

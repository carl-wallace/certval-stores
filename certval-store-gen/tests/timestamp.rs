//! The timestamp checks on an InstallRoot stream, exercised against the committed streams.
//!
//! These are the tests that make the timestamp worth believing. Reading `TSTInfo.genTime` is a
//! few lines; the reason the generator can validate a stream signer *at* that time is that the
//! token is verified first, and a check nothing tests is a check that quietly stops working.
//!
//! Each negative case tampers with a copy of a real stream in memory -- the committed files are
//! never written to -- and each one is aimed at a specific check.
//!
//! All of them verify under [`Revocation::Stapled`], so `cargo test` settles every status from
//! what the streams carry and reaches no responder. The fetched policy is what `verify --stream`
//! uses, and CI exercises it there: a test suite that failed when Sectigo was unreachable would be
//! reporting on Sectigo rather than on this crate.

use certval::PkiEnvironment;

use certval_store_gen::verify::{self, Revocation};

const DOD: &str = "../certval_stores_nipr/inputs/DoD.ir4";
const JITC: &str = "../certval_stores_nipr/inputs/JITC.ir4";
const ECA: &str = "../certval_stores_eca/inputs/ECA.ir4";

/// `id-aa-timeStampToken`, DER, tag and length included: `1.2.840.113549.1.9.16.2.14`.
const TST_ATTRIBUTE_OID: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
];

fn environment() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

fn stream_bytes(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path} is not readable: {e}"))
}

/// Every committed stream verifies, and the date it yields is the one its timestamps state.
///
/// The dates are asserted rather than merely printed: they are what a provider crate publishes as
/// its `published` value and what [`certval_store_gen::refresh`] compares to decide whether a
/// newer stream has been published, so a silent change of provenance would change both.
#[test]
fn committed_streams_verify_and_are_timestamped() {
    let pe = environment();
    for (path, expected) in [
        (DOD, "2026-06-12T19:30:59Z"),
        (JITC, "2025-02-03T16:07:50Z"),
        (ECA, "2025-12-18T15:57:21Z"),
    ] {
        let members = verify::stream(&pe, &stream_bytes(path), Revocation::Stapled)
            .unwrap_or_else(|e| panic!("{path} does not verify: {e}"));
        assert_eq!(4, members.len(), "{path} member count");
        for member in &members {
            assert!(
                member.timestamped_at.is_some(),
                "{path}: a member carries no verified timestamp"
            );
        }
        let latest = members
            .iter()
            .filter_map(|m| m.timestamped_at)
            .max_by_key(|t| t.as_unix_secs())
            .expect("a verified timestamp");
        assert_eq!(expected, latest.to_string(), "{path} publication instant");
    }
}

/// A token lifted from another member of the same stream is refused.
///
/// The check this exercises is the one that makes a timestamp about *this* signature:
/// `messageImprint` has to be the digest of the member's own `SignerInfo.signature`. Without it a
/// token could be taken from any other signed object -- including a neighbouring member, which is
/// signed by the same key, on the same day, by the same authority, and so is the splice most
/// likely to go unnoticed.
///
/// Members 1, 2 and 3 of `DoD.ir4` happen to carry byte-identical *lengths* of `unsignedAttrs`,
/// which is what lets this be a replacement rather than a re-encode: the tampered stream stays
/// structurally valid, so the failure is the imprint check and not a decoder complaining.
#[test]
fn a_token_from_another_member_is_refused() {
    let mut bytes = stream_bytes(DOD);
    // `A1 82 18 E2`: the [1] unsignedAttrs header the three same-length members share.
    let header: &[u8] = &[0xA1, 0x82, 0x18, 0xE2];
    let starts: Vec<usize> = (0..bytes.len() - header.len())
        .filter(|&i| &bytes[i..i + header.len()] == header)
        .collect();
    assert_eq!(
        3,
        starts.len(),
        "expected three same-length unsignedAttrs fields in {DOD}; the stream has been refreshed \
         and this test's splice needs re-measuring"
    );
    let len = 4 + 0x18E2;
    let donor = bytes[starts[1]..starts[1] + len].to_vec();
    bytes[starts[0]..starts[0] + len].copy_from_slice(&donor);

    let err = verify::stream(&environment(), &bytes, Revocation::Stapled)
        .expect_err("a member carrying another member's timestamp must not verify")
        .to_string();
    assert!(
        err.contains("attests to some other signature"),
        "expected the imprint check to refuse the splice, got: {err}"
    );
}

/// Moving the time a token states is refused.
///
/// `genTime` is the token's encapsulated content, so it is covered by the token's own
/// `messageDigest` attribute and then by its signature. This is what stops the value being edited
/// by whoever hands over the stream -- the reason the generator can use it as a time of interest
/// at all, rather than only as a label.
#[test]
fn a_moved_gen_time_is_refused() {
    let mut bytes = stream_bytes(DOD);
    let token = bytes
        .windows(TST_ATTRIBUTE_OID.len())
        .position(|w| w == TST_ATTRIBUTE_OID)
        .expect("DoD.ir4 carries an id-aa-timeStampToken attribute");
    // The first GeneralizedTime inside the token is TSTInfo.genTime. Moved a year *back*, which
    // is the direction that matters: backdating is how a signature made with an expired or
    // compromised key is placed inside the window where that key was still valid. (Moving it
    // forward is refused earlier, by the future-time check, before the digest is even computed.)
    let gen_time = bytes[token..]
        .windows(15)
        .position(|w| w.starts_with(b"20") && w.ends_with(b"Z") && w.len() == 15)
        .map(|i| token + i)
        .expect("the token states a genTime");
    assert_eq!(b'6', bytes[gen_time + 3], "genTime year digit");
    bytes[gen_time + 3] = b'5';

    let err = verify::stream(&environment(), &bytes, Revocation::Stapled)
        .expect_err("a token whose genTime has been moved must not verify")
        .to_string();
    assert!(
        err.contains("messageDigest attribute does not match the encapsulated content"),
        "expected the token's own digest check to refuse the edit, got: {err}"
    );
}

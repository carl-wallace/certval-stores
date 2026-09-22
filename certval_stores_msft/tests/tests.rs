//! Tests for the Microsoft root program provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every provider owes its
//! consumers. What is left here is specific to this one: counts that pin the embedded material,
//! the thumbprint binding that makes an unsigned certificate trust material at all, and the
//! subset relationships the six environments are supposed to have.

use std::collections::BTreeSet;
use std::path::Path;

use certval_stores_core::conformance;
use der::Decode;
use sha1::{Digest, Sha1};
use x509_cert::Certificate;

/// Roots carried from the list published 2026-08-25: 562 entries, less 98 expired and 107
/// restricted past their disallowed date. Update alongside the material -- a change here is the
/// point at which a refresh gets acknowledged in review.
#[cfg(feature = "msft_all")]
const EXPECTED_ALL: usize = 357;
#[cfg(feature = "msft_tls")]
const EXPECTED_TLS: usize = 234;
#[cfg(feature = "msft_client_auth")]
const EXPECTED_CLIENT_AUTH: usize = 267;
#[cfg(feature = "msft_email")]
const EXPECTED_EMAIL: usize = 215;
#[cfg(feature = "msft_code_signing")]
const EXPECTED_CODE_SIGNING: usize = 143;
#[cfg(feature = "msft_timestamping")]
const EXPECTED_TIMESTAMPING: usize = 162;

/// Gated like the tests that call it: with no environment feature enabled this crate serves
/// nothing, so there is no entry to look up.
#[cfg(any(
    feature = "msft_all",
    feature = "msft_tls",
    feature = "msft_client_auth",
    feature = "msft_email",
    feature = "msft_code_signing",
    feature = "msft_timestamping"
))]
fn entry(id: &str) -> certval_stores_core::StoreEntry {
    certval_stores_msft::provider()
        .entries()
        .into_iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("{id} is not served by this provider"))
}

#[test]
fn entry_shapes_are_sound() {
    let failures = conformance::check_entry_shape(certval_stores_msft::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every root has to decode and yield a certificate. A third of this program is SHA-1 signed and
/// two roots are MD2, so this is also what would fail first if the crate were built without
/// certval's `sha1_sig`.
#[test]
fn roots_parse() {
    let failures = conformance::check_roots_parse(certval_stores_msft::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_environment_carries_the_expected_number_of_roots() {
    #[cfg(feature = "msft_all")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_ALL).roots.len(),
        EXPECTED_ALL
    );
    #[cfg(feature = "msft_tls")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_TLS).roots.len(),
        EXPECTED_TLS
    );
    #[cfg(feature = "msft_client_auth")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_CLIENT_AUTH).roots.len(),
        EXPECTED_CLIENT_AUTH
    );
    #[cfg(feature = "msft_email")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_EMAIL).roots.len(),
        EXPECTED_EMAIL
    );
    #[cfg(feature = "msft_code_signing")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_CODE_SIGNING).roots.len(),
        EXPECTED_CODE_SIGNING
    );
    #[cfg(feature = "msft_timestamping")]
    assert_eq!(
        entry(certval_stores_msft::MSFT_TIMESTAMPING).roots.len(),
        EXPECTED_TIMESTAMPING
    );
}

/// The check the whole collection rests on, as a test rather than only as a generation-time step.
///
/// The trust list is signed and the certificates it names are not: each is served over plain HTTP
/// from a URL named after its SHA-1, and what admits it is that the bytes hash to the name that
/// asked for them. Every file in `roots/` is named by that digest, so re-computing it here asserts
/// the binding for the committed material, independently of the generator that wrote it.
#[test]
fn every_file_hashes_to_its_own_name() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("roots/ must exist") {
        let path = entry.expect("readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("der") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a thumbprint file name")
            .to_ascii_uppercase();
        let bytes = std::fs::read(&path).expect("a readable certificate");
        let digest = Sha1::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        assert_eq!(
            digest,
            name,
            "{} does not hash to its own name; it is not the certificate the trust list named",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no certificates found in {}", dir.display());
}

/// Each purpose-scoped environment is a subset of `msft_all`, because all six are views over one
/// list. A root appearing in a narrow environment and not in the broad one would mean the
/// generator filtered the list twice from different inputs.
#[test]
#[cfg(feature = "msft_all")]
fn every_environment_is_a_subset_of_the_whole_program() {
    let all: BTreeSet<&[u8]> = entry(certval_stores_msft::MSFT_ALL)
        .roots
        .iter()
        .copied()
        .collect();
    for e in certval_stores_msft::provider().entries() {
        if e.id == certval_stores_msft::MSFT_ALL {
            continue;
        }
        for root in e.roots {
            assert!(
                all.contains(root),
                "{} carries a root that {} does not",
                e.id,
                certval_stores_msft::MSFT_ALL
            );
        }
    }
}

/// No environment lists the same certificate twice. Six overlapping views over one directory is
/// exactly the shape in which a generator bug repeats an entry rather than dropping one.
#[test]
fn no_environment_repeats_a_root() {
    for e in certval_stores_msft::provider().entries() {
        let distinct: BTreeSet<&[u8]> = e.roots.iter().copied().collect();
        assert_eq!(distinct.len(), e.roots.len(), "{} repeats a root", e.id);
    }
}

/// The program publishes roots and no intermediates, so a CA store here would mean material from
/// somewhere else had been mixed in.
#[test]
fn no_environment_claims_a_ca_store() {
    for e in certval_stores_msft::provider().entries() {
        assert!(
            e.cert_store_cbor.is_none(),
            "{} claims a CA store; Microsoft publishes no intermediates",
            e.id
        );
    }
}

/// Both dates are knowable here -- the list states its own `thisUpdate`, and the generator records
/// when it fetched -- so neither may be left unstated.
#[test]
fn every_environment_states_both_dates() {
    for e in certval_stores_msft::provider().entries() {
        assert!(e.published.is_some(), "{} states no publication date", e.id);
        assert!(e.collected.is_some(), "{} states no collection date", e.id);
    }
}

/// No carried root is signed with an algorithm certval cannot verify.
///
/// The program lists ten such roots -- two MD2 and eight MD5 -- and all ten happen to be excluded
/// already for being expired or restricted. That is a coincidence of this month's list, not a
/// property of it, so the invariant is asserted rather than assumed: a root un-restricted by a
/// future refresh would otherwise arrive as an anchor that can anchor nothing.
#[test]
fn no_root_uses_an_algorithm_certval_cannot_verify() {
    const OBSOLETE: &[&str] = &[
        "1.2.840.113549.1.1.2", // md2WithRSAEncryption
        "1.2.840.113549.1.1.3", // md4WithRSAEncryption
        "1.2.840.113549.1.1.4", // md5WithRSAEncryption
    ];
    for e in certval_stores_msft::provider().entries() {
        for root in e.roots {
            let cert = Certificate::from_der(root).expect("a carried root must decode");
            let oid = cert.signature_algorithm().oid.to_string();
            assert!(
                !OBSOLETE.contains(&oid.as_str()),
                "{} carries a root signed with {oid}, which certval cannot verify",
                e.id
            );
        }
    }
}

/// Every environment named by the provider can be prepared into a `PkiEnvironment`.
#[test]
fn environments_prepare() {
    let failures = conformance::check_prepare_environment(certval_stores_msft::provider());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

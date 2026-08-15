//! Does `check_root_inputs` fail when a `roots/` directory and the anchors a
//! provider embeds stop agreeing?
//!
//! The provider crates cover the passing side with their real material. What
//! they cannot cover is the failing side, because a repository whose roots have
//! drifted is exactly what this check exists to prevent from being committed.
//! Real anchors are not needed to demonstrate it: the check compares encodings,
//! and parses one only to label a failure, so these use short byte strings
//! standing in for certificates and write them where Cargo hands the test a
//! scratch directory.

#![cfg(feature = "test-util")]

use std::fs;
use std::path::{Path, PathBuf};

use certval_stores_core::conformance::check_root_inputs;

const ROOT_A: &[u8] = b"anchor-a";
const ROOT_B: &[u8] = b"anchor-b";

/// A directory under Cargo's per-test scratch space holding the named files.
/// Recreated on each call, so a leftover from a previous run cannot mask a
/// result.
fn roots_dir(case: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(case);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch directory must be creatable");
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes).expect("scratch file must be writable");
    }
    dir
}

#[test]
fn a_directory_matching_the_embedded_anchors_passes() {
    let dir = roots_dir("agree", &[("a.der", ROOT_A), ("b.der", ROOT_B)]);
    let failures = check_root_inputs(&dir, &[ROOT_A, ROOT_B]);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The direction the compiler cannot catch, and the reason this check exists: a
/// `.der` added to the directory and left out of the `include_bytes!` list ships
/// looking like part of the trust set without being in it.
#[test]
fn an_anchor_on_disk_that_is_not_embedded_is_reported() {
    let dir = roots_dir("unembedded", &[("a.der", ROOT_A), ("b.der", ROOT_B)]);
    let failures = check_root_inputs(&dir, &[ROOT_A]);
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(failures[0].contains("b.der"), "{failures:#?}");
    assert!(
        failures[0].contains("include_bytes! list needs updating"),
        "{failures:#?}"
    );
}

/// The other direction. A build reaches this state only through a stale
/// `include_bytes!` path resolving elsewhere, but the check is cheap and the
/// failure is precise.
#[test]
fn an_embedded_anchor_with_no_file_is_reported() {
    let dir = roots_dir("missing_file", &[("a.der", ROOT_A)]);
    let failures = check_root_inputs(&dir, &[ROOT_A, ROOT_B]);
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(
        failures[0].contains("has no corresponding file"),
        "{failures:#?}"
    );
}

/// `.cer` counts as well as `.der`, and anything else in the directory — a
/// README, a `.p7c` the material was extracted from — is not an anchor and must
/// not be reported as one.
#[test]
fn extensions_decide_what_counts_as_an_anchor() {
    let dir = roots_dir(
        "extensions",
        &[
            ("a.CER", ROOT_A),
            ("notes.txt", b"not a certificate"),
            ("bundle.p7c", b"not a certificate either"),
        ],
    );
    let failures = check_root_inputs(&dir, &[ROOT_A]);
    assert!(failures.is_empty(), "{failures:#?}");
}

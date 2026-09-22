//! Keeps this crate's committed material in step with the cabinet it comes from.
//!
//! What the two halves do, and why the gate is a file rather than a feature, is in
//! `certval_store_gen::tpm_refresh` -- including why the expensive check that the shipped store is
//! the validated output of the committed cabinet lives in this crate's tests instead of here.

use certval_store_gen::build_log;
use certval_store_gen::tpm_refresh::run;

/// Created by hand in a working tree to allow a refresh, and never committed, so no checkout of
/// this repository carries it.
const REFRESH_SENTINEL: &str = "refresh-inputs";

/// The one environment this crate serves. Names the directories under `roots/`, `cas/` and
/// `provenance/`, and the CBOR store inside `cas/tpm/`.
const ENV: &str = "tpm";

fn main() {
    build_log::init(log::LevelFilter::Warn).ok();
    run(REFRESH_SENTINEL, ENV);
}

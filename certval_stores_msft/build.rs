//! Keeps this crate's committed material in step with the Microsoft trust list it comes from.
//!
//! What the two halves do, and why the gate is a file rather than a feature, is in
//! `certval_store_gen::build_refresh`. This is the table it runs on.
//!
//! Unlike the InstallRoot providers next door, a refresh here is a conditional request first:
//! the list changes about monthly, so all but roughly one build a month ends at a 304 without
//! reading or writing anything.

use certval_store_gen::authroot_refresh::{run, Env};
use certval_store_gen::build_log;

/// Created by hand in a working tree to allow a refresh, and never committed, so no checkout of
/// this repository carries it.
const REFRESH_SENTINEL: &str = "refresh-inputs";

/// Where Microsoft publishes the list this crate generates from. Recorded here rather than only
/// in the generator because it is this crate's provenance: a reader asking where the material
/// came from should find the answer beside the material.
const PUBLISHED_AT: &str =
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";

/// The environments, and the purpose each one filters the list by. `None` takes every root the
/// program still trusts.
///
/// The generator applies the two exclusions -- expired, and restricted past their disallowed
/// date -- to every environment alike, so they are not repeated here: they are properties of what
/// this crate carries at all, not of any one view over it.
const ENVS: &[Env] = &[
    Env {
        name: "all",
        eku: None,
    },
    Env {
        name: "tls",
        eku: Some("1.3.6.1.5.5.7.3.1"),
    },
    Env {
        name: "client_auth",
        eku: Some("1.3.6.1.5.5.7.3.2"),
    },
    Env {
        name: "email",
        eku: Some("1.3.6.1.5.5.7.3.4"),
    },
    Env {
        name: "code_signing",
        eku: Some("1.3.6.1.5.5.7.3.3"),
    },
    Env {
        name: "timestamping",
        eku: Some("1.3.6.1.5.5.7.3.8"),
    },
];

fn main() {
    // The generator narrates through `log` and picks no destination; this is what makes it reach
    // a person building the crate.
    build_log::init(log::LevelFilter::Warn).ok();
    run(REFRESH_SENTINEL, PUBLISHED_AT, ENVS);
}

//! Keeps this crate's committed material in step with the InstallRoot stream it comes from.
//!
//! What the two halves do, and why the gate is a file rather than a feature, is in
//! `certval_store_gen::build_refresh`. This is the table it runs on.

use certval_store_gen::adapters::tamp::Population;
use certval_store_gen::build_log;
use certval_store_gen::build_refresh::{run, Env};

/// Created by hand in a working tree to allow a refresh, and never committed, so no checkout of
/// this repository carries it.
const REFRESH_SENTINEL: &str = "refresh-inputs";

/// Where DISA publishes the stream this crate generates from.
const PUBLISHED_AT: &str = "https://crl.gds.disa.mil/pke/config";

/// One environment, and everything it needs is in the stream: unlike the interoperability
/// environments next door, ECA publishes its own anchors through InstallRoot.
///
/// `ECA.ir4` is signed by the same DISA code-signing population as `DoD.ir4`, so its signer
/// chains to a *DoD* root rather than to either of the ECA roots this crate carries. That is why
/// the anchors a stream is verified against are pinned in the generator and not taken from the
/// crate being generated.
const ENVS: &[Env] = &[Env {
    name: "prod",
    stream: "ECA.ir4",
    population: Population::Eca,
    extra_roots: &[],
    extra_cas: &[],
}];

fn main() {
    // The generator narrates through `log` and picks no destination; this is what makes it
    // reach a person building the crate.
    build_log::init(log::LevelFilter::Warn).ok();
    run(REFRESH_SENTINEL, PUBLISHED_AT, ENVS);
}

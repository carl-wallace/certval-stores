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

/// One environment, and `WCF.ir4` publishes nothing else: one stream, one PKI, unlike `JITC.ir4`.
///
/// `Population::Wcf` rather than `Dod` even so. WCF anchors sit under `OU=DoD` and would classify
/// as DoD material, which is accurate and useless: naming the population is what keeps this store
/// and `certval_stores_nipr` from being able to take each other's anchors if DISA ever publishes
/// them in one stream.
const ENVS: &[Env] = &[Env {
    name: "prod",
    stream: "WCF.ir4",
    population: Population::Wcf,
    extra_roots: &[],
    extra_cas: &[],
}];

fn main() {
    // The generator narrates through `log` and picks no destination; this is what makes it
    // reach a person building the crate.
    build_log::init(log::LevelFilter::Warn).ok();
    run(REFRESH_SENTINEL, PUBLISHED_AT, ENVS);
}

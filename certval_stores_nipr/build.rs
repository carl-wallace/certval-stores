//! Keeps this crate's committed material in step with the InstallRoot streams it comes from.
//!
//! What the two halves do, and why the gate is a file rather than a feature, is in
//! `certval_store_gen::build_refresh`. This is the table it runs on.

use certval_store_gen::adapters::tamp::Population;
use certval_store_gen::build_log;
use certval_store_gen::build_refresh::{run, Env};

/// Created by hand in a working tree to allow a refresh, and never committed, so no checkout of
/// this repository carries it.
const REFRESH_SENTINEL: &str = "refresh-inputs";

/// Where DISA publishes the streams this crate generates from.
const PUBLISHED_AT: &str = "https://crl.gds.disa.mil/pke/config";

/// The interoperability environments are NIPR plus exactly two things: a cross-certified root,
/// and the bundle that root publishes at its own SIA. Neither appears in any `.ir4` message --
/// the stream carries their cross-certificates only in `Untrusted`, which is InstallRoot's
/// *disallowed* store -- so both are committed here and named below. They are the part of this
/// crate a refresh cannot touch, and the reason its `include_bytes!` lists stay hand-written.
const ENVS: &[Env] = &[
    Env {
        name: "prod",
        stream: "DoD.ir4",
        population: Population::Dod,
        extra_roots: &[],
        extra_cas: &[],
    },
    // JITC publishes the operational-test material for the same population.
    Env {
        name: "om",
        stream: "JITC.ir4",
        population: Population::Dod,
        extra_roots: &[],
        extra_cas: &[],
    },
    Env {
        name: "interop",
        stream: "DoD.ir4",
        population: Population::Dod,
        extra_roots: &["inputs/DoD_Interoperability_Root_CA_2.der"],
        extra_cas: &["inputs/DODINTEROPERABILITYROOTCA2_IB.p7c"],
    },
    Env {
        name: "cceb_interop",
        stream: "DoD.ir4",
        population: Population::Dod,
        extra_roots: &["inputs/US_DoD_CCEB_Interoperability_Root_CA_2.der"],
        extra_cas: &["inputs/USDODCCEBINTEROPERABILITYROOTCA2_IB.p7c"],
    },
];

fn main() {
    // The generator narrates through `log` and picks no destination; this is what makes it
    // reach a person building the crate.
    build_log::init(log::LevelFilter::Warn).ok();
    run(REFRESH_SENTINEL, PUBLISHED_AT, ENVS);
}

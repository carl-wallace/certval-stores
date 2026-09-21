//! Web PKI adapter.
//!
//! Trust anchors come from the compiled-in Mozilla roots (webpki-roots, via certval's
//! `TaSource::new_from_webpki`). Intermediates come from one of:
//! - nothing (roots-only store),
//! - a folder of CA certificates (DER/PEM), or
//! - a CCADB "All Intermediate Certs (with PEM)" CSV export (the canonical Web PKI set).
//!
//! This is the optimization layer for the wasm client: preloading intermediates lets a
//! chain build without a just-in-time AIA fetch (a round trip to fetch the issuer's
//! certificate), and it works for servers that omit AIA altogether. Once the fetch proxy
//! lands, AIA becomes the fallback for anything not preloaded here.

use std::path::Path;

use anyhow::{anyhow, Result};

use certval::{PkiEnvironment, TaSource, TimeOfInterest};

use crate::adapters::ccadb::read_ccadb_csv;
use crate::core::StoreInputs;
use crate::ingest::read_intermediates_dir;

/// Source of Web PKI intermediate certificates.
pub enum Intermediates<'a> {
    /// No preloaded intermediates (roots-only store).
    None,
    /// A folder of CA certificates in DER/PEM.
    Dir(&'a str),
    /// A CCADB CSV export; `include_expired` keeps certs outside their validity window,
    /// `now_unix` is the reference time for the validity filter.
    CcadbCsv {
        path: &'a Path,
        include_expired: bool,
        now_unix: u64,
    },
}

/// Build Web PKI store inputs: Mozilla roots + the selected intermediate source.
pub fn build(
    pe: &PkiEnvironment,
    source: Intermediates,
    toi: TimeOfInterest,
) -> Result<StoreInputs> {
    let wp =
        TaSource::new_from_webpki().map_err(|e| anyhow!("failed to load webpki roots: {e:?}"))?;
    let trust_anchors = wp.get_tas();
    if trust_anchors.is_empty() {
        return Err(anyhow!("webpki-roots produced no trust anchors"));
    }

    let intermediates = match source {
        Intermediates::None => Vec::new(),
        Intermediates::Dir(dir) => read_intermediates_dir(pe, dir, toi)?,
        Intermediates::CcadbCsv {
            path,
            include_expired,
            now_unix,
        } => read_ccadb_csv(path, include_expired, now_unix)?,
    };

    Ok(StoreInputs {
        trust_anchors,
        intermediates,
        // The CCADB report is a live query rather than a dated release, so the only
        // date it supports is the day it was fetched, which the caller supplies.
        published: None,
    })
}

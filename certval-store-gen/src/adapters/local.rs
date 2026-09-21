//! Local-folders adapter — a folder of trust-anchor certs and a folder of intermediate
//! CA certs, both DER/PEM.
//!
//! This is the collection-agnostic path: whatever assembled the two folders (a CCADB
//! export, a hand-curated DoD set, the output of a future TAMP/AIA collector), this turns
//! them into a `ta.cbor` / `ca.cbor` pair. The intermediates folder is filtered of
//! self-signed certs (see [`read_intermediates_dir`]); the trust-anchors folder keeps
//! self-signed roots.

use anyhow::Result;

use certval::{PkiEnvironment, TimeOfInterest};

use crate::core::StoreInputs;
use crate::ingest::{read_intermediates_dir, read_ta_dir};

/// Build store inputs from a trust-anchor folder and an optional intermediates folder.
pub fn build(
    pe: &PkiEnvironment,
    ta_dir: &str,
    ca_dir: Option<&str>,
    toi: TimeOfInterest,
) -> Result<StoreInputs> {
    let trust_anchors = read_ta_dir(pe, ta_dir, toi)?;
    let intermediates = match ca_dir {
        Some(dir) => read_intermediates_dir(pe, dir, toi)?,
        None => Vec::new(),
    };
    Ok(StoreInputs {
        trust_anchors,
        intermediates,
        // Folders of DER state nothing about when they were published.
        published: None,
    })
}

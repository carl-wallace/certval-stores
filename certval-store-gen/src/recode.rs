//! Rewriting an existing store in certval's current CBOR encoding.
//!
//! `CertFile::bytes` used to serialize as one CBOR integer per octet, because `Vec<u8>` has no
//! distinguished representation in serde. certval now writes a byte string and reads either form,
//! so a store generated before that change still loads but carries roughly 1.8x the bytes it needs.
//!
//! This converts one in place. It is deliberately not a regeneration: the store is deserialized and
//! serialized back, so the certificates and the partial-path graph — including its ordering, which
//! path rows refer to by index — come through untouched and the encoding is the only difference.
//! Re-collecting the material instead would answer a different question, and for the stores built
//! from a crawler bundle or a CCADB export there is nothing on disk to re-collect from.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use certval::BuffersAndPaths;

/// What the conversion did, for reporting.
pub struct Recoded {
    pub certificates: usize,
    pub path_rows: usize,
    pub before: usize,
    pub after: usize,
}

/// Read the store at `path`, rewrite it in the current encoding, and return what changed.
///
/// The certificate set is compared across the round trip rather than assumed: a reader that quietly
/// dropped a buffer would otherwise shrink the file and look like a success.
pub fn recode(path: &Path, write: bool) -> Result<Recoded> {
    let before =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    let store: BuffersAndPaths = ciborium::de::from_reader(before.as_slice())
        .map_err(|e| anyhow!("{} is not a certval CBOR store: {e}", path.display()))?;

    let certificates: BTreeSet<Vec<u8>> = store.buffers.iter().map(|b| b.bytes.clone()).collect();
    let path_rows = store.partial_paths.len();

    let mut after = vec![];
    ciborium::ser::into_writer(&store, &mut after)
        .map_err(|e| anyhow!("failed to serialize {}: {e}", path.display()))?;

    let round_trip: BuffersAndPaths = ciborium::de::from_reader(after.as_slice())
        .map_err(|e| anyhow!("the rewritten store does not read back: {e}"))?;
    let round_trip_certificates: BTreeSet<Vec<u8>> =
        round_trip.buffers.iter().map(|b| b.bytes.clone()).collect();
    if round_trip_certificates != certificates {
        return Err(anyhow!(
            "{}: the rewritten store holds a different certificate set ({} vs {})",
            path.display(),
            round_trip_certificates.len(),
            certificates.len()
        ));
    }
    if round_trip.partial_paths != store.partial_paths {
        return Err(anyhow!(
            "{}: the rewritten store's partial paths differ",
            path.display()
        ));
    }

    if write {
        std::fs::write(path, &after)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(Recoded {
        certificates: certificates.len(),
        path_rows,
        before: before.len(),
        after: after.len(),
    })
}

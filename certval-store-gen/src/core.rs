//! Shared generation core.
//!
//! Every input adapter normalizes its source (Web PKI roots + CCADB intermediates,
//! a DoD TAMP message, an FPKI PKCS#7 bundle) into the same shape: a set of
//! self-signed trust anchors and a set of intermediate CA certificates. This module
//! turns that shape into the two CBOR stores that pittv3 (desktop and wasm) consume:
//!
//! * `ta.cbor`  — trust-anchor buffers, no partial paths. Loaded via
//!   [`certval::TaSource::new_from_cbor`].
//! * `ca.cbor`  — intermediate buffers plus all precomputed partial certification
//!   paths. Loaded via [`certval::CertSource::new_from_cbor`].
//!
//! The two-store split and serialization mirror `certval::build_graph` exactly (the
//! path pittv3 `--generate` drives), so the outputs drop straight into the pittv3
//! store fetch path with no format special-casing.

use std::collections::BTreeSet;

use anyhow::{anyhow, Result};

use certval::{
    BuffersAndPaths, CertFile, CertSource, CertVector, CertificationPathBuilderFormats,
    CertificationPathSettings, PkiEnvironment, TaSource, TimeOfInterest,
};

/// Normalized adapter output: the raw material for a store pair.
#[derive(Default, Clone)]
pub struct StoreInputs {
    /// Self-signed roots (DER-encoded certificates) destined for `ta.cbor`.
    pub trust_anchors: Vec<CertFile>,
    /// Non-self-signed CA certificates (DER-encoded) destined for `ca.cbor`.
    pub intermediates: Vec<CertFile>,
    /// The date the source itself states it published this material, `YYYY-MM-DD`,
    /// where the source states one.
    ///
    /// Only a signed or dated artifact can answer: the `installroot` adapter reads it
    /// from `TSTInfo.genTime` in the verified RFC 3161 timestamp on the stream's members,
    /// falling back to a `signingTime` for a publisher that asserts one (DoD asserts none),
    /// while an adapter handed a folder of DER or an
    /// undated bundle leaves it `None`. It reaches a provider crate as
    /// `certval_stores_core::StoreEntry::published`, which is shown to a user as how
    /// current the trust material is — so a guess here would be worse than nothing.
    pub published: Option<String>,
}

/// The generated CBOR stores. `ca_cbor` is `None` when no intermediates were supplied
/// (e.g. a roots-only Web PKI store), since an empty partial-path graph is not useful.
pub struct GeneratedStore {
    pub ta_cbor: Vec<u8>,
    pub ca_cbor: Option<Vec<u8>>,
}

/// Build the `ta.cbor` / `ca.cbor` pair from normalized inputs.
pub fn generate(inputs: &StoreInputs) -> Result<GeneratedStore> {
    if inputs.trust_anchors.is_empty() {
        return Err(anyhow!(
            "no trust anchors supplied; a ta.cbor store needs at least one self-signed root"
        ));
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut cps = CertificationPathSettings::new();
    // Web PKI roots (and many enterprise roots) do not assert a validity window we want
    // to gate on at generation time; validity is a validation-time concern for the
    // consumer. Matches pittv3's webpki-tas handling.
    cps.set_enforce_trust_anchor_validity(false);
    // Same reason, applied to the intermediates. The default time of interest is now, and
    // find_all_partial_paths skips a certificate that is expired relative to it — so an
    // expired CA would be serialized as a buffer with no path to its root, and a consumer
    // validating against an earlier time of interest would find nothing for it. A store
    // records what a PKI published; deciding whether a certificate is still current is the
    // consumer's job, and it cannot do that job for a path the store never recorded.
    cps.set_time_of_interest(TimeOfInterest::disabled());

    // Normalize the per-cert filename label to a basename before serializing. Folder-based
    // adapters mint CertFiles carrying the absolute source path, which would (a) bake the
    // build machine's directory layout and username into the shipped store, (b) make the
    // output non-deterministic across machines (defeating reproducible generation), and
    // (c) add dead bytes. The label is only ever surfaced in logs/reports (path building
    // indexes by SKID/name and CertFile equality ignores it), so a basename keeps a useful
    // label while dropping the leak and the nondeterminism.
    let trust_anchors = normalize_labels(&inputs.trust_anchors);
    let intermediates = normalize_labels(&inputs.intermediates);

    // 1. ta.cbor — serialize the trust-anchor buffers with no partial paths. This mirrors
    //    build_graph's `cbor_ta_store` branch (a CertSource populated with the TA buffers,
    //    serialized without find_all_partial_paths).
    let mut ta_store = CertSource::new();
    for cf in &trust_anchors {
        if !ta_store.contains(cf) {
            ta_store.push(cf.clone());
        }
    }
    ta_store
        .initialize(&cps)
        .map_err(cv("initialize ta store"))?;
    let ta_cbor = ta_store
        .serialize(CertificationPathBuilderFormats::Cbor)
        .map_err(cv("serialize ta.cbor"))?;

    // 2. Register the trust anchors in the environment. find_all_partial_paths consults
    //    pe.get_trust_anchor_for_target to know where intermediate chains terminate, so the
    //    TAs must be present as a TaSource before the graph is built.
    let mut ta_source = TaSource::new();
    for cf in &trust_anchors {
        if !ta_source.contains(cf) {
            ta_source.push(cf.clone());
        }
    }
    ta_source.initialize().map_err(cv("initialize ta source"))?;
    pe.add_trust_anchor_source(Box::new(ta_source));

    // 3. ca.cbor — intermediates plus every partial certification path. Skipped when there
    //    are no intermediates (roots-only store).
    let ca_cbor = if intermediates.is_empty() {
        None
    } else {
        let mut ca_store = CertSource::new();
        for cf in &intermediates {
            if !ca_store.contains(cf) {
                ca_store.push(cf.clone());
            }
        }
        ca_store
            .initialize(&cps)
            .map_err(cv("initialize ca store"))?;
        ca_store.find_all_partial_paths(&pe, &cps);
        let bytes = ca_store
            .serialize(CertificationPathBuilderFormats::Cbor)
            .map_err(cv("serialize ca.cbor"))?;
        Some(bytes)
    };

    Ok(GeneratedStore { ta_cbor, ca_cbor })
}

/// Drop intermediates that reach no trust anchor, and report which.
///
/// A store records what a PKI published, so this is not a judgement about the certificates: it is
/// that `conformance::check_partial_paths` requires every CA in a store to appear in some path,
/// and a CA that chains to nothing cannot. Carrying it would ship a store that fails its own
/// checks, and the alternative -- relaxing the check -- would give up the property that catches a
/// genuinely broken generation.
///
/// The publisher is not always wrong to publish one. `TrustedTpm.cab` carries thirty-odd AMD
/// intermediates whose issuers it does not include, and whose AIA URIs serve a self-signed
/// certificate rather than the issuer; those CAs are real, but this TA set simply cannot root
/// them. That is why the names come back rather than being logged and forgotten: a provider crate
/// records them, so the count is reviewable and a publisher fixing it shows up as a change.
///
/// Costs a generation pass, since which buffers are in a path is only knowable after the graph is
/// built. Matching is by certificate bytes rather than by index: `generate` deduplicates, so
/// buffer positions do not correspond to input positions.
pub fn prune_unrooted(inputs: &StoreInputs) -> Result<(StoreInputs, Vec<String>)> {
    if inputs.intermediates.is_empty() {
        return Ok((inputs.clone(), vec![]));
    }
    let Some(cbor) = generate(inputs)?.ca_cbor else {
        return Ok((inputs.clone(), vec![]));
    };
    let bap: BuffersAndPaths = ciborium::de::from_reader(cbor.as_slice())
        .map_err(|e| anyhow!("the generated CA store did not read back: {e}"))?;

    let mut in_a_path = vec![false; bap.buffers.len()];
    for row in bap.partial_paths.iter() {
        for paths in row.values() {
            for path in paths {
                for i in path {
                    if let Some(seen) = in_a_path.get_mut(*i) {
                        *seen = true;
                    }
                }
            }
        }
    }
    let rooted: BTreeSet<&[u8]> = bap
        .buffers
        .iter()
        .zip(&in_a_path)
        .filter(|(_, seen)| **seen)
        .map(|(buffer, _)| buffer.bytes.as_slice())
        .collect();

    let mut kept = vec![];
    let mut dropped = vec![];
    for cf in &inputs.intermediates {
        match rooted.contains(cf.bytes.as_slice()) {
            true => kept.push(cf.clone()),
            false => dropped.push(cf.filename.clone()),
        }
    }
    dropped.sort();
    Ok((
        StoreInputs {
            intermediates: kept,
            ..inputs.clone()
        },
        dropped,
    ))
}

/// Return a copy of `certs` with each `filename` reduced to its basename, so no absolute
/// path (and no build-machine directory layout) ends up in the serialized store. Labels
/// that are already path-free (e.g. an adapter-supplied subject string) are unchanged.
fn normalize_labels(certs: &[CertFile]) -> Vec<CertFile> {
    certs
        .iter()
        .map(|cf| CertFile {
            filename: basename(&cf.filename),
            bytes: cf.bytes.clone(),
        })
        .collect()
}

/// The final path component, splitting on both `/` and `\\` so Windows-style paths are
/// handled too. Non-path labels pass through unchanged.
fn basename(label: &str) -> String {
    label
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(label)
        .to_string()
}

/// Adapt a `certval::Error` (which is not `std::error::Error`) into an `anyhow::Error`
/// with a bit of context about the failing step.
fn cv(ctx: &'static str) -> impl FnOnce(certval::Error) -> anyhow::Error {
    move |e| anyhow!("{ctx}: {e:?}")
}

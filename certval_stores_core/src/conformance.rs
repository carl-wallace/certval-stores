//! Reusable conformance checks over the expectations a [`TrustStoreProvider`]'s
//! material must satisfy — the part of the contract the trait cannot express.
//!
//! Enabled by the `test-util` feature and intended for use from provider
//! crates' integration tests:
//!
//! ```no_run
//! # #[cfg(feature = "test-util")]
//! # fn main() {
//! # let provider: &dyn certval_stores_core::TrustStoreProvider = unimplemented!();
//! certval_stores_core::conformance::assert_conformant(provider);
//! # }
//! # #[cfg(not(feature = "test-util"))]
//! # fn main() {}
//! ```
//!
//! Living here rather than in each provider crate means the private providers
//! (e.g. `certval_stores_sipr`) get the same coverage without a copy of the
//! logic landing in a private repository, and a check added here applies to
//! every community at once.
//!
//! Each `check_*` function returns a list of human-readable failures — an empty
//! list means the check passed — so a caller can run one check in isolation or
//! aggregate them all with [`conformance_failures`]. The checks are deliberately
//! **time-independent**: material is parsed with the time of interest disabled,
//! so an expired-but-well-formed CA reads as a stale store (a separate concern,
//! visible in the store's refresh procedure) rather than as a corrupt one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use certval::{
    get_leaf_rdn, hex_skid_from_cert, name_to_string, parse_cert, BuffersAndPaths, CertFile,
    CertSource, CertVector, CertificationPathResults, CertificationPathSettings, Error,
    PkiEnvironment, TaSource, TimeOfInterest,
};

#[cfg(feature = "reqwest-client")]
use crate::get_reqwest_client;
use crate::{prepare_certval_environment, StoreEntry, TrustStoreProvider};

/// A store's contents in a form this crate can build and edit.
///
/// [`certval::BuffersAndPaths`] is `#[readonly::make]`: its fields read from outside but neither
/// construct nor mutate, and both are needed to *break* a store on purpose — which is the only way
/// to show that the checks below actually bite. The serde shape here is the same, so this reads and
/// writes exactly the bytes certval does; nothing in it is a second opinion about the format.
///
/// For tests. A provider's real material is produced by the generator, never by this.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RawStore {
    /// The certificates the store carries.
    pub buffers: Vec<CertFile>,
    /// Partial certification paths, as indices into `buffers` keyed by the leaf CA's key
    /// identifier.
    pub partial_paths: certval::PartialPaths,
}

impl RawStore {
    /// Read a serialized store.
    pub fn from_cbor(cbor: &[u8]) -> Self {
        ciborium::de::from_reader(cbor).expect("store must deserialize")
    }

    /// Serialize, leaking the bytes because [`StoreEntry`] holds `'static` material — which is what
    /// `include_bytes!` gives the real providers.
    pub fn into_static_cbor(self) -> &'static [u8] {
        let mut cbor = vec![];
        ciborium::ser::into_writer(&self, &mut cbor).expect("store must serialize");
        Box::leak(cbor.into_boxed_slice())
    }
}

/// Environment name no provider may serve, used to confirm that an unrecognized
/// environment is rejected rather than silently served.
const NO_SUCH_ENV: &str = "__CONFORMANCE_NO_SUCH_ENV__";

/// Settings for structural parsing: time-of-interest checks disabled, so
/// [`CertSource::initialize`] drops a buffer only when it fails to decode.
fn structural_settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::disabled());
    cps
}

/// Load and initialize an entry's CA store for structural inspection.
fn load_store(cbor: &[u8]) -> Result<CertSource, Error> {
    let mut cert_source = CertSource::new_from_cbor(cbor)?;
    cert_source.initialize(&structural_settings())?;
    Ok(cert_source)
}

/// Subject name of a DER-encoded certificate, in the canonical form used to key
/// the maps below, or `None` if it does not parse.
fn subject_name(der: &[u8]) -> Option<String> {
    parse_cert(der, "")
        .ok()
        .map(|c| name_to_string(c.decoded().tbs_certificate().subject()))
}

/// Check the shape of the entries a provider yields: usable environment labels
/// and at least one non-empty trust anchor.
///
/// The `env` string is the match key in [`prepare_certval_environment`], so a
/// typo or stray whitespace there means the provider silently serves nothing.
pub fn check_entry_shape(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    let mut seen = BTreeSet::new();
    for entry in provider.entries() {
        let env = entry.env;
        if env.trim().is_empty() {
            failures.push("an entry carries an empty env label".to_string());
        } else if env != env.trim() {
            failures.push(format!(
                "env label {env:?} has leading or trailing whitespace; it would never match a caller's environment string"
            ));
        }
        if !seen.insert(env) {
            failures.push(format!(
                "env label {env:?} is carried by more than one entry"
            ));
        }
        if entry.roots.is_empty() {
            failures.push(format!("entry {env:?} carries no trust anchors"));
        } else {
            for (i, root) in entry.roots.iter().enumerate() {
                if root.is_empty() {
                    failures.push(format!("entry {env:?} root {i} is empty"));
                }
            }
        }
        // The dates are shown to a user as a statement about how current the material
        // is, so a malformed one is worse than none: it reads as an answer. Both are
        // written by the generator into files the provider `include_str!`s, which is
        // where a stray newline or a half-finished hand edit would arrive from.
        for (what, value) in [
            ("published", entry.published),
            ("collected", entry.collected),
        ] {
            let Some(value) = value else {
                continue;
            };
            if !is_iso_date(value) {
                failures.push(format!(
                    "entry {env:?} {what} date {value:?} is not an ISO 8601 calendar date (YYYY-MM-DD)"
                ));
            }
        }
        // Lexicographic comparison is a date comparison for this format, which is most
        // of why the format is required above. Collecting material before its publisher
        // published it is not a thing that happened, so one of the two is wrong.
        if let (Some(published), Some(collected)) = (entry.published, entry.collected) {
            if is_iso_date(published) && is_iso_date(collected) && published > collected {
                failures.push(format!(
                    "entry {env:?} says it was published {published} and collected {collected}, which is before it existed"
                ));
            }
        }
    }
    failures
}

/// Whether `value` is a `YYYY-MM-DD` calendar date.
///
/// Syntax and range only: this rejects `2026-13-01` and `2026-08-32`, and accepts
/// `2026-02-31`, which no publisher emits and which nothing here would do anything
/// different about. A full calendar is not worth carrying to check a date a human
/// reads.
fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let part = |from: usize, to: usize| value[from..to].parse::<u32>().unwrap_or(0);
    (1..=12).contains(&part(5, 7)) && (1..=31).contains(&part(8, 10))
}

/// Check that every trust anchor parses as an x509-cert `Certificate` (the
/// certval path-building leg) and, under the `reqwest-client` feature, as a
/// `reqwest::Certificate` (the TLS leg).
///
/// The reqwest leg is load-bearing where it applies: [`get_reqwest_client`] logs
/// and continues when a root fails to parse, so an unparseable root silently
/// shrinks the trust set of every client the provider configures instead of
/// failing the build. Building without that feature drops the check but not the
/// expectation — a consumer that adds a client later inherits the same
/// requirement, so run the suite with default features before publishing
/// material.
pub fn check_roots_parse(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let mut seen: BTreeMap<&[u8], usize> = BTreeMap::new();
        for (i, root) in entry.roots.iter().enumerate() {
            match parse_cert(root, env) {
                Ok(_cert) => {
                    #[cfg(feature = "reqwest-client")]
                    {
                        let label = get_leaf_rdn(_cert.decoded().tbs_certificate().subject());
                        if reqwest::Certificate::from_der(root).is_err() {
                            failures.push(format!(
                                "entry {env:?} root {i} ({label}) parses as a certificate but is rejected by reqwest, so TLS clients would silently omit it"
                            ));
                        }
                    }
                }
                Err(e) => failures.push(format!("entry {env:?} root {i} failed to parse: {e:?}")),
            }
            if let Some(prev) = seen.insert(root, i) {
                failures.push(format!(
                    "entry {env:?} roots {prev} and {i} are the same certificate"
                ));
            }
        }
    }
    failures
}

/// Check that every embedded CA store deserializes, initializes, is non-empty,
/// and that every buffer it carries decodes as a certificate.
///
/// A truncated or corrupted CBOR blob fails here rather than at a consumer's
/// first path build.
pub fn check_cert_stores_load(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let Some(cbor) = entry.cert_store_cbor else {
            continue;
        };
        let cert_source = match load_store(cbor) {
            Ok(cert_source) => cert_source,
            Err(e) => {
                failures.push(format!("entry {env:?} CA store failed to load: {e:?}"));
                continue;
            }
        };
        if cert_source.num_buffers() == 0 {
            failures.push(format!("entry {env:?} carries an empty CA store"));
        }
        let buffers = cert_source.get_buffers();
        for (i, cert) in cert_source.certs().iter().enumerate() {
            if cert.is_none() {
                let filename = buffers
                    .get(i)
                    .map(|b| b.filename.clone())
                    .unwrap_or_default();
                failures.push(format!(
                    "entry {env:?} CA store buffer {i} ({filename}) failed to decode"
                ));
            }
        }
    }
    failures
}

/// Check the partial paths serialized alongside a store's buffers.
///
/// A store whose CAs are merely *connected* to its anchors would still build
/// paths dynamically; what an offline consumer actually uses is the serialized
/// path set, so that is what this checks:
///
/// - **Every CA appears in some path.** A CA in none of them is dead weight the
///   path builder will never reach, which is what a store regenerated against
///   stale inputs looks like.
/// - **Every path starts at a CA one of the entry's own anchors issued.** Purge
///   an anchor without regenerating and the paths still deserialize, still look
///   populated, and lead somewhere the consumer cannot anchor.
/// - **Every index names a buffer the store carries.** `get_paths_for_target`
///   indexes its parsed-certificate vector with these directly.
/// - **Every path's key is the SKID of its own leaf CA.** That key is how
///   `get_paths_for_target` finds paths — it looks up the target's AKID — so a
///   path filed under the wrong key is unreachable for exactly the targets it
///   exists to serve, in a store that otherwise looks fully populated.
/// - **Row *i* holds paths of length *i+1*.** How `find_all_partial_paths`
///   builds them: row 0 is the CAs an anchor issued, and each later pass extends
///   the row before it by one certificate. Nothing in the read path relies on
///   this, but a store that violates it was not built by that generator, and
///   regenerating from it would extend the wrong row and mis-apply the depth cap.
pub fn check_partial_paths(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let Some(cbor) = entry.cert_store_cbor else {
            continue;
        };
        // The same bytes CertSource::new_from_cbor reads, deserialized directly
        // because CertSource exposes its buffers but not its partial paths.
        let bap: BuffersAndPaths = match ciborium::de::from_reader(cbor) {
            Ok(bap) => bap,
            Err(_) => continue, // check_cert_stores_load reports the load failure
        };

        let anchor_subjects: BTreeSet<String> =
            entry.roots.iter().filter_map(|r| subject_name(r)).collect();
        let label = |i: usize| -> String {
            match bap.buffers.get(i) {
                Some(buffer) => match parse_cert(&buffer.bytes, "") {
                    Ok(cert) => get_leaf_rdn(cert.decoded().tbs_certificate().subject()),
                    Err(_) => buffer.filename.clone(),
                },
                None => format!("buffer {i}"),
            }
        };

        if bap.partial_paths.is_empty() && !bap.buffers.is_empty() {
            failures.push(format!(
                "entry {env:?} carries {} CAs but no serialized partial paths at all",
                bap.buffers.len()
            ));
            continue;
        }

        // A buffer that does not parse is reported by check_cert_stores_load;
        // the checks below that need a parsed certificate skip it rather than
        // reporting the same broken buffer twice.
        let cert_at = |i: usize| {
            bap.buffers
                .get(i)
                .and_then(|buffer| parse_cert(&buffer.bytes, "").ok())
        };

        let mut in_a_path = vec![false; bap.buffers.len()];
        let mut out_of_range: BTreeSet<usize> = BTreeSet::new();
        let mut unanchored: BTreeSet<usize> = BTreeSet::new();
        let mut miskeyed: BTreeSet<(String, usize)> = BTreeSet::new();
        let mut mislevelled: BTreeSet<(usize, usize)> = BTreeSet::new();
        for (row, outer) in bap.partial_paths.iter().enumerate() {
            for (key, paths) in outer {
                for path in paths {
                    for i in path {
                        match in_a_path.get_mut(*i) {
                            Some(seen) => *seen = true,
                            None => {
                                out_of_range.insert(*i);
                            }
                        }
                    }
                    if path.len() != row + 1 {
                        mislevelled.insert((row, path.len()));
                    }
                    // A path runs anchor-ward first, so its head is the CA the
                    // trust anchor issued and its tail is the leaf CA the key
                    // names.
                    if let Some(head) = path.first() {
                        if let Some(cert) = cert_at(*head) {
                            let issuer = name_to_string(cert.decoded().tbs_certificate().issuer());
                            if !anchor_subjects.contains(&issuer) {
                                unanchored.insert(*head);
                            }
                        }
                    }
                    if let Some(tail) = path.last() {
                        if let Some(cert) = cert_at(*tail) {
                            if hex_skid_from_cert(&cert) != *key {
                                miskeyed.insert((key.clone(), *tail));
                            }
                        }
                    }
                }
            }
        }

        for i in out_of_range {
            failures.push(format!(
                "entry {env:?} has a partial path referencing buffer {i}, which the store does not carry; certval indexes its parsed-certificate vector with these directly, so a consumer would panic rather than fail over"
            ));
        }
        for (key, tail) in miskeyed {
            failures.push(format!(
                "entry {env:?} files paths under key {key} whose leaf CA is {:?}, whose own key identifier differs; paths are found by that key, so these would never be returned",
                label(tail)
            ));
        }
        for (row, len) in mislevelled {
            failures.push(format!(
                "entry {env:?} has a path of {len} certificates in row {row}, which holds paths of {}",
                row + 1
            ));
        }
        for i in unanchored {
            failures.push(format!(
                "entry {env:?} has partial paths starting at {:?}, which none of the entry's trust anchors issued",
                label(i)
            ));
        }
        for (i, seen) in in_a_path.iter().enumerate() {
            if !seen {
                failures.push(format!(
                    "entry {env:?} CA {:?} appears in no serialized partial path, so the path builder will never reach it",
                    label(i)
                ));
            }
        }
    }
    failures
}

/// Build the environment a consumer would get for `env`, with time-of-interest
/// checks disabled so the material is judged on its structure rather than on
/// what happens to be valid today.
fn environment_for(entry: &StoreEntry) -> Option<(PkiEnvironment, TaSource)> {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    environment_from(entry, pe)
}

/// As [`environment_for`], but over a caller-supplied environment — which is how
/// a provider whose material needs crypto beyond the RustCrypto classical
/// callbacks gets its own verifiers into the check.
fn environment_from(
    entry: &StoreEntry,
    mut pe: PkiEnvironment,
) -> Option<(PkiEnvironment, TaSource)> {
    if let Some(cbor) = entry.cert_store_cbor {
        pe.add_certificate_source(Box::new(load_store(cbor).ok()?));
    }
    let mut ta_store = TaSource::new();
    for der in entry.roots {
        ta_store.push(CertFile {
            filename: format!("{} root", entry.env),
            bytes: der.to_vec(),
        });
    }
    ta_store.initialize().ok()?;
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    Some((pe, ta_store))
}

/// Check that every anchor an entry advertises is one certval can actually
/// *use*, rather than merely one it counted.
///
/// `TaSource::initialize` logs and continues past a buffer that is not a valid
/// `TrustAnchorChoice`, and `index_tas` leaves out any anchor whose key
/// identifier cannot be computed — so the buffer count that
/// [`check_prepare_environment`] compares can be right while the anchor itself
/// is unusable. This is the certval-side twin of the reqwest check in
/// [`check_roots_parse`], and it also catches the collision case: certval
/// poisons a key identifier that resolves to two different public keys and
/// refuses to anchor on it, so two anchors sharing a SKID make *both* unusable
/// rather than one shadowing the other.
pub fn check_anchors_are_usable(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let Some((pe, _)) = environment_for(&entry) else {
            continue; // the load failure is reported by check_cert_stores_load
        };
        for (i, root) in entry.roots.iter().enumerate() {
            let Ok(cert) = parse_cert(root, env) else {
                continue; // reported by check_roots_parse
            };
            let hex_skid = hex_skid_from_cert(&cert);
            let label = get_leaf_rdn(cert.decoded().tbs_certificate().subject());
            if hex_skid.is_empty() {
                failures.push(format!(
                    "entry {env:?} root {i} ({label}) has no computable key identifier, so certval cannot index it as an anchor"
                ));
            } else if pe.get_trust_anchor_by_hex_skid(&hex_skid).is_err() {
                failures.push(format!(
                    "entry {env:?} root {i} ({label}) is installed but unusable as a trust anchor — it is not a usable TrustAnchorChoice, or its key identifier collides with another anchor carrying a different key"
                ));
            }
        }
    }
    failures
}

/// Check that certval can actually build a path for every CA in an embedded
/// store, using the same call a consumer makes.
///
/// The other store checks read the serialized material; this one exercises it,
/// so it covers the wiring between the three pieces at once — anchor lookup by
/// the CA's authority key identifier, partial-path lookup by that same key, and
/// the name comparison certval applies before accepting a path. A store can
/// satisfy every structural check and still return nothing here.
pub fn check_paths_build(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let Some(cbor) = entry.cert_store_cbor else {
            continue;
        };
        let (Some((pe, _)), Ok(cert_source)) = (environment_for(&entry), load_store(cbor)) else {
            continue;
        };
        for cert in cert_source.certs().iter().flatten() {
            let mut paths = vec![];
            let found = pe.get_paths_for_target(cert, &mut paths, 0, TimeOfInterest::disabled());
            if found.is_err() || paths.is_empty() {
                failures.push(format!(
                    "entry {env:?} yields no certification path for CA {:?}, which a consumer asking certval for one would see as an unusable CA",
                    get_leaf_rdn(cert.decoded().tbs_certificate().subject())
                ));
            }
        }
    }
    failures
}

/// Check that certval can *validate* a path to every CA in an embedded store,
/// not merely assemble one — signatures verified from the anchor down, and
/// whatever else RFC 5280 processing the settings ask for.
///
/// **The environment comes from the caller, because the core cannot know a
/// community's crypto.** `populate_5280_pki_environment` installs the RustCrypto
/// classical callbacks and nothing else: a store signed with PQC or composite
/// algorithms needs certval's `pqc` feature, and a community that offloads
/// verification to a token needs callbacks only its own crate can install. So a
/// provider passes `make_environment`, a factory returning a fresh environment
/// already carrying its verifiers; this adds that provider's own material to it
/// and drives the validation. Most providers can pass [`default_environment`].
///
/// It is a factory rather than a borrowed environment — the asymmetry with `cps`
/// is deliberate — because the environment is built up per entry rather than
/// merely read: each gets its own store and anchors, and reusing one would let a
/// CA validate under a *different* entry's anchor. `PkiEnvironment` is a
/// switchboard of boxed callbacks and sources, so it cannot simply be cloned.
///
/// A CA is reported when *no* path to it validates. Several paths to one CA is
/// normal in a cross-certified mesh, and some of those may be superseded; what
/// makes the CA usable is that at least one still validates.
///
/// This is the check the other store checks approximate. They read the material;
/// this one asks certval whether it is cryptographically sound. Keep `cps`
/// time-independent (time of interest disabled) unless you want the suite to
/// start failing the day a CA expires.
pub fn check_paths_validate(
    provider: &dyn TrustStoreProvider,
    make_environment: impl Fn() -> PkiEnvironment,
    cps: &CertificationPathSettings,
) -> Vec<String> {
    let mut failures = vec![];
    for entry in provider.entries() {
        let env = entry.env;
        let Some(cbor) = entry.cert_store_cbor else {
            continue;
        };
        let (Some((pe, _)), Ok(cert_source)) = (
            environment_from(&entry, make_environment()),
            load_store(cbor),
        ) else {
            continue;
        };
        let toi = cps.get_time_of_interest();
        for cert in cert_source.certs().iter().flatten() {
            let label = get_leaf_rdn(cert.decoded().tbs_certificate().subject());
            let mut paths = vec![];
            if pe.get_paths_for_target(cert, &mut paths, 0, toi).is_err() || paths.is_empty() {
                continue; // reported by check_paths_build
            }
            let mut last_error = None;
            let validated = paths.iter_mut().any(|path| {
                let mut results = CertificationPathResults::new();
                match pe.validate_path(&pe, cps, path, &mut results) {
                    Ok(()) => true,
                    Err(e) => {
                        last_error = Some(e);
                        false
                    }
                }
            });
            if !validated {
                failures.push(format!(
                    "entry {env:?} builds paths for CA {label:?} but none validates: {:?}",
                    last_error
                ));
            }
        }
    }
    failures
}

/// A fresh environment carrying certval's RFC 5280 processing and whichever
/// RustCrypto verifiers are compiled in.
///
/// **Which algorithms that covers is decided by the calling crate, not by this
/// one.** certval gates RSA behind its `rsa` feature, Ed25519 behind `eddsa`,
/// and ML-DSA/SLH-DSA/composite behind `pqc` — none of them in its defaults. A
/// provider whose material is RSA-signed and whose own dev-dependency on certval
/// does not enable `rsa` will see every CA reported as unvalidatable, because
/// signature verification returns `Unrecognized` rather than failing loudly. Set
/// the features your community's algorithms need:
///
/// ```toml
/// [dev-dependencies]
/// certval = { git = "…", features = ["std", "rsa"] }
/// ```
pub fn default_environment() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

/// Settings for a time-independent validation run: no time of interest, so a
/// store is judged on whether it is sound rather than on whether it is current.
pub fn structural_validation_settings() -> CertificationPathSettings {
    structural_settings()
}

/// Run [`check_paths_validate`], panicking with all failures if any fail.
pub fn assert_paths_validate(
    provider: &dyn TrustStoreProvider,
    make_environment: impl Fn() -> PkiEnvironment,
    cps: &CertificationPathSettings,
) {
    let failures = check_paths_validate(provider, make_environment, cps);
    assert!(
        failures.is_empty(),
        "paths do not validate:\n - {}",
        failures.join("\n - ")
    );
}

/// Check that [`prepare_certval_environment`] accepts every environment the
/// provider advertises, installs all of its anchors, and still rejects an
/// environment no provider serves.
pub fn check_prepare_environment(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    let providers: [&dyn TrustStoreProvider; 1] = [provider];
    for entry in provider.entries() {
        let env = entry.env;
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        let mut ta_store = TaSource::new();
        match prepare_certval_environment(&providers, &mut pe, &mut ta_store, env) {
            Ok(()) => {
                if ta_store.len() != entry.roots.len() {
                    failures.push(format!(
                        "entry {env:?} advertises {} anchors but installed {} — duplicate anchor bytes?",
                        entry.roots.len(),
                        ta_store.len()
                    ));
                }
            }
            Err(e) => failures.push(format!(
                "prepare_certval_environment rejected advertised environment {env:?}: {e:?}"
            )),
        }
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();
    let r = prepare_certval_environment(&providers, &mut pe, &mut ta_store, NO_SUCH_ENV);
    if !matches!(r, Err(Error::Unrecognized)) {
        failures.push(format!(
            "prepare_certval_environment did not return Unrecognized for {NO_SUCH_ENV:?}"
        ));
    }
    failures
}

/// Check that a `reqwest` client can be built from the provider's anchors.
///
/// Only meaningful under the `reqwest-client` feature; without it there is no
/// client to build and this reports nothing.
///
/// Backend selection is left to the caller elsewhere in this crate; this uses a
/// default builder so the check exercises anchor installation rather than the
/// TLS backend the host happens to have compiled in.
pub fn check_client_builds(provider: &dyn TrustStoreProvider) -> Vec<String> {
    #[cfg(not(feature = "reqwest-client"))]
    {
        let _ = provider;
        vec![]
    }
    #[cfg(feature = "reqwest-client")]
    {
        let providers: [&dyn TrustStoreProvider; 1] = [provider];
        match get_reqwest_client(&providers, reqwest::Client::builder(), None) {
            Ok(_) => vec![],
            Err(e) => vec![format!("failed to build a reqwest client: {e:?}")],
        }
    }
}

/// Check that a set of providers can be composed into one environment, the way
/// a consumer assembles them from its enabled features.
///
/// Each provider can be perfectly conformant on its own and still be unusable
/// beside another. certval scans every registered trust anchor source and
/// *poisons* a key identifier that resolves to more than one public key, then
/// refuses to anchor on it — so a collision does not shadow one anchor, it
/// disables both, in whichever consumer happens to load the two providers
/// together. Two providers claiming the same environment label is the other
/// composition failure: [`prepare_certval_environment`] would quietly serve both
/// communities' material under one name.
///
/// This is the check to run when adding a provider to the family, and the one a
/// consumer should run over its own assembled list.
pub fn check_providers_compose(providers: &[&dyn TrustStoreProvider]) -> Vec<String> {
    let mut failures = vec![];
    let mut envs: BTreeMap<&str, usize> = BTreeMap::new();
    let mut anchors: BTreeMap<String, (certval::PDVCertificate, String)> = BTreeMap::new();

    for (p, provider) in providers.iter().enumerate() {
        for entry in provider.entries() {
            if let Some(prev) = envs.insert(entry.env, p) {
                if prev != p {
                    failures.push(format!(
                        "providers {prev} and {p} both serve environment {:?}, so preparing it would merge material from both",
                        entry.env
                    ));
                }
            }
            for root in entry.roots {
                let Ok(cert) = parse_cert(root, entry.env) else {
                    continue; // reported per-provider by check_roots_parse
                };
                let hex_skid = hex_skid_from_cert(&cert);
                if hex_skid.is_empty() {
                    continue; // reported per-provider by check_anchors_are_usable
                }
                let label = format!(
                    "{:?} in {:?}",
                    get_leaf_rdn(cert.decoded().tbs_certificate().subject()),
                    entry.env
                );
                match anchors.get(&hex_skid) {
                    Some((first, first_label)) => {
                        if first.decoded().tbs_certificate().subject_public_key_info()
                            != cert.decoded().tbs_certificate().subject_public_key_info()
                        {
                            failures.push(format!(
                                "anchors {first_label} and {label} share key identifier {hex_skid} but carry different public keys; certval refuses to anchor on such a key identifier, so composing these providers disables both"
                            ));
                        }
                    }
                    None => {
                        anchors.insert(hex_skid, (cert, label));
                    }
                }
            }
        }
    }
    failures
}

/// Run [`check_providers_compose`], panicking with all failures if any fail.
pub fn assert_providers_compose(providers: &[&dyn TrustStoreProvider]) {
    let failures = check_providers_compose(providers);
    assert!(
        failures.is_empty(),
        "providers do not compose:\n - {}",
        failures.join("\n - ")
    );
}

/// Check a generator-input directory against the store built from it.
///
/// Only the `.cbor` store is `include_bytes!`'d into a provider crate; the
/// `.der` files beside it are the generator's inputs, which ship but affect
/// nothing at runtime. They therefore drift silently: a certificate added to
/// the directory without regenerating the store, or dropped from the directory
/// after being folded in, is invisible until someone tries to rebuild. This
/// compares the two sets by encoding, in both directions.
///
/// `dir` is a filesystem path — provider crates pass
/// `Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/<env>")`.
pub fn check_generator_inputs(dir: &Path, cbor: &[u8]) -> Vec<String> {
    let cert_source = match load_store(cbor) {
        Ok(cert_source) => cert_source,
        Err(e) => {
            return vec![format!(
                "CA store for {} failed to load: {e:?}",
                dir.display()
            )]
        }
    };

    let mut in_store: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for buffer in cert_source.get_buffers() {
        in_store.insert(buffer.bytes, buffer.filename);
    }

    let (on_disk, mut failures) = match read_der_dir(dir) {
        Ok(read) => read,
        Err(e) => return vec![e],
    };

    for (bytes, name) in &on_disk {
        if !in_store.contains_key(bytes) {
            failures.push(format!(
                "{name} is present in {} but not in the store built from it — the store needs regenerating",
                dir.display()
            ));
        }
    }

    for (bytes, filename) in &in_store {
        if !on_disk.contains_key(bytes) {
            failures.push(format!(
                "the store carries {filename}, which has no corresponding file in {} — the inputs are incomplete",
                dir.display()
            ));
        }
    }
    failures
}

/// Check a trust-anchor directory against the anchors a provider embeds.
///
/// Anchors reach a provider through a hand-maintained `include_bytes!` list
/// rather than through a generated store, so the compiler catches only one
/// direction of drift: remove a `.der` and the crate stops building. Add one and
/// nothing happens — the file ships, reads as part of the trust set to anyone
/// looking at the repository, and is not in it. This compares the directory
/// against the anchors the provider actually yields, by encoding, in both
/// directions.
///
/// `dir` is a filesystem path — provider crates pass
/// `Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/<env>")` alongside the
/// matching entry's `roots`.
pub fn check_root_inputs(dir: &Path, roots: &[&[u8]]) -> Vec<String> {
    let (on_disk, mut failures) = match read_der_dir(dir) {
        Ok(read) => read,
        Err(e) => return vec![e],
    };

    let embedded: BTreeSet<&[u8]> = roots.iter().copied().collect();
    for (bytes, name) in &on_disk {
        if !embedded.contains(bytes.as_slice()) {
            failures.push(format!(
                "{name} is present in {} but is not embedded as a trust anchor — the include_bytes! list needs updating",
                dir.display()
            ));
        }
    }

    for root in roots {
        if !on_disk.contains_key(*root) {
            let label = subject_name(root).unwrap_or_else(|| "<unparseable>".to_string());
            failures.push(format!(
                "the crate embeds trust anchor {label:?}, which has no corresponding file in {} — the inputs are incomplete",
                dir.display()
            ));
        }
    }
    failures
}

/// Read the DER-encoded certificates in a directory, keyed by encoding.
///
/// `Err` means the directory itself could not be read, which is fatal to the
/// caller's check. Per-file read errors are returned alongside the certificates
/// that did load, so one unreadable file does not hide the rest of the
/// directory.
#[allow(clippy::type_complexity)]
fn read_der_dir(dir: &Path) -> Result<(BTreeMap<Vec<u8>, String>, Vec<String>), String> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(e) => return Err(format!("failed to read {}: {e}", dir.display())),
    };

    let mut failures = vec![];
    let mut on_disk: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let is_der = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("der") || e.eq_ignore_ascii_case("cer"))
            .unwrap_or(false);
        if !is_der {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                failures.push(format!("failed to read {}: {e}", path.display()));
                continue;
            }
        };
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        on_disk.insert(bytes, name);
    }
    Ok((on_disk, failures))
}

/// Run every provider-level check and return the combined failures. Does not
/// include [`check_generator_inputs`] or [`check_root_inputs`], which need a
/// filesystem path the provider crate supplies.
pub fn conformance_failures(provider: &dyn TrustStoreProvider) -> Vec<String> {
    let mut failures = vec![];
    failures.extend(check_entry_shape(provider));
    failures.extend(check_roots_parse(provider));
    failures.extend(check_cert_stores_load(provider));
    failures.extend(check_partial_paths(provider));
    failures.extend(check_anchors_are_usable(provider));
    failures.extend(check_paths_build(provider));
    failures.extend(check_prepare_environment(provider));
    failures.extend(check_client_builds(provider));
    failures
}

/// Run every provider-level check, panicking with all failures if any fail.
pub fn assert_conformant(provider: &dyn TrustStoreProvider) {
    let failures = conformance_failures(provider);
    assert!(
        failures.is_empty(),
        "provider is not conformant:\n - {}",
        failures.join("\n - ")
    );
}

/// The checks above are only worth running if they fail when they should. These
/// feed deliberately broken providers to each check; the provider crates cover
/// the passing side with their real material.
#[cfg(test)]
mod tests {
    use super::*;

    /// A provider assembled from whatever entries a test hands it.
    struct Fake(Box<dyn Fn() -> Vec<StoreEntry>>);
    impl TrustStoreProvider for Fake {
        fn entries(&self) -> Vec<StoreEntry> {
            (self.0)()
        }
    }

    fn fake(entries: impl Fn() -> Vec<StoreEntry> + 'static) -> Fake {
        Fake(Box::new(entries))
    }

    /// Serialize a store the way the provider crates embed it. Leaked because
    /// `StoreEntry` holds `'static` bytes, which is what `include_bytes!` gives
    /// the real providers.
    fn store(
        buffers: Vec<certval::CertFile>,
        partial_paths: certval::PartialPaths,
    ) -> &'static [u8] {
        RawStore {
            buffers,
            partial_paths,
        }
        .into_static_cbor()
    }

    fn buffer(filename: &str) -> certval::CertFile {
        certval::CertFile {
            filename: filename.to_string(),
            bytes: NOT_A_CERT.to_vec(),
        }
    }

    static NOT_A_CERT: &[u8] = b"this is not a certificate";
    static ROOTS_ONE_BAD: &[&[u8]] = &[NOT_A_CERT];
    static NO_ROOTS: &[&[u8]] = &[];
    static EMPTY_ROOT: &[&[u8]] = &[&[]];
    static DUPLICATE_ROOTS: &[&[u8]] = &[NOT_A_CERT, NOT_A_CERT];

    #[test]
    fn entry_shape_catches_unusable_labels_and_missing_anchors() {
        let failures = check_entry_shape(&fake(|| {
            vec![
                StoreEntry {
                    env: " NIPR",
                    roots: NO_ROOTS,
                    cert_store_cbor: None,
                    published: None,
                    collected: None,
                },
                StoreEntry {
                    env: "DEV",
                    roots: EMPTY_ROOT,
                    cert_store_cbor: None,
                    published: None,
                    collected: None,
                },
                StoreEntry {
                    env: "DEV",
                    roots: EMPTY_ROOT,
                    cert_store_cbor: None,
                    published: None,
                    collected: None,
                },
            ]
        }));
        assert_eq!(failures.len(), 5, "{failures:#?}");
    }

    /// `ROOTS_ONE_BAD` so neither entry trips the anchor checks: what is under test
    /// is the dates alone, and a third failure here would mean something else fired.
    #[test]
    fn a_malformed_date_and_one_collected_before_it_was_published_are_reported() {
        let failures = check_entry_shape(&fake(|| {
            vec![
                StoreEntry {
                    env: "DEV",
                    roots: ROOTS_ONE_BAD,
                    cert_store_cbor: None,
                    // The trailing newline an `include_str!` of a generated file brings
                    // with it when nothing trims it.
                    published: Some("2026-08-13\n"),
                    collected: None,
                },
                StoreEntry {
                    env: "NIPR",
                    roots: ROOTS_ONE_BAD,
                    cert_store_cbor: None,
                    published: Some("2026-09-11"),
                    collected: Some("2026-06-12"),
                },
            ]
        }));
        assert_eq!(failures.len(), 2, "{failures:#?}");
        assert!(
            failures.iter().any(|f| f.contains("ISO 8601")),
            "{failures:#?}"
        );
        assert!(
            failures.iter().any(|f| f.contains("before it existed")),
            "{failures:#?}"
        );
    }

    #[test]
    fn roots_that_do_not_parse_are_reported() {
        let failures = check_roots_parse(&fake(|| {
            vec![StoreEntry {
                env: "DEV",
                roots: ROOTS_ONE_BAD,
                cert_store_cbor: None,
                published: None,
                collected: None,
            }]
        }));
        assert_eq!(failures.len(), 1, "{failures:#?}");
    }

    #[test]
    fn a_root_included_twice_is_reported() {
        let failures = check_roots_parse(&fake(|| {
            vec![StoreEntry {
                env: "DEV",
                roots: DUPLICATE_ROOTS,
                cert_store_cbor: None,
                published: None,
                collected: None,
            }]
        }));
        // One parse failure per copy, plus the duplication itself.
        assert_eq!(failures.len(), 3, "{failures:#?}");
    }

    #[test]
    fn a_corrupt_cert_store_is_reported() {
        let failures = check_cert_stores_load(&fake(|| {
            vec![StoreEntry {
                env: "DEV",
                roots: NO_ROOTS,
                cert_store_cbor: Some(b"\x00truncated"),
                published: None,
                collected: None,
            }]
        }));
        assert_eq!(failures.len(), 1, "{failures:#?}");
    }

    /// A store can deserialize perfectly and still be useless offline, so the
    /// paths are checked separately from the load.
    #[test]
    fn a_store_carrying_no_serialized_paths_is_reported() {
        let cbor = store(vec![buffer("orphan.der")], vec![]);
        let failures = check_partial_paths(&fake(move || {
            vec![StoreEntry {
                env: "DEV",
                roots: NO_ROOTS,
                cert_store_cbor: Some(cbor),
                published: None,
                collected: None,
            }]
        }));
        assert_eq!(failures.len(), 1, "{failures:#?}");
        assert!(
            failures[0].contains("no serialized partial paths"),
            "{failures:#?}"
        );
    }

    /// Two paths, both correctly levelled for row 0: one covering a buffer the
    /// store has, one naming a buffer it does not. That leaves the second buffer
    /// in no path at all. Exactly those two failures and nothing else — a third
    /// would mean a check is firing on something this store does not do wrong.
    #[test]
    fn a_ca_in_no_path_and_a_path_off_the_end_are_both_reported() {
        let paths = vec![BTreeMap::from([(
            "SKID".to_string(),
            vec![vec![0], vec![7]],
        )])];
        let cbor = store(vec![buffer("covered.der"), buffer("orphan.der")], paths);
        let failures = check_partial_paths(&fake(move || {
            vec![StoreEntry {
                env: "DEV",
                roots: NO_ROOTS,
                cert_store_cbor: Some(cbor),
                published: None,
                collected: None,
            }]
        }));
        assert_eq!(failures.len(), 2, "{failures:#?}");
        assert!(
            failures
                .iter()
                .any(|f| f.contains("which the store does not carry")),
            "{failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|f| f.contains("orphan.der") && f.contains("no serialized partial path")),
            "{failures:#?}"
        );
    }

    /// Row 0 holds paths of one certificate, so a two-certificate path there did
    /// not come from `find_all_partial_paths`. (The key and anchor checks stay
    /// quiet here: neither buffer parses, which check_cert_stores_load reports.)
    #[test]
    fn a_path_in_the_wrong_row_is_reported() {
        let paths = vec![BTreeMap::from([("SKID".to_string(), vec![vec![0, 1]])])];
        let cbor = store(vec![buffer("a.der"), buffer("b.der")], paths);
        let failures = check_partial_paths(&fake(move || {
            vec![StoreEntry {
                env: "DEV",
                roots: NO_ROOTS,
                cert_store_cbor: Some(cbor),
                published: None,
                collected: None,
            }]
        }));
        assert_eq!(failures.len(), 1, "{failures:#?}");
        assert!(
            failures[0].contains("path of 2 certificates in row 0"),
            "{failures:#?}"
        );
    }

    #[test]
    fn a_provider_serving_nothing_still_rejects_unknown_environments() {
        assert!(check_prepare_environment(&fake(Vec::new)).is_empty());
    }

    #[test]
    fn a_missing_generator_input_directory_is_reported() {
        let failures = check_generator_inputs(Path::new("/no/such/directory"), b"\x00truncated");
        assert_eq!(failures.len(), 1, "{failures:#?}");
    }

    #[test]
    fn a_missing_root_directory_is_reported() {
        let failures = check_root_inputs(Path::new("/no/such/directory"), &[]);
        assert_eq!(failures.len(), 1, "{failures:#?}");
    }
}

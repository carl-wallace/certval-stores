//! The build-script driver a provider crate generated from InstallRoot streams runs.
//!
//! Two halves, and which one runs depends on where the crate is being built from.
//!
//! **In a working tree with the sentinel present** each stream is re-fetched, compared
//! against the committed copy by the publisher's own date, and -- when the publisher has
//! something newer -- written, regenerated into `roots/`, `cas/` and `provenance/`, and
//! reported. The result is an ordinary source change: a person reviews the certificate diff and
//! commits it, so what ships is still what someone looked at.
//!
//! **Anywhere else** the sentinel is absent, so nothing is fetched -- verification runs under
//! `verify::Revocation::Stapled`, which settles every status from what the streams carry -- and
//! nothing in the source tree is written -- which matters more than it sounds, since a checkout sits under `~/.cargo` beside
//! a `.cargo-checksum.json` that writing to it would invalidate. The consumer gets the committed
//! material and the checks.
//!
//! What makes it absent is that the file is **gitignored and never committed**, not the `exclude`
//! in each crate's `Cargo.toml`: these crates are consumed as git dependencies, and a git
//! dependency is a checkout of this repository, so a committed sentinel would put every consumer
//! on the refresh path. The `exclude` covers the published-crate route as well.
//!
//! The sentinel gates *running* the fetch, not *compiling* it: a crate calling this takes the
//! `fetch` feature unconditionally, so a consumer still builds ureq even though nothing calls
//! it. Putting that behind a feature of the provider crate would cost the ergonomic the
//! sentinel buys -- a plain `cargo build` in a checkout refreshing the material -- so it is a
//! deliberate trade.
//!
//! Here rather than copied into each provider's `build.rs` because once two crates run the same
//! script modulo a table, the table is the only content either of them has.

use std::collections::BTreeSet;
use std::path::Path;

use certval::PkiEnvironment;

use crate::adapters::tamp::{self, Population};
use crate::core::generate;
use crate::verify::Revocation;
use crate::{build_check, ingest, provider, refresh};

/// One generated environment: the stream it reads, and the material no stream carries.
pub struct Env {
    /// Names the directories under `roots/`, `cas/` and `provenance/`, and the CBOR store
    /// inside `cas/<name>/`.
    pub name: &'static str,
    /// The committed stream's basename, which is also what the publisher serves it under.
    pub stream: &'static str,
    /// Which of the PKIs in that stream this environment is. One stream carries several, and
    /// they belong to different crates.
    pub population: Population,
    /// Trust anchors supplied file by file because no stream publishes them -- an
    /// interoperability root, say. These are the part of a crate a refresh cannot touch.
    pub extra_roots: &'static [&'static str],
    /// CA certificates supplied the same way, such as the bundle a supplied root publishes at
    /// its own SIA, which is that root's own statement of what it issued.
    pub extra_cas: &'static [&'static str],
}

impl Env {
    fn stream_path(&self) -> String {
        format!("inputs/{}", self.stream)
    }

    fn store_path(&self) -> String {
        format!("cas/{}/{}.cbor", self.name, self.name)
    }
}

/// Refresh what the sentinel allows, regenerate what changed, and check everything.
///
/// `sentinel` is the file marking a source checkout; `published_at` the directory URL the
/// streams are served from, joined to each `Env::stream` basename.
///
/// Call from a provider crate's `build.rs`. Panics on a mismatch or a failed regeneration,
/// which is how a build script fails.
pub fn run(sentinel: &str, published_at: &str, envs: &[Env]) {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={sentinel}");

    let refreshed = if Path::new(sentinel).exists() {
        refresh_streams(published_at, envs)
    } else {
        BTreeSet::new()
    };

    for env in envs {
        if refreshed.contains(env.stream) {
            regenerate(env);
        }
        build_check::assert_tamp_store_with(
            &env.stream_path(),
            env.population.name(),
            env.extra_roots,
            env.extra_cas,
            &env.store_path(),
        );
    }
}

/// Re-fetch each distinct stream, returning the basenames of those that were replaced.
///
/// Distinct because several environments can be generated from one stream -- NIPR production and
/// both interoperability environments all read `DoD.ir4` -- and fetching it once per environment
/// would ask the publisher the same question three times.
fn refresh_streams(published_at: &str, envs: &[Env]) -> BTreeSet<&'static str> {
    let mut replaced = BTreeSet::new();
    let mut seen = BTreeSet::new();

    for env in envs {
        if !seen.insert(env.stream) {
            continue;
        }
        let committed = env.stream_path();
        let url = format!("{}/{}", published_at.trim_end_matches('/'), env.stream);
        match refresh::stream(&url, Path::new(&committed), env.population) {
            refresh::Outcome::Replaced { was, now } => {
                let from = was.unwrap_or_else(|| "an undated stream".to_string());
                println!("cargo::warning={committed} refreshed from {url}: {from} -> {now}");
                replaced.insert(env.stream);
            }
            refresh::Outcome::Current { published } => {
                let when = published.unwrap_or_else(|| "an unstated date".to_string());
                println!("{committed} is current (published {when})");
            }
            refresh::Outcome::Older {
                committed: have,
                offered,
            } => {
                println!(
                    "cargo::warning={url} is serving material published {}, older than the \
                     committed {}; keeping what is committed",
                    offered.unwrap_or_else(|| "at an unstated date".to_string()),
                    have.unwrap_or_else(|| "stream".to_string())
                );
            }
            refresh::Outcome::Kept { why } => {
                println!("cargo::warning=keeping the committed {}: {why}", env.stream);
            }
        }
    }
    replaced
}

/// Rewrite one environment's `roots/`, `cas/` and `provenance/` from the stream now in hand.
///
/// Panicking is how a build script fails, and this path is only reached in a checkout after a
/// deliberate refresh: the stream has already moved, so leaving the generated material
/// half-written would be worse than stopping.
fn regenerate(env: &Env) {
    let stream = env.stream_path();
    let bytes = std::fs::read(&stream).unwrap_or_else(|e| panic!("{stream} is unreadable: {e}"));

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // Regeneration happens only in a source checkout, which has just fetched the stream, so the
    // responder may be asked too.
    let mut inputs = tamp::build(&pe, &bytes, env.population, Revocation::StapledAndFetched)
        .unwrap_or_else(|e| panic!("{stream} did not parse: {e}"));
    ingest::merge_extras(&mut inputs, env.extra_roots, env.extra_cas)
        .unwrap_or_else(|e| panic!("the material supplied for {} did not read: {e}", env.name));

    let store = generate(&inputs)
        .unwrap_or_else(|e| panic!("generating {} from {stream} failed: {e}", env.name));
    let provenance = provider::Provenance {
        published: inputs.published.clone(),
        collected: provider::today(),
    };
    provider::write(
        Path::new("."),
        env.name,
        env.name,
        &inputs.trust_anchors,
        &inputs.intermediates,
        &store,
        &provenance,
    )
    .unwrap_or_else(|e| panic!("writing the {} environment failed: {e}", env.name));

    // The roots reach `src/lib.rs` through a hand-maintained `include_bytes!` list, which this
    // cannot edit -- `check_root_inputs` fails the crate's tests when the two disagree, which is
    // that check doing its job. Printing the list makes bringing them back into step a paste
    // rather than a transcription.
    match provider::include_bytes_lines(Path::new("roots").join(env.name).as_path()) {
        Ok(lines) => println!(
            "cargo::warning={} regenerated; its include_bytes! list is now: {}",
            env.name,
            lines.replace('\n', " ")
        ),
        Err(e) => println!("cargo::warning=could not list the {} roots: {e}", env.name),
    }
}

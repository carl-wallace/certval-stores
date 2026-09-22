//! certval-store-gen — offline generator for certval CBOR trust-anchor and
//! intermediate-CA stores.
//!
//! Produces a `ta.cbor` / `ca.cbor` pair that pittv3 (desktop and wasm) load directly as
//! fetched stores. Three input adapters feed a shared generation core:
//!
//!   webpki  Mozilla roots (+ optional CCADB intermediates folder)
//!   fpki    an oversized PKCS#7 certs-only bundle (Federal PKI)
//!   installroot  a DoD InstallRoot .ir4 stream (one population of it)

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};

use certval::{PkiEnvironment, TimeOfInterest};

use certval_store_gen::adapters;
use certval_store_gen::core::{generate, GeneratedStore};
use certval_store_gen::ingest;
use certval_store_gen::provider;

#[derive(Parser)]
#[command(name = "certval-store-gen", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    out: OutputArgs,
}

#[derive(Args)]
struct OutputArgs {
    /// Directory to write ta.cbor and ca.cbor into.
    #[arg(long, global = true, default_value = ".")]
    out_dir: PathBuf,

    /// Override the trust-anchor store path (default: <out-dir>/ta.cbor).
    #[arg(long, global = true)]
    ta_out: Option<PathBuf>,

    /// Override the intermediate store path (default: <out-dir>/ca.cbor).
    #[arg(long, global = true)]
    ca_out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Local folders: a folder of trust anchors + a folder of intermediate CA certs.
    Local {
        /// Folder of trust-anchor (root) certificates in DER/PEM.
        #[arg(long)]
        tas: String,
        /// Folder of intermediate CA certificates in DER/PEM. Omit for a roots-only store.
        #[arg(long)]
        cas: Option<String>,
    },
    /// Web PKI: Mozilla roots + optional intermediates (folder or CCADB CSV).
    Webpki {
        /// Folder of CA (intermediate) certificates in DER/PEM. Omit for a roots-only store.
        #[arg(long)]
        ccadb: Option<String>,
        /// CCADB "All Intermediate Certs (with PEM)" CSV export to source intermediates from.
        #[arg(long, conflicts_with = "ccadb")]
        ccadb_csv: Option<PathBuf>,
        /// Keep intermediates that are outside their validity window (default: skip expired).
        #[arg(long)]
        include_expired: bool,
    },
    /// Walk a mesh from committed anchors, following each CA's own SIA `caRepository`.
    ///
    /// For a PKI that publishes no single artifact to generate from. The anchors are supplied
    /// as files because they are committed material, never discovered: a crawl collects edges.
    Crawl {
        /// Anchor certificates to start from (DER, PEM, or a certs-only PKCS#7).
        #[arg(long, num_args = 1.., required = true)]
        anchor: Vec<PathBuf>,
        /// Most repositories to fetch before stopping and reporting the walk as truncated.
        #[arg(long)]
        max_fetches: Option<usize>,
        /// An existing CBOR store to report the walk's difference against, changing nothing.
        #[arg(long)]
        against: Option<PathBuf>,
    },
    /// Federal PKI: an (oversized) PKCS#7 certs-only bundle.
    Fpki {
        /// Path to the PKCS#7 / CMS SignedData file (DER).
        #[arg(long)]
        p7: PathBuf,
    },
    /// Rewrite existing stores in certval's current CBOR encoding, changing nothing else.
    Recode {
        /// Store files to convert in place.
        #[arg(long, num_args = 1.., required = true)]
        store: Vec<PathBuf>,
        /// Report what would change and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify the signatures on one or more InstallRoot `.ir4` streams and write nothing.
    ///
    /// Separate from `installroot` because it asks a different question: not "can this
    /// environment be generated" but "are these bytes authentic", which is what gates a
    /// stream being committed in the first place. Takes no population for the same reason --
    /// a signature covers a member, not a PKI -- and touches no network.
    Verify {
        /// Streams to check. Every one is reported; the command fails if any member of any
        /// stream fails, so a run names all the bad files rather than the first.
        #[arg(long, num_args = 1.., required = true)]
        stream: Vec<PathBuf>,
    },
    /// DoD: an InstallRoot `.ir4` stream.
    Installroot {
        /// Path to the stream (e.g. DoD.ir4, JITC.ir4).
        #[arg(long)]
        stream: PathBuf,
        /// Which PKI published in the stream to generate for: dod, nss, eca or wcf. One stream
        /// can carry more than one, and they belong to different store crates.
        #[arg(long, default_value = "dod")]
        population: String,
        /// Root of a certval_stores_* crate to write into, in place of ta.cbor/ca.cbor. Writes
        /// roots/<env>/*.der, cas/<env>/*.der and cas/<env>/<env>.cbor.
        #[arg(long)]
        provider_dir: Option<PathBuf>,
        /// Environment subdirectory and store name under --provider-dir (e.g. prod, om).
        #[arg(long, requires = "provider_dir")]
        env: Option<String>,
        /// Report what would change under --provider-dir and write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Trust anchors to merge in beyond what the stream carries, named as files rather
        /// than a folder: DER, PEM, or a certs-only PKCS#7 bundle. For an anchor no
        /// repository publishes -- DoD Interoperability Root CA 2 appears in no `.ir4`
        /// message and in no `issuedby` bundle, so an interoperability environment has to
        /// be handed it.
        #[arg(long, num_args = 1..)]
        extra_roots: Vec<PathBuf>,
        /// CA certificates to merge in beyond what the stream carries, same formats.
        /// Intended for the bundle a supplied root publishes at its own SIA, which is that
        /// root's own statement of what it issued. Self-issued certificates are rejected:
        /// they belong in --extra-roots.
        #[arg(long, num_args = 1..)]
        extra_cas: Vec<PathBuf>,
        /// The day the stream was downloaded, `YYYY-MM-DD`. Defaults to today, which is
        /// right when the stream was fetched for this run and wrong when an older copy is
        /// being regenerated -- so pass it when regenerating from a stream already on disk.
        /// Written to provenance/<env>/collected.txt; the publication date beside it is
        /// read from the stream itself and is not settable here.
        #[arg(long)]
        collected: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // Include everything regardless of validity window; expiry is a validation-time concern
    // for the consumer, not a reason to omit a cert from the store.
    let toi = TimeOfInterest::disabled();

    // Recoding reads and rewrites finished stores rather than building one from trust material, so
    // it does not go through the adapter-then-generate path below.
    if let Command::Recode { store, dry_run } = &cli.command {
        return recode_stores(store, *dry_run);
    }
    // Like recoding, this never reaches the adapter-then-generate path: it reports on bytes
    // rather than producing a store from them.
    if let Command::Verify { stream } = &cli.command {
        return verify_streams(&pe, stream);
    }

    let mut inputs = match &cli.command {
        Command::Local { tas, cas } => adapters::local::build(&pe, tas, cas.as_deref(), toi)?,
        Command::Webpki {
            ccadb,
            ccadb_csv,
            include_expired,
        } => {
            let source = match (ccadb_csv, ccadb) {
                (Some(csv), _) => adapters::webpki::Intermediates::CcadbCsv {
                    path: csv,
                    include_expired: *include_expired,
                    now_unix: now_unix(),
                },
                (None, Some(dir)) => adapters::webpki::Intermediates::Dir(dir),
                (None, None) => adapters::webpki::Intermediates::None,
            };
            adapters::webpki::build(&pe, source, toi)?
        }
        Command::Crawl {
            anchor,
            max_fetches,
            against,
        } => {
            let mut anchors = vec![];
            for path in anchor {
                anchors.extend(ingest::read_cert_file(path)?);
            }
            let mut limits = certval_store_gen::crawl::Limits::default();
            if let Some(m) = max_fetches {
                limits.max_fetches = *m;
            }
            let crawled = certval_store_gen::crawl::from_anchors(&anchors, &limits);
            log::info!(
                "walked {} repositories from {} anchor(s): {} certificate(s), {} absent, {} unreachable{}",
                crawled.fetched,
                anchors.len(),
                crawled.certificates.len(),
                crawled.absent.len(),
                crawled.unreachable.len(),
                if crawled.truncated {
                    ", TRUNCATED by a limit"
                } else {
                    ""
                }
            );
            for f in &crawled.absent {
                log::info!("nothing published there: {f}");
            }
            // Warned rather than logged: each of these is a subtree that may be missing from the
            // result, which is what makes a walk unsafe to commit over one that succeeded.
            for f in &crawled.unreachable {
                log::warn!("no answer: {f}");
            }
            if let Some(path) = against {
                let committed = std::fs::read(path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let (added, removed) =
                    certval_store_gen::crawl::diff_against_store(&crawled.certificates, &committed);
                log::info!(
                    "against {}: {} added, {} removed",
                    path.display(),
                    added.len(),
                    removed.len()
                );
                for a in &added {
                    log::info!("  + {a}");
                }
                for r in &removed {
                    log::info!("  - {r}");
                }
            }
            certval_store_gen::crawl::into_inputs(&pe, anchors, crawled)
        }
        Command::Fpki { p7 } => {
            let bytes = std::fs::read(p7)
                .with_context(|| format!("failed to read PKCS#7 file {}", p7.display()))?;
            adapters::p7::build(&pe, &bytes)?
        }
        // Handled above; the match has to name these to stay exhaustive.
        Command::Recode { .. } => unreachable!("recoding returns before this point"),
        Command::Verify { .. } => unreachable!("verification returns before this point"),
        Command::Installroot {
            stream, population, ..
        } => {
            let bytes = std::fs::read(stream).with_context(|| {
                format!("failed to read InstallRoot stream {}", stream.display())
            })?;
            adapters::tamp::build(
                &pe,
                &bytes,
                adapters::tamp::Population::parse(population)?,
                certval_store_gen::verify::Revocation::StapledAndFetched,
            )?
        }
    };

    // Merged after the adapter and before `generate`, so the extras join the same
    // partial-path build as the stream's own material rather than being appended to a
    // finished store. `generate` dedupes, so a certificate the stream already carries
    // costs nothing if it is named again here.
    if let Command::Installroot {
        extra_roots,
        extra_cas,
        ..
    } = &cli.command
    {
        ingest::merge_extras(&mut inputs, extra_roots, extra_cas)?;
    }

    log::info!(
        "normalized inputs: {} trust anchors, {} intermediates",
        inputs.trust_anchors.len(),
        inputs.intermediates.len()
    );

    let store = generate(&inputs)?;

    // A provider crate takes its material as loose DER plus one named store, not as the
    // ta.cbor/ca.cbor pair, so that destination is handled separately -- and always reports the
    // diff first, whether or not it then writes.
    if let Command::Installroot {
        provider_dir: Some(dir),
        env,
        dry_run,
        collected,
        ..
    } = &cli.command
    {
        let env = env.as_deref().ok_or_else(|| {
            anyhow!("--provider-dir needs --env to say which environment to write")
        })?;
        let collected = match collected {
            Some(date) => {
                if !is_iso_date(date) {
                    return Err(anyhow!(
                        "--collected {date:?} is not an ISO 8601 calendar date (YYYY-MM-DD)"
                    ));
                }
                date.clone()
            }
            None => provider::today(),
        };
        let provenance = provider::Provenance {
            published: inputs.published.clone(),
            collected,
        };
        return write_provider(dir, env, &inputs, &store, *dry_run, &provenance);
    }

    write_store(&cli.out, &store)?;
    Ok(())
}

/// Convert each named store to the current CBOR encoding, reporting the size each one gives up.
fn recode_stores(stores: &[PathBuf], dry_run: bool) -> Result<()> {
    let (mut before_total, mut after_total) = (0usize, 0usize);
    for path in stores {
        let r = certval_store_gen::recode::recode(path, !dry_run)?;
        before_total += r.before;
        after_total += r.after;
        let pct = 100.0 * (r.before as f64 - r.after as f64) / r.before as f64;
        log::info!(
            "{}: {} certificates, {} path rows, {} -> {} bytes ({pct:.1}% smaller)",
            path.display(),
            r.certificates,
            r.path_rows,
            r.before,
            r.after
        );
    }
    if stores.len() > 1 {
        log::info!("total: {before_total} -> {after_total} bytes");
    }
    if dry_run {
        log::info!("dry run: nothing written");
    }
    Ok(())
}

/// Verify every named stream, reporting each, and fail if any of them does not verify.
///
/// Every stream is checked before anything is reported as failing, so one run names all the bad
/// files. A check that stopped at the first would make a repository with two broken streams take
/// two rounds to fix.
fn verify_streams(pe: &PkiEnvironment, streams: &[PathBuf]) -> Result<()> {
    let mut failures = vec![];
    for path in streams {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: unreadable: {e}", path.display()));
                continue;
            }
        };
        match certval_store_gen::verify::stream(
            pe,
            &bytes,
            certval_store_gen::verify::Revocation::StapledAndFetched,
        ) {
            Ok(members) => {
                // The latest timestamp, which is when the publisher's signing run finished and
                // the time the signers were validated at.
                let timestamped = members
                    .iter()
                    .filter_map(|m| m.timestamped_at)
                    .max_by_key(|t| t.as_unix_secs())
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "no timestamp".to_string());
                log::info!(
                    "{}: every member verifies, signed by {}, timestamped {timestamped}",
                    path.display(),
                    certval_store_gen::verify::signer_names(&members).join(", ")
                )
            }
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            log::error!("{f}");
        }
        return Err(anyhow!(
            "{} of {} stream(s) failed verification",
            failures.len(),
            streams.len()
        ));
    }
    log::info!("{} stream(s) verified", streams.len());
    Ok(())
}

/// Report the change a regeneration would make to a provider crate, then write it unless this is
/// a dry run.
fn write_provider(
    dir: &Path,
    env: &str,
    inputs: &certval_store_gen::core::StoreInputs,
    store: &GeneratedStore,
    dry_run: bool,
    provenance: &provider::Provenance,
) -> Result<()> {
    for (what, subdir, certs) in [
        (
            "trust anchors",
            dir.join("roots").join(env),
            &inputs.trust_anchors,
        ),
        (
            "intermediates",
            dir.join("cas").join(env),
            &inputs.intermediates,
        ),
    ] {
        let diff = provider::diff(&subdir, certs)?;
        if diff.is_empty() {
            log::info!("{what}: no change ({} unchanged)", diff.unchanged);
            continue;
        }
        log::info!(
            "{what}: {} added, {} removed, {} unchanged",
            diff.added.len(),
            diff.removed.len(),
            diff.unchanged
        );
        for a in &diff.added {
            log::info!("  + {a}");
        }
        for r in &diff.removed {
            log::info!("  - {r}");
        }
    }

    if dry_run {
        log::info!("dry run: nothing written");
        return Ok(());
    }

    provider::write(
        dir,
        env,
        env,
        provider::Material {
            anchors: &inputs.trust_anchors,
            intermediates: &inputs.intermediates,
            // The CLI generates the environments a person curates by hand, which have dozens of
            // intermediates at most, so their diffs stay certificate by certificate.
            loose: provider::Intermediates::AsFiles,
            store,
        },
        provenance,
    )?;
    log::info!(
        "the include_bytes! list for this environment is now:\n{}",
        provider::include_bytes_lines(&dir.join("roots").join(env))?
    );
    Ok(())
}

fn write_store(out: &OutputArgs, store: &GeneratedStore) -> Result<()> {
    std::fs::create_dir_all(&out.out_dir)
        .with_context(|| format!("failed to create output dir {}", out.out_dir.display()))?;

    let ta_path = out
        .ta_out
        .clone()
        .unwrap_or_else(|| out.out_dir.join("ta.cbor"));
    write_file(&ta_path, &store.ta_cbor)?;
    log::info!(
        "wrote {} ({} bytes)",
        ta_path.display(),
        store.ta_cbor.len()
    );

    match &store.ca_cbor {
        Some(ca) => {
            let ca_path = out
                .ca_out
                .clone()
                .unwrap_or_else(|| out.out_dir.join("ca.cbor"));
            write_file(&ca_path, ca)?;
            log::info!("wrote {} ({} bytes)", ca_path.display(), ca.len());
        }
        None => log::info!("no intermediates supplied; skipped ca.cbor"),
    }
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

/// Whether `value` is a `YYYY-MM-DD` calendar date, matching what the conformance suite in
/// `certval_stores_core` will accept from the file this writes.
fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
        && (1..=12).contains(&value[5..7].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&value[8..10].parse::<u32>().unwrap_or(0))
}

/// Current time as seconds since the Unix epoch, for the CCADB validity filter.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::is_iso_date;
    use certval_store_gen::provider::today;

    /// `--collected` is written straight into a file a provider crate compiles in and a
    /// frontend shows to a user, so this is the only gate between a typo and a store
    /// reporting a date that reads as an answer.
    #[test]
    fn only_calendar_dates_are_accepted() {
        assert!(is_iso_date("2026-09-11"));
        assert!(is_iso_date(&today()));

        assert!(!is_iso_date("2026-9-11"), "months are two digits");
        assert!(!is_iso_date("11-09-2026"), "not the day-first spelling");
        assert!(!is_iso_date("2026-09-11 "), "no trailing whitespace");
        assert!(!is_iso_date("2026-13-01"), "no thirteenth month");
        assert!(!is_iso_date("2026-09-32"), "no thirty-second day");
        assert!(!is_iso_date("yesterday"));
        assert!(!is_iso_date(""));
    }
}

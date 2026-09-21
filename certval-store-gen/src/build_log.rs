//! Routing this crate's `log` output to cargo, for use from a `build.rs`.
//!
//! The library narrates through the `log` facade and writes nothing to stdout itself, so
//! a caller decides where the narration goes: the CLI installs `env_logger`, and a build
//! script installs [`init`] from here.
//!
//! Cargo surfaces exactly one thing from a build script's stdout: a line beginning
//! `cargo::warning=`. Everything else is captured in the build log and shown only under
//! `cargo build -vv`. So warnings and errors become `cargo::warning=` — a person sees a
//! store that skipped a certificate without asking for verbose output — while info and
//! below are printed plainly, available when someone goes looking.

use log::{Level, LevelFilter, Log, Metadata, Record};

/// A `log` implementation that writes to cargo's build-script protocol.
///
/// Carries no level of its own: filtering is `log::max_level()`, which [`init`] sets. That
/// keeps it a zero-sized static, so installing it needs neither an allocation nor `log`'s
/// non-default `std` feature.
pub struct CargoLogger;

impl Log for CargoLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // A directive is one line: a record carrying newlines would leave its tail being
        // read as build-script output rather than as part of the warning.
        let msg = record.args().to_string().replace(['\n', '\r'], " ");
        match record.level() {
            Level::Error | Level::Warn => println!("cargo::warning={msg}"),
            _ => println!("{}: {msg}", record.level()),
        }
    }

    fn flush(&self) {}
}

/// Install [`CargoLogger`] as the process logger, at or below `level`.
///
/// Call once, first thing in `build.rs`. Returns an error if a logger is already
/// installed, which a build script can ignore -- it means someone else set the
/// destination deliberately.
///
/// ```no_run
/// // build.rs
/// certval_store_gen::build_log::init(log::LevelFilter::Info).ok();
/// ```
pub fn init(level: LevelFilter) -> Result<(), log::SetLoggerError> {
    static LOGGER: CargoLogger = CargoLogger;
    log::set_logger(&LOGGER)?;
    log::set_max_level(level);
    Ok(())
}

//! certval-store-gen library surface.
//!
//! The generation core and input adapters are exposed here so both the `certval-store-gen`
//! binary and integration tests drive the same code paths.

pub mod adapters;
#[cfg(feature = "authroot")]
pub mod authroot_refresh;
pub mod build_check;
pub mod build_log;
#[cfg(feature = "cab")]
pub mod cab;
pub mod core;
#[cfg(feature = "fetch")]
pub mod crawl;
pub mod ingest;
pub mod provider;
pub mod recode;
#[cfg(feature = "fetch")]
pub mod refresh;
#[cfg(feature = "tpm")]
pub mod tpm_refresh;

pub mod timestamp;
pub mod verify;

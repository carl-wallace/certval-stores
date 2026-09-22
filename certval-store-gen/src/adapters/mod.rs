//! Input adapters. Each normalizes a source of trust material into
//! [`StoreInputs`](crate::core::StoreInputs) for the shared generation core.

#[cfg(feature = "authroot")]
pub mod authroot;
pub mod ccadb;
pub mod local;
pub mod p7;
pub mod tamp;
#[cfg(feature = "tpm")]
pub mod tpm;
pub mod webpki;

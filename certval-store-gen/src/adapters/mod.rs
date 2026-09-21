//! Input adapters. Each normalizes a source of trust material into
//! [`StoreInputs`](crate::core::StoreInputs) for the shared generation core.

pub mod ccadb;
pub mod local;
pub mod p7;
pub mod tamp;
pub mod webpki;

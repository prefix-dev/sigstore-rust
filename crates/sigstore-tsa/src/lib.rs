//! RFC 3161 Time-Stamp Protocol client for Sigstore
//!
//! This crate implements the Time-Stamp Protocol as specified in RFC 3161,
//! including request creation, response parsing, and timestamp verification.

pub mod asn1;
pub mod client;
pub mod error;
pub mod verify;

pub use asn1::{
    AlgorithmIdentifier, Asn1MessageImprint, PkiStatus, TimeStampReq, TimeStampResp, TstInfo,
};
pub use client::{timestamp_sigstore, TimestampClient};
pub use error::{Error, Result};
pub use verify::{verify_timestamp_response, TimestampResult, VerifyOpts};

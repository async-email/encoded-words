//! Defects

use thiserror::Error;

/// These are parsing defects which the parser was able to work around.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Defect {
    #[error("Header contained bytes that could not be decoded")]
    UndecodableBytes,
    #[error("base64 encoded sequence had an incorrect length")]
    InvalidBase64Padding,
    #[error(
        "base64 encoded sequence had characters not in base64 alphabet: {}",
        byte
    )]
    InvalidBase64Characters { byte: u8 },
    #[error("base64 encoded sequence had invalid length (1 mod 4)")]
    InvalidBase64Length,
    #[error(
        "ASCII characters outside the ascii-printable range found: {:?}",
        non_printables
    )]
    NonPrintable { non_printables: Vec<u8> },
    #[error("An illegal charset was given: {}", charset)]
    InvalidCharset { charset: String },
}

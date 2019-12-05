//! Defects

use thiserror::Error;

/// These are parsing defects which the parser was able to work around.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Defect {
    #[error("A message claimed to be a multipart but had no boundary parameter.")]
    NoBoundaryInMultipart,
    #[error("The claimed start boundary was never found.")]
    StartBoundaryNotFound,
    #[error("A start boundary was found, but not the corresponding close boundary.")]
    CloseBoundaryNotFound,
    #[error("A message had a continuation line as its first header line.")]
    FirstHeaderLineIsContinuation,
    #[error("A 'Unix-from' header was found in the middle of a header block.")]
    MisplacedEnvelopeHeader,
    #[error("Found line with no leading whitespace and no colon before blank line.")]
    MissingHeaderBodySeparator,
    #[error("A message claimed to be a multipart but no subparts were found.")]
    MultipartInvariantViolation,
    #[error("An invalid content transfer encoding was set on the multipart itself.")]
    InvalidMultipartContentTransferEncoding,
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
    #[error("Header is not valid, message gives details.")]
    InvalidHeader,
    #[error("A header that must have a value had none")]
    HeaderMissingRequiredValue,
    #[error(
        "ASCII characters outside the ascii-printable range found: {:?}",
        non_printables
    )]
    NonPrintable { non_printables: Vec<u8> },
    #[error("Header uses syntax declared obsolete by RFC 5322")]
    ObsoleteHeader,
    #[error("local_part contains non-ASCII characters")]
    NonASCIILocalPart,
    #[error("An illegal charset was given: {}", charset)]
    InvalidCharset { charset: String },
}

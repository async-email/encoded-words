use std::borrow::Cow;

use charset::Charset as EncodingCharset;
use encoding_rs::Encoding;

lazy_static::lazy_static! {
    static ref UTF7: EncodingCharset = EncodingCharset::for_label(b"UTF-7").unwrap();
}

/// Map character sets to their email properties.
///
/// Provides information about the requirements imposed on email
/// for a specific character set.
/// Certain character sets must be encoded with quoted-printable or base64
/// when used in email headers or bodies.  Certain character sets must be
/// converted outright, and are not allowed in email.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Charset {
    Ascii,
    Utf7,
    Unknown8Bit,
    Encoding(&'static Encoding),
}

impl Default for Charset {
    fn default() -> Self {
        Charset::Ascii
    }
}

impl From<&'static Encoding> for Charset {
    fn from(enc: &'static Encoding) -> Self {
        Charset::Encoding(enc)
    }
}

impl Charset {
    pub fn name(&self) -> &'static str {
        match self {
            Charset::Ascii => "us-ascii",
            Charset::Utf7 => "utf-7",
            Charset::Unknown8Bit => "unknown-8bit",
            Charset::Encoding(encoding) => encoding.name(),
        }
    }

    pub fn for_label(label: &[u8]) -> Option<Self> {
        if let Ok(enc) = std::str::from_utf8(label) {
            let enc = enc.to_lowercase();
            if enc == "us-ascii" {
                return Some(Charset::Ascii);
            }

            if enc == "utf-7" {
                return Some(Charset::Utf7);
            }
            if enc == "unknown-8bit" {
                return Some(Charset::Unknown8Bit);
            }
        }

        if let Some(enc) = Encoding::for_label(label) {
            return Some(Charset::Encoding(enc));
        }

        None
    }

    // Convenience function for encoding strings, taking into account
    // that they might be unknown-8bit (ie: have surrogate-escaped bytes)
    pub fn encode(self, input: &str) -> (Cow<[u8]>, bool) {
        match self {
            Charset::Ascii => {
                let (out, _, errors) = encoding_rs::WINDOWS_1252.encode(input);
                (out, errors)
            }
            Charset::Utf7 | Charset::Unknown8Bit => (Cow::Borrowed(input.as_bytes()), false),
            Charset::Encoding(encoding) => {
                let (out, _, errors) = encoding.encode(input);
                (out, errors)
            }
        }
    }

    pub fn decode_without_bom_handling(self, bytes: &[u8]) -> (Cow<str>, bool) {
        match self {
            Charset::Utf7 => UTF7.decode_without_bom_handling(bytes),
            Charset::Unknown8Bit | Charset::Ascii => {
                encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes)
            }
            Charset::Encoding(encoding) => encoding.decode_without_bom_handling(bytes),
        }
    }

    /// Return the output character set.
    pub fn get_output_charset(self) -> Charset {
        match self {
            Charset::Ascii | Charset::Utf7 | Charset::Unknown8Bit => Charset::default(),
            Charset::Encoding(encoding) => Charset::Encoding(encoding.output_encoding()),
        }
    }
}

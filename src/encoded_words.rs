//! Routines for manipulating RFC2047 encoded words.
//!
//! An ecoded word looks like this: `=?charset[*lang]?cte?encoded_string?=`.
//!
//! For more information about charset see the charset module.  Here it is one
//! of the preferred MIME charset names (hopefully; you never know when parsing).
//! cte (Content Transfer Encoding) is either 'q' or 'b' (ignoring case).  In
//! theory other letters could be used for other encodings, but in practice this
//! (almost?) never happens.  There could be a public API for adding entries
//! to the CTE tables, but YAGNI for now.  'q' is Quoted Printable, 'b' is
//! Base64.  The meaning of encoded_string should be obvious.  'lang' is optional
//! as indicated by the brackets (they are not part of the syntax) but is almost
//! never encountered in practice.
//!
//! The general interface for a CTE decoder is that it takes the encoded_string
//! as its argument, and returns a tuple (cte_decoded_string, defects).  The
//! cte_decoded_string is the original binary that was encoded using the
//! specified cte.  'defects' is a list of MessageDefect instances indicating any
//! problems encountered during conversion.  'charset' and 'lang' are the
//! corresponding strings extracted from the EW, case preserved.
//!
//! The general interface for a CTE encoder is that it takes a binary sequence
//! as input and returns the cte_encoded_string, which is an ascii-only string.
//!
//! Each decoder must also supply a length function that takes the binary
//! sequence as its argument and returns the length of the resulting encoded
//! string.
//!
//! The main API functions for the module are decode, which calls the decoder
//! referenced by the cte specifier, and encode, which adds the appropriate
//! RFC 2047 "chrome" to the encoded string, and can optionally automatically
//! select the shortest possible encoding.  See their docstrings below for
//! details.

use regex::bytes::{Captures, NoExpand, Regex};
use thiserror::Error;

use crate::charset::Charset;
use crate::defects::Defect;

// -- Quoted Printable

// regex based decoder.

lazy_static::lazy_static! {
    static ref Q_BYTE_RE_1: Regex = Regex::new(r"(_)").unwrap();
    static ref Q_BYTE_RE_2: Regex = Regex::new(r"=([a-fA-F0-9]{2})").unwrap();
}

fn decode_q<T: AsRef<[u8]>>(encoded: T) -> Vec<u8> {
    let one = Q_BYTE_RE_1.replace_all(encoded.as_ref(), NoExpand(b" "));
    Q_BYTE_RE_2
        .replace_all(one.as_ref(), |caps: &Captures| {
            hex::decode(caps[1].as_ref()).expect("invalid regex capture")
        })
        .to_vec()
}

fn write_q_byte<T: std::fmt::Write>(mut writer: T, byte: u8) -> std::fmt::Result {
    match byte {
        b' ' => writer.write_char('_'),
        b'-' | b'!' | b'*' | b'+' | b'/' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => {
            writer.write_char(byte as char)
        }
        _ => write!(writer, "={:02X}", byte),
    }
}

fn encode_q<T: AsRef<[u8]>>(bstring: T) -> String {
    let mut out = String::with_capacity(bstring.as_ref().len());

    for byte in bstring.as_ref() {
        write_q_byte(&mut out, *byte).expect("String writes always succeed");
    }

    out
}

fn len_q<T: AsRef<[u8]>>(bstring: T) -> usize {
    bstring.as_ref().iter().copied().map(len_q_byte).sum()
}

fn len_q_byte(byte: u8) -> usize {
    match byte {
        b' ' => 1,
        b'-' | b'!' | b'*' | b'+' | b'/' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => 1,
        _ => 3,
    }
}

// -- Base64

fn decode_b<T: AsRef<[u8]>>(encoded: T) -> (Vec<u8>, Vec<Defect>) {
    let mut defects = Vec::new();

    let config =
        base64::Config::new(base64::CharacterSet::Standard, true).decode_allow_trailing_bits(true);
    // First try the good case.
    match base64::decode_config(&encoded, config) {
        Ok(decoded) => {
            let pad_err = encoded.as_ref().len() % 4;
            if pad_err > 0 {
                defects.push(Defect::InvalidBase64Padding);
            }

            (decoded, defects)
        }
        Err(err) => match err {
            base64::DecodeError::InvalidByte(_offset, byte) => {
                defects.push(Defect::InvalidBase64Characters { byte });

                // filter out invalid characters
                let encoded: Vec<u8> = encoded
                    .as_ref()
                    .iter()
                    .copied()
                    .filter(|b| match b {
                        0..=42 => false,
                        43 => true,
                        44..=46 => false,
                        47..=57 => true,
                        58..=64 => false,
                        65..=90 => true,
                        91..=96 => false,
                        97..=122 => true,
                        _ => false,
                    })
                    .collect();

                if encoded.len() % 4 > 0 {
                    defects.push(Defect::InvalidBase64Padding);
                }

                match base64::decode_config(&encoded, config) {
                    Ok(decoded) => (decoded, defects),
                    Err(_err) => {
                        // giving up
                        (encoded.to_vec(), defects)
                    }
                }
            }
            base64::DecodeError::InvalidLastSymbol(_offset, _byte) => {
                unreachable!("config disables this error");
            }
            base64::DecodeError::InvalidLength => {
                // Nothing we can do
                defects.push(Defect::InvalidBase64Length);
                (encoded.as_ref().to_vec(), defects)
            }
        },
    }
}

fn encode_b<T: AsRef<[u8]>>(bstring: T) -> String {
    base64::encode(&bstring)
}

fn len_b<T: AsRef<[u8]>>(bstring: T) -> usize {
    let len = bstring.as_ref().len();
    let groups_of_3 = len / 3;
    let leftover = len % 3;

    // 4 bytes out for each 3 bytes (or nonzero fraction thereof) in.
    let padding_len = if leftover > 0 { 4 } else { 0 };
    groups_of_3 * 4 + padding_len
}

/// The result from decoding an encoded word.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodingResult {
    pub decoded: String,
    pub charset: Charset,
    pub lang: String,
    pub defects: Vec<Defect>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DecodingError {
    #[error("Malformed input")]
    MalformedInput,
    #[error("Unknown charset {}", charset)]
    UnknownCharset { charset: String },
}

/// Decode encoded word and return (string, charset, lang, defects) tuple.
///
/// An RFC 2047/2243 encoded word has the form: `=?charset*lang?cte?encoded_string?=`
///
/// where '*lang' may be omitted but the other parts may not be.
///
/// This function expects exactly such a string (that is, it does not check the
/// syntax and may raise errors if the string is not well formed), and returns
/// the encoded_string decoded first from its Content Transfer Encoding and
/// then from the resulting bytes into unicode using the specified charset.  If
/// the cte-decoded string does not successfully decode using the specified
/// character set, a defect is added to the defects list and the unknown octets
/// are replaced by the unicode 'unknown' character \\uFDFF.
///
/// The specified charset and language are returned.  The default for language,
/// which is rarely if ever encountered, is the empty string.
pub fn decode<T: AsRef<str>>(ew: T) -> Result<DecodingResult, DecodingError> {
    let mut split = ew.as_ref().split('?');
    let _ = split.next().ok_or_else(|| DecodingError::MalformedInput)?;
    let charset = split.next().ok_or_else(|| DecodingError::MalformedInput)?;
    let cte = split.next().ok_or_else(|| DecodingError::MalformedInput)?;
    let cte_string = split.next().ok_or_else(|| DecodingError::MalformedInput)?;

    let (charset, lang) = if let Some(index) = charset.find('*') {
        let (charset, lang) = charset.split_at(index);
        (charset, &lang[1..])
    } else {
        (charset, "")
    };

    let mut defects = Vec::new();

    let charset = if charset == "latin-1" {
        // For some resason latin-1 is not repored
        Charset::for_label(b"latin1").unwrap()
    } else {
        match Charset::for_label(charset.as_bytes()) {
            Some(c) => c,
            None => {
                if charset != "unknown-8bit" {
                    defects.push(Defect::InvalidCharset {
                        charset: charset.into(),
                    })
                }
                Charset::Ascii
            }
        }
    };

    let cte = cte.to_lowercase();

    // Recover the original bytes and do CTE decoding.
    let (bstring, has_invalid_ascii) = Charset::Ascii.encode(cte_string);
    if has_invalid_ascii {
        defects.push(Defect::UndecodableBytes);
    }
    let (bstring, new_defects) = match cte.as_str() {
        "q" => (decode_q(bstring), Vec::new()),
        "b" => decode_b(bstring),
        _ => return Err(DecodingError::MalformedInput),
    };
    defects.extend_from_slice(&new_defects);

    // Turn the CTE decoded bytes into unicode.
    let (decoded, has_invalid_bytes) = charset.decode_without_bom_handling(&bstring);

    if has_invalid_bytes {
        defects.push(Defect::UndecodableBytes);
    }

    Ok(DecodingResult {
        decoded: decoded.into(),
        charset,
        lang: lang.into(),
        defects,
    })
}

/// Flags for types of header encodings
pub enum EncodingFlag {
    /// Quoted printable encoding.
    QuotedPrintable,
    /// Base64 encoding.
    Base64,
    /// The shorter of `QuotedPrintable` or `Base64`, but only for headers.
    Shortest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Encoding {
    QuotedPrintable,
    Base64,
}

impl Encoding {
    pub fn decode<T: AsRef<[u8]>>(self, ew: T) -> (Vec<u8>, Vec<Defect>) {
        match self {
            Encoding::QuotedPrintable => (decode_q(ew), Vec::new()),
            Encoding::Base64 => decode_b(ew),
        }
    }

    pub fn encode<T: AsRef<[u8]>>(self, bstring: T) -> String {
        match self {
            Encoding::QuotedPrintable => encode_q(bstring),
            Encoding::Base64 => encode_b(bstring),
        }
    }
    pub fn char(self) -> char {
        match self {
            Encoding::QuotedPrintable => 'q',
            Encoding::Base64 => 'b',
        }
    }
}

/// Encode string using the CTE encoding that produces the shorter result.
///
/// Produces an RFC 2047/2243 encoded word of the form: `=?charset*lang?cte?encoded_string?=`
///
/// where '*lang' is omitted unless the 'lang' parameter is given a value.
/// Optional argument charset (defaults to utf-8) specifies the charset to use
/// to encode the string to binary before CTE encoding it.  Optional argument
/// 'encoding' is the cte specifier for the encoding that should be used ('q'
/// or 'b'); if it is None (the default) the encoding which produces the
/// shortest encoded sequence is used, except that 'q' is preferred if it is up
/// to five characters longer.  Optional argument 'lang' (default '') gives the
/// RFC 2243 language string to specify in the encoded word.
pub fn encode<T: AsRef<str>>(
    ew: T,
    charset: Option<Charset>,
    encoding_flag: EncodingFlag,
    lang: Option<&str>,
) -> String {
    // TODO: is using Charset the right option here? Need to handle utf-7 somehow.
    let charset = charset.unwrap_or_else(|| Charset::Encoding(encoding_rs::UTF_8));
    let (bstring, _) = charset.encode(ew.as_ref());

    let encoding = match encoding_flag {
        EncodingFlag::Base64 => Encoding::Base64,
        EncodingFlag::QuotedPrintable => Encoding::QuotedPrintable,
        EncodingFlag::Shortest => {
            let q_len = len_q(&bstring);
            let b_len = len_b(&bstring);

            // Bias toward q. 5 is arbitrary.
            if q_len as isize - (b_len as isize) < 5 {
                Encoding::QuotedPrintable
            } else {
                Encoding::Base64
            }
        }
    };

    let encoded = encoding.encode(&bstring);
    if let Some(lang) = lang {
        format!(
            "=?{}*{}?{}?{}?=",
            charset.name().to_lowercase(),
            lang,
            encoding.char(),
            encoded
        )
    } else {
        format!(
            "=?{}?{}?{}?=",
            charset.name().to_lowercase(),
            encoding.char(),
            encoded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_q_no_encoded() {
        assert_eq!(&decode_q(b"foobar"), b"foobar");
    }

    #[test]
    fn test_decode_q_spaces() {
        assert_eq!(&decode_q(b"foo=20bar=20"), b"foo bar ");
        assert_eq!(&decode_q(b"foo_bar_"), b"foo bar ");
    }

    #[test]
    fn test_decode_q_encoded() {
        assert_eq!(&decode_q(b"foo=20=20=21=2Cbar"), b"foo  !,bar");
    }

    #[test]
    fn test_decode_b_simple() {
        assert_eq!(decode_b(b"Zm9v"), (b"foo".to_vec(), Vec::new()));
    }

    #[test]
    fn test_decode_b_missing_padding() {
        // 1 missing padding character
        assert_eq!(
            decode_b(b"dmk"),
            (b"vi".to_vec(), vec![Defect::InvalidBase64Padding])
        );
        // 2 missing padding characters
        assert_eq!(
            decode_b(b"dg"),
            (b"v".to_vec(), vec![Defect::InvalidBase64Padding])
        );
    }

    #[test]
    fn test_decode_b_invalid_character() {
        assert_eq!(
            decode_b(b"dm\x01k==="),
            (
                b"vi".to_vec(),
                vec![
                    Defect::InvalidBase64Characters { byte: b'\x01' },
                    Defect::InvalidBase64Padding
                ]
            )
        );
    }

    #[test]
    fn test_decode_b_invalid_character_and_bad_padding() {
        assert_eq!(
            decode_b(b"dm\x01k"),
            (
                b"vi".to_vec(),
                vec![
                    Defect::InvalidBase64Characters { byte: b'\x01' },
                    Defect::InvalidBase64Padding
                ]
            )
        );
    }

    #[test]
    fn test_decode_b_invalid_length() {
        assert_eq!(
            decode_b(b"abcde"),
            (b"abcde".to_vec(), vec![Defect::InvalidBase64Length])
        );
    }

    #[test]
    fn test_decode_wrong_format_input() {
        assert_eq!(decode("=?badone?="), Err(DecodingError::MalformedInput));
        assert_eq!(decode("=?"), Err(DecodingError::MalformedInput));
        assert_eq!(decode(""), Err(DecodingError::MalformedInput));
        assert_eq!(
            decode("=?utf-9?X?somevalue?="),
            Err(DecodingError::MalformedInput)
        );
    }

    #[test]
    fn test_decode_simple_q() {
        assert_eq!(
            decode("=?us-ascii?q?foo?=").unwrap(),
            DecodingResult {
                decoded: "foo".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: Vec::new(),
            }
        );
    }

    #[test]
    fn test_decode_simple_b() {
        assert_eq!(
            decode("=?us-ascii?b?dmk=?=").unwrap(),
            DecodingResult {
                decoded: "vi".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: Vec::new(),
            }
        );
    }

    #[test]
    fn test_decode_case_ignored_q() {
        assert_eq!(
            decode("=?us-ascii?Q?foo?=").unwrap(),
            DecodingResult {
                decoded: "foo".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: Vec::new(),
            }
        );
    }

    #[test]
    fn test_decode_case_ignored_b() {
        assert_eq!(
            decode("=?us-ascii?B?dmk=?=").unwrap(),
            DecodingResult {
                decoded: "vi".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: Vec::new(),
            }
        );
    }

    #[test]
    fn test_decode_non_trivial_q() {
        assert_eq!(
            decode("=?latin-1?q?=20F=fcr=20Elise=20?=").unwrap(),
            DecodingResult {
                decoded: " Für Elise ".into(),
                charset: Charset::for_label(b"latin1").unwrap(),
                lang: "".into(),
                defects: Vec::new(),
            }
        );
    }

    #[test]
    fn test_decode_escaped_bytes_preserved_q() {
        assert_eq!(
            decode("=?us-ascii?q?=20\u{AC}foo?=").unwrap(),
            DecodingResult {
                decoded: " \u{AC}foo".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: vec![/*Defect::UndecodableBytes*/],
            }
        );
    }

    #[test]
    fn test_decode_undecodable_bytes_ignored_with_defect_b() {
        assert_eq!(
            decode("=?us-ascii?b?dm\u{AC}k?=").unwrap(),
            DecodingResult {
                decoded: "vi".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: vec![
                    Defect::InvalidBase64Characters { byte: 172 },
                    Defect::InvalidBase64Padding
                ],
            }
        );
    }

    #[test]
    fn test_decode_invalid_bytes_ignored_with_defect_b() {
        assert_eq!(
            decode("=?us-ascii?b?dm\x01k===?=").unwrap(),
            DecodingResult {
                decoded: "vi".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: vec![
                    Defect::InvalidBase64Characters { byte: 1 },
                    Defect::InvalidBase64Padding
                ],
            }
        );
    }

    #[test]
    fn test_decode_padding_defect_b() {
        assert_eq!(
            decode("=?us-ascii?b?dmk?=").unwrap(),
            DecodingResult {
                decoded: "vi".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: vec![Defect::InvalidBase64Padding],
            }
        );
    }

    #[test]
    fn test_decode_nonnull_lang() {
        assert_eq!(
            decode("=?us-ascii*jive?q?test?=").unwrap(),
            DecodingResult {
                decoded: "test".into(),
                charset: Charset::Ascii,
                lang: "jive".into(),
                defects: vec![],
            }
        );
    }

    #[test]
    fn test_decode_unknown_8bit_charset() {
        assert_eq!(
            decode("=?unknown-8bit?q?foo=ACbar?=").unwrap(),
            DecodingResult {
                decoded: "foo\u{ac}bar".into(),
                charset: Charset::Unknown8Bit,
                lang: "".into(),
                defects: vec![],
            }
        );
    }

    #[test]
    fn test_decode_unknown_charset() {
        assert_eq!(
            decode("=?foobar?q?foo=ACbar?=").unwrap(),
            DecodingResult {
                decoded: "foo\u{ac}bar".into(),
                charset: Charset::Ascii,
                lang: "".into(),
                defects: vec![Defect::InvalidCharset {
                    charset: "foobar".into()
                }],
            }
        );
    }

    #[test]
    fn test_decode_nonascii_q() {
        assert_eq!(
            decode("=?utf-8?q?=C3=89ric?=").unwrap(),
            DecodingResult {
                decoded: "Éric".into(),
                charset: Charset::for_label(b"utf-8").unwrap(),
                lang: "".into(),
                defects: vec![],
            }
        );
    }

    #[test]
    fn test_encode_q_all_safe() {
        assert_eq!(&encode_q(b"foobar"), "foobar");
    }

    #[test]
    fn test_encode_q_spaces() {
        assert_eq!(&encode_q(b"foo bar "), "foo_bar_");
    }

    #[test]
    fn test_encode_q_encodables() {
        assert_eq!(&encode_q(b"foo  ,,bar"), "foo__=2C=2Cbar");
        assert_eq!(len_q(b"foo  ,,bar"), b"foo__=2C=2Cbar".len());
    }

    #[test]
    fn test_encode_b_simple() {
        assert_eq!(&encode_b(b"foo"), "Zm9v");
        assert_eq!(len_b(b"foo"), b"Zm9v".len());
    }

    #[test]
    fn test_encode_b_padding() {
        assert_eq!(&encode_b(b"vi"), "dmk=");
        assert_eq!(len_b(b"vi"), b"dmk=".len());
    }

    #[test]
    fn test_encode_simple_q() {
        assert_eq!(
            &encode(
                "foo",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::QuotedPrintable,
                None,
            ),
            "=?utf-8?q?foo?="
        );
    }

    #[test]
    fn test_encode_simple_b() {
        assert_eq!(
            &encode(
                "foo",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Base64,
                None,
            ),
            "=?utf-8?b?Zm9v?="
        );
    }

    #[test]
    fn test_encode_auto_q() {
        assert_eq!(
            &encode(
                "foo",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Shortest,
                None,
            ),
            "=?utf-8?q?foo?="
        );
    }

    #[test]
    fn test_encode_auto_q_if_short_mostly_safe() {
        assert_eq!(
            &encode(
                "vi.",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Shortest,
                None,
            ),
            "=?utf-8?q?vi=2E?="
        );
    }

    #[test]
    fn test_encode_auto_b_if_enough_unsafe() {
        assert_eq!(
            &encode(
                ".....",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Shortest,
                None,
            ),
            "=?utf-8?b?Li4uLi4=?="
        );
    }

    #[test]
    fn test_encode_auto_b_if_long_unsafe() {
        assert_eq!(
            &encode(
                "vi.vi.vi.vi.vi.",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Shortest,
                None,
            ),
            "=?utf-8?b?dmkudmkudmkudmkudmku?="
        );
    }

    #[test]
    fn test_encode_auto_q_if_mostly_safe() {
        assert_eq!(
            &encode(
                "vi vi vi.vi ",
                Some(encoding_rs::UTF_8.into()),
                EncodingFlag::Shortest,
                None,
            ),
            "=?utf-8?q?vi_vi_vi=2Evi_?="
        );
    }

    #[test]
    fn test_encode_utf8_default() {
        assert_eq!(
            &encode("foo", None, EncodingFlag::Shortest, None,),
            "=?utf-8?q?foo?="
        );
    }

    #[test]
    fn test_encode_lang() {
        assert_eq!(
            &encode("foo", None, EncodingFlag::Shortest, Some("jive")),
            "=?utf-8*jive?q?foo?="
        );
    }
}

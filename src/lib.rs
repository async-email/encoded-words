//! Routines for manipulating RFC2047 encoded words.
//!
//! An ecoded word looks like this: `=?charset[*lang]?cte?encoded_string?=`.

mod charset;
mod defects;
mod encoded_words;

pub use self::charset::Charset;
pub use self::defects::Defect;
pub use self::encoded_words::*;

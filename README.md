# encoded-words

> Routines for manipulating RFC2047 encoded words. Based on the email package from Python 3.


## Example

```rust
use encoded_words::{EncodingFlag, encode};

assert_eq!(
    &encode("foo", None, EncodingFlag::Shortest, None),
    "=?utf-8?q?foo?="
);
```

## License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

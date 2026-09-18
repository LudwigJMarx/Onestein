//! Base32.
//!
//! The vectors are RFC 4648 §10's own, minus the padding this stack does not
//! use. That makes them a foreign oracle in the sense `CONTRIBUTING.md` asks
//! for: the numbers come from the document that defines the encoding, not
//! from this implementation.

use onestein_contact::base32::{Error, decode, encode};

const VECTORS: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "MY"),
    (b"fo", "MZXQ"),
    (b"foo", "MZXW6"),
    (b"foob", "MZXW6YQ"),
    (b"fooba", "MZXW6YTB"),
    (b"foobar", "MZXW6YTBOI"),
];

#[test]
fn the_rfc_vectors_encode_and_decode() {
    for (bytes, text) in VECTORS {
        assert_eq!(encode(bytes), text, "encoding {bytes:?}");
        assert_eq!(decode(text), Ok(bytes.to_vec()), "decoding {text}");
    }
}

// "A reader accepts lower case and ignores whitespace, because a link crosses
// channels that reflow text; an encoder never produces either."
#[test]
fn a_reader_is_forgiving_and_a_writer_is_not() {
    assert_eq!(decode("mzxw6ytboi"), Ok(b"foobar".to_vec()));
    assert_eq!(decode("MZXW 6YTB\nOI"), Ok(b"foobar".to_vec()));
    assert_eq!(encode(b"foobar"), "MZXW6YTBOI");
    assert!(!encode(b"foobar").contains('='));
}

#[test]
fn a_character_outside_the_alphabet_is_refused() {
    assert_eq!(decode("MZXW6YTB!"), Err(Error::NotBase32 { found: '!' }));
    // 0, 1 and 8 are not in the alphabet: they are the ones people confuse
    // with O, I and B, which is why RFC 4648 leaves them out.
    assert_eq!(decode("MZXW0"), Err(Error::NotBase32 { found: '0' }));
    assert_eq!(decode("MZXW6YTB="), Err(Error::NotBase32 { found: '=' }));
}

// Two strings that decode to the same bytes would mean two links for one
// contact, and a fingerprint that compares unequal while meaning the same.
#[test]
fn a_tail_with_bits_left_over_is_refused() {
    assert_eq!(decode("MZ"), Err(Error::NonCanonicalTail));
    assert_eq!(decode("MY"), Ok(b"f".to_vec()));
}

#[test]
fn anything_encoded_comes_back() {
    for length in 0..40usize {
        let bytes: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
        assert_eq!(decode(&encode(&bytes)), Ok(bytes));
    }
}

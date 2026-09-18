//! RFC 4648 base32, upper case, no padding.
//!
//! Written here rather than taken from a crate because it is twenty lines and
//! one dependency less in the piece of this stack that a person retypes by
//! hand. It is not a cryptographic primitive; the rule against writing those
//! stands untouched, and the RFC's own test vectors are the oracle.
//!
//! Spec: `spec/35-contact.md` §4.

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Why a string is not base32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A character that is not in the alphabet, and not whitespace.
    NotBase32 {
        /// The character.
        found: char,
    },
    /// The bits left over at the end are not zero, so two different strings
    /// would decode to the same bytes.
    NonCanonicalTail,
}

/// Encodes bytes, upper case, without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol((buffer >> bits) & 0x1f));
        }
    }
    if bits > 0 {
        // The last group is padded with zero bits, which is what makes the
        // tail check on the reading side possible.
        out.push(symbol((buffer << (5 - bits)) & 0x1f));
    }
    out
}

fn symbol(value: u32) -> char {
    let index = usize::try_from(value).unwrap_or(0);
    let byte = ALPHABET
        .get(index)
        .copied()
        .expect("the value is masked to five bits");
    char::from(byte)
}

/// Decodes a string, accepting lower case and ignoring whitespace.
///
/// # Errors
///
/// [`Error`] for anything that is not this encoding.
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for character in text.chars() {
        if character.is_whitespace() {
            continue;
        }
        let upper = character.to_ascii_uppercase();
        let value = u8::try_from(u32::from(upper))
            .ok()
            .and_then(|byte| ALPHABET.iter().position(|symbol| *symbol == byte))
            .ok_or(Error::NotBase32 { found: character })?;

        buffer = (buffer << 5) | u32::try_from(value).unwrap_or(0);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap_or(0));
        }
    }

    // Anything left over must be the zero bits the encoder padded with. Two
    // strings that decode to the same bytes would be two links for one
    // contact, and a fingerprint that compares unequal while meaning the same.
    if bits > 0 && buffer & ((1 << bits) - 1) != 0 {
        return Err(Error::NonCanonicalTail);
    }
    Ok(out)
}

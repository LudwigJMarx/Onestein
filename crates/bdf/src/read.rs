//! Decoding BDF objects.
//!
//! The reader is strict. Where the specification names the legal values of a
//! field, everything else is refused instead of guessed at: two
//! implementations that disagree about what a byte string means will disagree
//! about the identifiers derived from it, and identifiers are how the rest of
//! the stack decides what it already has.

use crate::{MAX_NESTING, Value};

/// Why a byte string is not a BDF object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended in the middle of an object.
    Truncated,
    /// The first four bits name a type that version 1 does not define, or the
    /// next four bits are not zero where the type requires them to be.
    UnknownType(u8),
    /// An integer claimed a length other than 1, 2, 4 or 8.
    InvalidIntLength(u8),
    /// A float claimed a length other than 8.
    InvalidFloatLength(u8),
    /// A string or raw value claimed a length-of-length other than 1, 2, 4
    /// or 8.
    InvalidLengthOfLength(u8),
    /// A length is a two's complement integer, so it can be negative on the
    /// wire. It cannot be negative in meaning.
    NegativeLength(i64),
    /// A length pointed past the end of the input. Held separately from
    /// [`Error::Truncated`] because nothing is allocated for it.
    LengthBeyondInput {
        /// Bytes the length asked for.
        needed: u64,
        /// Bytes left in the input.
        available: usize,
    },
    /// A string was not valid UTF-8.
    InvalidUtf8,
    /// An End object appeared where a value belongs.
    UnexpectedEnd,
    /// A dictionary key was not a String object.
    KeyNotAString,
    /// Containers nested deeper than [`MAX_NESTING`].
    TooDeeplyNested,
    /// The first object ended before the input did.
    TrailingBytes(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "input ended inside an object"),
            Self::UnknownType(h) => write!(f, "header {h:#04x} is not a version 1 object"),
            Self::InvalidIntLength(n) => write!(f, "integer length {n} is not 1, 2, 4 or 8"),
            Self::InvalidFloatLength(n) => write!(f, "float length {n} is not 8"),
            Self::InvalidLengthOfLength(n) => {
                write!(f, "length-of-length {n} is not 1, 2, 4 or 8")
            }
            Self::NegativeLength(n) => write!(f, "length {n} is negative"),
            Self::LengthBeyondInput { needed, available } => {
                write!(f, "length {needed} exceeds the {available} bytes left")
            }
            Self::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            Self::UnexpectedEnd => write!(f, "End appeared where a value belongs"),
            Self::KeyNotAString => write!(f, "dictionary key is not a String"),
            Self::TooDeeplyNested => write!(f, "nested deeper than {MAX_NESTING} containers"),
            Self::TrailingBytes(n) => write!(f, "{n} bytes left after the first object"),
        }
    }
}

impl core::error::Error for Error {}

const END: u8 = 0x80;

/// Decodes one BDF object and requires the input to end there.
///
/// # Errors
///
/// Returns [`Error`] for any byte string that is not exactly one object.
pub fn from_bytes(input: &[u8]) -> Result<Value, Error> {
    let mut reader = Reader { input, pos: 0 };
    let value = reader.value(0)?;
    let left = input.len().saturating_sub(reader.pos);
    if left == 0 {
        Ok(value)
    } else {
        Err(Error::TrailingBytes(left))
    }
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self.input.get(self.pos).ok_or(Error::Truncated)?;
        self.pos = self.pos.saturating_add(1);
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Reads `count` bytes without trusting `count`: a length of 2^62 has to
    /// cost nothing until the bytes are actually there.
    fn take(&mut self, count: u64) -> Result<&[u8], Error> {
        let available = self.input.len().saturating_sub(self.pos);
        let count_usize = usize::try_from(count).map_err(|_| Error::LengthBeyondInput {
            needed: count,
            available,
        })?;
        if count_usize > available {
            return Err(Error::LengthBeyondInput {
                needed: count,
                available,
            });
        }
        let end = self.pos.saturating_add(count_usize);
        let slice = self.input.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Big-endian two's complement over 1, 2, 4 or 8 bytes.
    fn signed(&mut self, length: u8) -> Result<i64, Error> {
        if !matches!(length, 1 | 2 | 4 | 8) {
            return Err(Error::InvalidIntLength(length));
        }
        let mut value: i64 = 0;
        let mut first = true;
        for _ in 0..length {
            let byte = self.byte()?;
            if first {
                // Sign-extend from the first byte, then shift the rest in.
                value = i64::from(byte as i8);
                first = false;
            } else {
                value = value.wrapping_shl(8) | i64::from(byte);
            }
        }
        Ok(value)
    }

    fn length(&mut self, length_of_length: u8) -> Result<u64, Error> {
        if !matches!(length_of_length, 1 | 2 | 4 | 8) {
            return Err(Error::InvalidLengthOfLength(length_of_length));
        }
        let signed = self.signed(length_of_length)?;
        u64::try_from(signed).map_err(|_| Error::NegativeLength(signed))
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        let header = self.byte()?;
        let kind = header >> 4;
        let low = header & 0x0f;
        match kind {
            0 if low == 0 => Ok(Value::Null),
            1 if low <= 1 => Ok(Value::Bool(low == 1)),
            2 => Ok(Value::Int(self.signed(low)?)),
            3 => {
                if low != 8 {
                    return Err(Error::InvalidFloatLength(low));
                }
                let bytes = self.take(8)?;
                let mut buffer = [0u8; 8];
                for (slot, byte) in buffer.iter_mut().zip(bytes) {
                    *slot = *byte;
                }
                Ok(Value::Float(f64::from_be_bytes(buffer)))
            }
            4 => {
                let length = self.length(low)?;
                let bytes = self.take(length)?.to_vec();
                String::from_utf8(bytes)
                    .map(Value::Str)
                    .map_err(|_| Error::InvalidUtf8)
            }
            5 => {
                let length = self.length(low)?;
                Ok(Value::Raw(self.take(length)?.to_vec()))
            }
            6 if low == 0 => {
                let depth = self.deeper(depth)?;
                let mut items = Vec::new();
                while self.peek() != Some(END) {
                    items.push(self.value(depth)?);
                }
                self.pos = self.pos.saturating_add(1);
                Ok(Value::List(items))
            }
            7 if low == 0 => {
                let depth = self.deeper(depth)?;
                let mut entries = Vec::new();
                while self.peek() != Some(END) {
                    let Value::Str(key) = self.value(depth)? else {
                        return Err(Error::KeyNotAString);
                    };
                    entries.push((key, self.value(depth)?));
                }
                self.pos = self.pos.saturating_add(1);
                Ok(Value::Dict(entries))
            }
            8 => Err(Error::UnexpectedEnd),
            _ => Err(Error::UnknownType(header)),
        }
    }

    /// One level down, or a refusal. Input arrives from the network, and a
    /// reader that recurses as deep as the sender says is a crash waiting for
    /// a sender who cares.
    fn deeper(&self, depth: usize) -> Result<usize, Error> {
        let next = depth.saturating_add(1);
        if next > MAX_NESTING {
            Err(Error::TooDeeplyNested)
        } else {
            Ok(next)
        }
    }
}

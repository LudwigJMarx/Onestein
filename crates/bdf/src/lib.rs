//! Binary Data Format (BDF) version 1.
//!
//! BDF is the encoding the Bramble protocols are written in. Six primitive
//! types (null, boolean, integer, float, string, raw) and two container types
//! (list, dictionary). The first four bits of every object give its type, the
//! next four give the value, the length, or the length of the length.
//!
//! This crate is written from the specification alone. It has no dependencies.

#![forbid(unsafe_code)]

mod read;
mod write;

/// How deeply containers may nest before the reader refuses the input.
///
/// The specification does not name a limit. This one is ours, and it is a
/// conformance risk in both directions: data the Java implementation accepts
/// may be refused here. Settle it against that implementation before the
/// first release.
pub const MAX_NESTING: usize = 64;

pub use read::{Error, from_bytes};
pub use write::to_bytes;

/// A BDF object.
///
/// A dictionary keeps its entries in the order they appeared on the wire,
/// because the wire order is what a signature covers. Use
/// [`Value::is_canonical`] to ask whether an object is in the form required
/// for hashing and signing.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Type 0.
    Null,
    /// Type 1.
    Bool(bool),
    /// Type 2, encoded in 1, 2, 4 or 8 bytes, big-endian two's complement.
    Int(i64),
    /// Type 3, encoded in 8 bytes, IEEE 754.
    Float(f64),
    /// Type 4, UTF-8.
    Str(String),
    /// Type 5, opaque bytes.
    Raw(Vec<u8>),
    /// Type 6, terminated by an End object.
    List(Vec<Value>),
    /// Type 7, terminated by an End object.
    Dict(Vec<(String, Value)>),
}

impl Value {
    /// Whether this object is in the form the specification asks for when
    /// data is to be hashed or signed: dictionary keys unique and sorted in
    /// lexicographic order, recursively.
    ///
    /// Minimal integer and length encodings are the other half of that rule,
    /// and they are not visible here: [`to_bytes`] always writes them.
    ///
    /// Lexicographic order is taken over the UTF-8 bytes of the keys. Java
    /// compares strings by UTF-16 code unit, which orders the supplementary
    /// planes before U+E000 to U+FFFF rather than after. No Briar client is
    /// known to use such keys, but the two orders are not the same order, and
    /// this is where they would part.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        match self {
            Self::List(items) => items.iter().all(Self::is_canonical),
            Self::Dict(entries) => {
                let sorted = entries
                    .iter()
                    .zip(entries.iter().skip(1))
                    .all(|((left, _), (right, _))| left.as_bytes() < right.as_bytes());
                sorted && entries.iter().all(|(_, value)| value.is_canonical())
            }
            _ => true,
        }
    }
}

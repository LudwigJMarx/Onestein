//! The record framing shared by the handshake and the sync layer.
//!
//! ```text
//! record_header = int_8(layer_version) || int_8(record_type) || int_16(len(payload))
//! record = record_header || payload
//! ```
//!
//! Defined here rather than in either layer, because a wire format used by
//! two layers and specified in one of them is a dependency in the wrong
//! direction.
//!
//! Spec: `spec/05-primitives.md` §4.

#![forbid(unsafe_code)]

/// Bytes of header before every payload.
pub const HEADER_LEN: usize = 4;

/// The longest payload a record may carry.
pub const MAX_PAYLOAD_LEN: usize = 48 * 1024;

/// One record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// The version of the layer that owns this record.
    pub version: u8,
    /// The record type, meaningful only to that layer.
    pub record_type: u8,
    /// The payload, as it lay on the wire.
    pub payload: &'a [u8],
}

/// Why a record could not be written or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The payload is longer than [`MAX_PAYLOAD_LEN`].
    PayloadTooLong {
        /// Bytes given.
        given: usize,
    },
    /// The input ended inside a record.
    Truncated {
        /// Bytes still expected.
        expected: usize,
        /// Bytes left.
        given: usize,
    },
    /// A record announced a version this reader does not speak. Refusing it is
    /// what stops a peer being talked down to an older layer.
    UnknownVersion {
        /// The version this reader speaks.
        expected: u8,
        /// The version on the wire.
        given: u8,
    },
}

/// Writes one record.
///
/// # Errors
///
/// [`Error::PayloadTooLong`].
pub fn encode(version: u8, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_PAYLOAD_LEN)
        .ok_or(Error::PayloadTooLong {
            given: payload.len(),
        })?;

    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
    out.push(version);
    out.push(record_type);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reads a sequence of records from one stream.
///
/// Unknown **types** are handed to the caller, which is the only party that
/// knows which types it has: `05-primitives.md` §4 has a peer ignore a record
/// whose type it does not know, so that a later addition passes through an
/// older peer. Unknown **versions** never reach the caller.
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    version: u8,
    stopped: bool,
}

impl<'a> Reader<'a> {
    /// A reader over `input`, speaking one layer version.
    #[must_use]
    pub const fn new(input: &'a [u8], version: u8) -> Self {
        Self {
            input,
            pos: 0,
            version,
            stopped: false,
        }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Record<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        let remaining = self.remaining();
        if remaining == 0 {
            return None;
        }
        // Every refusal stops the reader. Whatever follows a record we could
        // not parse is at an offset we are guessing at, and guessing at
        // offsets is how a parser starts reading a payload as a header.
        self.stopped = true;

        if remaining < HEADER_LEN {
            return Some(Err(Error::Truncated {
                expected: HEADER_LEN,
                given: remaining,
            }));
        }
        let mut header = [0u8; HEADER_LEN];
        for (slot, byte) in header.iter_mut().zip(self.input.iter().skip(self.pos)) {
            *slot = *byte;
        }
        let [version, record_type, length_high, length_low] = header;

        if version != self.version {
            return Some(Err(Error::UnknownVersion {
                expected: self.version,
                given: version,
            }));
        }
        let length = usize::from(u16::from_be_bytes([length_high, length_low]));
        if length > MAX_PAYLOAD_LEN {
            return Some(Err(Error::PayloadTooLong { given: length }));
        }
        let available = remaining.saturating_sub(HEADER_LEN);
        if available < length {
            return Some(Err(Error::Truncated {
                expected: length,
                given: available,
            }));
        }

        let start = self.pos.saturating_add(HEADER_LEN);
        let end = start.saturating_add(length);
        let payload = self.input.get(start..end)?;
        self.pos = end;
        self.stopped = false;
        Some(Ok(Record {
            version,
            record_type,
            payload,
        }))
    }
}

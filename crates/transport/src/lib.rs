//! Time-based key management for the transport layer.
//!
//! Keys are derived from a root key, rotated once per time period, and
//! deleted when the period passes. Forward secrecy comes from the derivation
//! being one-way: this crate can move keys forward in time and has no way to
//! move them back.
//!
//! Spec: `spec/20-transport.md`.

#![forbid(unsafe_code)]

mod wire;

pub use wire::{
    AUTH_LEN, FRAME_HEADER_LEN, FrameHeader, MAX_FRAME_LEN, MAX_FRAME_NUMBER, MAX_FRAME_PAYLOAD,
    NONCE_LEN, STREAM_HEADER_LEN, StreamHeader, WireError, open_frame_body, open_frame_header,
    open_stream_header, seal_frame_body, seal_frame_header, seal_stream_header,
};

use onestein_crypto::{HASH_LEN, kdf, prf};

const A_TAG_KEY: &[u8] = b"org.onestein.transport/A_TAG_KEY";
const A_HEADER_KEY: &[u8] = b"org.onestein.transport/A_HEADER_KEY";
const B_TAG_KEY: &[u8] = b"org.onestein.transport/B_TAG_KEY";
const B_HEADER_KEY: &[u8] = b"org.onestein.transport/B_HEADER_KEY";
const ROTATE: &[u8] = b"org.onestein.transport/ROTATE";

/// Transport layer version, in every tag and stream header.
pub const TRANSPORT_VERSION: u8 = 1;

/// Length of a stream tag in bytes.
pub const TAG_LEN: usize = 16;

/// The largest number of periods this crate will rotate in one step.
///
/// About three years on a 25-hour period. The period being rotated towards
/// comes from a clock, and a clock can be moved by someone else; without a
/// bound, one wrong number is an unbounded loop in a layer that has not
/// authenticated anything yet.
pub const MAX_ROTATIONS: u64 = 1024;

/// A transport, with the period length that `spec/20-transport.md` §4 fixes
/// for it.
///
/// The period length is normative. Two peers that disagree about it derive
/// different keys, and the symptom is a network that looks broken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transport {
    id: &'static str,
    period_seconds: u64,
}

impl Transport {
    /// The identifier that goes into the key derivation.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// D + L in seconds.
    #[must_use]
    pub const fn period_seconds(&self) -> u64 {
        self.period_seconds
    }
}

/// Tor, or any routed network. D = 24 h, L = 1 h.
pub const TOR: Transport = Transport {
    id: "org.onestein.transport.tor",
    period_seconds: 25 * 3600,
};

/// A local network. D = 24 h, L = 1 h.
pub const LAN: Transport = Transport {
    id: "org.onestein.transport.lan",
    period_seconds: 25 * 3600,
};

/// Bluetooth. D = 24 h, L = 1 h.
pub const BLUETOOTH: Transport = Transport {
    id: "org.onestein.transport.bluetooth",
    period_seconds: 25 * 3600,
};

/// Removable media. D = 24 h, L = 30 d.
pub const MEDIA: Transport = Transport {
    id: "org.onestein.transport.media",
    period_seconds: 31 * 24 * 3600,
};

/// A relay. D = 24 h, L = 30 d.
pub const RELAY: Transport = Transport {
    id: "org.onestein.transport.relay",
    period_seconds: 31 * 24 * 3600,
};

/// Which side of the pair a device is, decided by the order of the two
/// identity identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The device whose identity identifier sorts earlier.
    A,
    /// The other one.
    B,
}

/// Why keys could not be derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The agreed timestamp falls in period 0, so there is no period before
    /// it for the initial keys to belong to.
    TimestampTooEarly,
    /// Rotation only moves forward. This is forward secrecy, not a check.
    PeriodInThePast {
        /// The period the keys are in.
        current: u64,
        /// The period asked for.
        requested: u64,
    },
    /// Further ahead than [`MAX_ROTATIONS`].
    TooFarAhead {
        /// Periods that would have to be derived.
        periods: u64,
    },
}

/// The two keys for one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectionKeys {
    /// Generates the tags that let the recipient recognise a stream.
    pub tag_key: [u8; HASH_LEN],
    /// Encrypts the stream header.
    pub header_key: [u8; HASH_LEN],
}

/// Both directions' keys for one period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodKeys {
    /// The period these keys belong to.
    pub period: u64,
    /// Keys for streams this device sends.
    pub outgoing: DirectionKeys,
    /// Keys for streams this device receives.
    pub incoming: DirectionKeys,
}

impl Transport {
    /// The period a timestamp falls in. Period zero starts at the Unix epoch.
    #[must_use]
    pub fn period_at(&self, timestamp_ms: u64) -> u64 {
        (timestamp_ms / 1_000) / self.period_seconds
    }
}

impl PeriodKeys {
    /// Derives the initial keys, which belong to the period **before** the one
    /// containing the agreed timestamp.
    ///
    /// # Errors
    ///
    /// [`Error::TimestampTooEarly`] if the timestamp falls in period zero.
    pub fn initial(
        root_key: &[u8; HASH_LEN],
        transport: &Transport,
        role: Role,
        timestamp_ms: u64,
    ) -> Result<Self, Error> {
        let period = transport
            .period_at(timestamp_ms)
            .checked_sub(1)
            .ok_or(Error::TimestampTooEarly)?;
        let mine = match role {
            Role::A => (A_TAG_KEY, A_HEADER_KEY),
            Role::B => (B_TAG_KEY, B_HEADER_KEY),
        };
        let theirs = match role {
            Role::A => (B_TAG_KEY, B_HEADER_KEY),
            Role::B => (A_TAG_KEY, A_HEADER_KEY),
        };
        let id = transport.id.as_bytes();
        Ok(Self {
            period,
            outgoing: DirectionKeys {
                tag_key: kdf(root_key, &[mine.0, id]),
                header_key: kdf(root_key, &[mine.1, id]),
            },
            incoming: DirectionKeys {
                tag_key: kdf(root_key, &[theirs.0, id]),
                header_key: kdf(root_key, &[theirs.1, id]),
            },
        })
    }

    /// Rotates forward to a later period.
    ///
    /// # Errors
    ///
    /// [`Error::PeriodInThePast`] because the derivation is one-way, and
    /// [`Error::TooFarAhead`] beyond [`MAX_ROTATIONS`].
    pub fn rotate_to(&self, period: u64) -> Result<Self, Error> {
        if period < self.period {
            return Err(Error::PeriodInThePast {
                current: self.period,
                requested: period,
            });
        }
        let steps = period.saturating_sub(self.period);
        if steps > MAX_ROTATIONS {
            return Err(Error::TooFarAhead { periods: steps });
        }
        let mut keys = *self;
        for next in (self.period.saturating_add(1))..=period {
            let counter = next.to_be_bytes();
            for key in [
                &mut keys.outgoing.tag_key,
                &mut keys.outgoing.header_key,
                &mut keys.incoming.tag_key,
                &mut keys.incoming.header_key,
            ] {
                *key = kdf(key, &[ROTATE, &counter]);
            }
        }
        keys.period = period;
        Ok(keys)
    }
}

/// The tag that starts a stream.
#[must_use]
pub fn tag(tag_key: &[u8; HASH_LEN], stream_number: u64) -> [u8; TAG_LEN] {
    let version = u16::from(TRANSPORT_VERSION).to_be_bytes();
    let number = stream_number.to_be_bytes();
    let mut message = [0u8; 10];
    for (slot, byte) in message.iter_mut().zip(version.iter().chain(number.iter())) {
        *slot = *byte;
    }
    let full = prf(tag_key, &message);
    let mut out = [0u8; TAG_LEN];
    for (slot, byte) in out.iter_mut().zip(full.iter()) {
        *slot = *byte;
    }
    out
}

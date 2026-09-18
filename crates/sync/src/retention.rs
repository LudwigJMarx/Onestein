//! What a device keeps, and what it may drop.
//!
//! Advice, not a rule. A member may keep more, and nothing detects a member
//! that keeps less: a policy that claimed to bind other people's devices
//! would be a promise about a device the promiser does not own.
//!
//! Spec: `spec/50-sync.md` §6.

use std::collections::BTreeSet;

use onestein_bdf::{Value, from_bytes_canonical, to_bytes};

use crate::{Error, MessageId};

/// Milliseconds in a day.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// How much of a group a device intends to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep everything.
    All,
    /// Keep at least the most recently received `n` messages.
    Count(u32),
    /// Keep at least what arrived within the last `days`.
    Age {
        /// Days, counted from when this device received a message.
        days: u32,
    },
}

impl Retention {
    /// Encodes the policy as canonical BDF, so a client can put it where
    /// every member sees the same advice.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let fields = match self {
            Self::All => vec![("k".to_owned(), Value::Str("all".to_owned()))],
            Self::Count(count) => vec![
                ("k".to_owned(), Value::Str("count".to_owned())),
                ("n".to_owned(), Value::Int(i64::from(*count))),
            ],
            Self::Age { days } => vec![
                ("k".to_owned(), Value::Str("age".to_owned())),
                ("n".to_owned(), Value::Int(i64::from(*days))),
            ],
        };
        let value = Value::Dict(fields);
        debug_assert!(value.is_canonical(), "k sorts before n");
        to_bytes(&value)
    }

    /// Reads a policy.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything that is not one of the three.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Ok(Value::Dict(fields)) = from_bytes_canonical(bytes) else {
            return Err(Error::Malformed);
        };
        let kind = match fields.iter().find(|(key, _)| key == "k") {
            Some((_, Value::Str(kind))) => kind.as_str(),
            _ => return Err(Error::Malformed),
        };
        let number = || match fields.iter().find(|(key, _)| key == "n") {
            Some((_, Value::Int(number))) => u32::try_from(*number).map_err(|_| Error::Malformed),
            _ => Err(Error::Malformed),
        };
        // An unexpected key means a policy this version does not understand,
        // and guessing at it would keep less than its author asked for.
        let expected = if kind == "all" { 1 } else { 2 };
        if fields.len() != expected {
            return Err(Error::Malformed);
        }
        match kind {
            "all" => Ok(Self::All),
            "count" => Ok(Self::Count(number()?)),
            "age" => Ok(Self::Age { days: number()? }),
            _ => Err(Error::Malformed),
        }
    }

    /// Which messages this policy allows dropping, given what the device
    /// holds.
    ///
    /// The caller passes each message with the time **this device** received
    /// it. The timestamp inside a message is what its author wrote, and a
    /// policy that read it would let the author decide when the reader
    /// deletes.
    ///
    /// Returns identifiers in the order they were given, so a caller can keep
    /// its own ordering.
    #[must_use]
    pub fn droppable(&self, now_ms: u64, held: &[(MessageId, u64)]) -> Vec<MessageId> {
        match self {
            Self::All => Vec::new(),
            Self::Count(count) => {
                let mut newest_first: Vec<(usize, u64)> = held
                    .iter()
                    .enumerate()
                    .map(|(index, (_, received))| (index, *received))
                    .collect();
                // Ties keep the order the caller gave, so two messages that
                // arrived in the same millisecond are not dropped at random.
                newest_first.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
                let keep: BTreeSet<usize> = newest_first
                    .into_iter()
                    .take(usize::try_from(*count).unwrap_or(usize::MAX))
                    .map(|(index, _)| index)
                    .collect();
                held.iter()
                    .enumerate()
                    .filter(|(index, _)| !keep.contains(index))
                    .map(|(_, (id, _))| *id)
                    .collect()
            }
            Self::Age { days } => {
                let window = u64::from(*days).saturating_mul(DAY_MS);
                // A receipt time ahead of the clock keeps the message: a clock
                // that jumped backwards must not empty a group.
                let cutoff = now_ms.saturating_sub(window);
                held.iter()
                    .filter(|(_, received)| *received < cutoff)
                    .map(|(id, _)| *id)
                    .collect()
            }
        }
    }
}

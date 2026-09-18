//! Reordering windows, and the counter on the sending side.
//!
//! Both are state that must survive a restart, and neither is stored here:
//! this crate hands the numbers to the caller and takes them back. Where they
//! live, and whether they can be wiped, is the application's decision.
//!
//! Spec: `spec/20-transport.md` §7.

use onestein_crypto::HASH_LEN;

use crate::{TAG_LEN, tag};

/// How many stream numbers a window covers.
///
/// The specification sets a floor of 32 and leaves the rest open. This is the
/// floor: a wider window tolerates more reordering and costs more stored
/// tags, and nothing in the protocol depends on both sides choosing alike.
pub const WINDOW_LEN: u64 = 32;

// The floor is normative and the seen bits are a u32, so both ends of the
// choice are checked where the choice is made rather than where it is used.
const _: () = assert!(
    WINDOW_LEN >= 32,
    "spec/20-transport.md §7 sets the floor at 32"
);
const _: () = assert!(WINDOW_LEN <= 32, "the seen bits are a u32");

/// Why a stream number was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The window has already slid past this number, so the stream can no
    /// longer be recognised. Not an attack by itself: a stream delayed longer
    /// than the window is wide looks exactly like this.
    AlreadyPassed {
        /// The number offered.
        stream_number: u64,
        /// The lowest number the window still covers.
        base: u64,
    },
    /// Further ahead than the window reaches.
    OutsideWindow {
        /// The number offered.
        stream_number: u64,
        /// The first number beyond the window.
        limit: u64,
    },
    /// Seen before. This is the replay.
    AlreadySeen {
        /// The number offered.
        stream_number: u64,
    },
    /// The period's stream numbers are used up, which is 2^64 streams and
    /// therefore a bug somewhere else.
    CounterExhausted,
}

/// One window: the stream numbers from `base` to `base + WINDOW_LEN`, each
/// marked seen or unseen.
///
/// A device keeps one of these per time period, for the previous, current and
/// next period, and per peer and transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    base: u64,
    seen: u32,
}

impl Window {
    /// A window at the start of a period, with nothing seen.
    #[must_use]
    pub const fn new() -> Self {
        Self { base: 0, seen: 0 }
    }

    /// Restores a window from the two numbers the caller stored.
    #[must_use]
    pub const fn restore(base: u64, seen: u32) -> Self {
        Self { base, seen }
    }

    /// The lowest stream number the window still covers.
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// The seen bits, lowest number in the lowest bit. Store this and `base`.
    #[must_use]
    pub const fn seen(&self) -> u32 {
        self.seen
    }

    /// Whether this stream number is inside the window and already seen.
    #[must_use]
    pub fn is_seen(&self, stream_number: u64) -> bool {
        self.offset(stream_number)
            .is_some_and(|offset| self.seen & (1 << offset) != 0)
    }

    /// The bit position of a stream number, if the window covers it.
    fn offset(&self, stream_number: u64) -> Option<u32> {
        let offset = stream_number.checked_sub(self.base)?;
        if offset >= WINDOW_LEN {
            return None;
        }
        u32::try_from(offset).ok()
    }

    /// One place forward: the lowest number leaves the window.
    fn slide(&mut self) {
        self.base = self.base.saturating_add(1);
        self.seen >>= 1;
    }

    /// Marks a stream number as seen and slides the window.
    ///
    /// # Errors
    ///
    /// [`WindowError`] for a number the window has passed, one beyond its
    /// reach, or one already seen.
    pub fn mark_seen(&mut self, stream_number: u64) -> Result<(), WindowError> {
        if stream_number < self.base {
            return Err(WindowError::AlreadyPassed {
                stream_number,
                base: self.base,
            });
        }
        let limit = self.base.saturating_add(WINDOW_LEN);
        let Some(offset) = self.offset(stream_number) else {
            return Err(WindowError::OutsideWindow {
                stream_number,
                limit,
            });
        };
        let bit = 1u32 << offset;
        if self.seen & bit != 0 {
            return Err(WindowError::AlreadySeen { stream_number });
        }
        self.seen |= bit;

        // "Slide the window until all tags in the top half of the window are
        // unseen." The top half is what gives the sender room to run ahead.
        let top_half = u32::MAX << (WINDOW_LEN / 2);
        while self.seen & top_half != 0 {
            self.slide();
        }
        // "Slide the window until the lowest tag in the window is unseen."
        while self.seen & 1 != 0 {
            self.slide();
        }
        Ok(())
    }

    /// The tags this window would recognise, with the stream numbers they
    /// belong to.
    ///
    /// The caller keeps them in whatever lookup it likes; this crate does not
    /// hold a table across calls.
    pub fn expected(&self, tag_key: &[u8; HASH_LEN]) -> impl Iterator<Item = (u64, [u8; TAG_LEN])> {
        let key = *tag_key;
        (self.base..self.base.saturating_add(WINDOW_LEN))
            .map(move |number| (number, tag(&key, number)))
    }
}

/// The count of streams sent to one peer in one period.
///
/// Losing it repeats a tag, and a repeated tag is the one thing on this wire
/// that is recognisably not random. It is therefore written down before a
/// stream is sent, not after.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamCounter {
    next: u64,
    exhausted: bool,
}

impl StreamCounter {
    /// A counter at the start of a period.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: 0,
            exhausted: false,
        }
    }

    /// Restores the counter from the number the caller stored.
    #[must_use]
    pub const fn restore(next: u64) -> Self {
        Self {
            next,
            exhausted: false,
        }
    }

    /// The number the next stream will use, to be stored before it is used.
    #[must_use]
    pub const fn peek(&self) -> u64 {
        self.next
    }

    /// Takes the next stream number.
    ///
    /// # Errors
    ///
    /// [`WindowError::CounterExhausted`] when the period's numbers are used up.
    pub fn take(&mut self) -> Result<u64, WindowError> {
        if self.exhausted {
            return Err(WindowError::CounterExhausted);
        }
        let number = self.next;
        match self.next.checked_add(1) {
            Some(following) => self.next = following,
            // Hand out the last number, then stop. Wrapping here would repeat
            // every tag of the period from the beginning.
            None => self.exhausted = true,
        }
        Ok(number)
    }
}

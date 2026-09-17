//! The hash construction the Bramble protocols are built on.
//!
//! BSP defines a multi-argument hash function over a plain hash function H:
//!
//! ```text
//! HASH(x_1, ..., x_n) = H(int_32(len(x_1)) || x_1 || ... || int_32(len(x_n)) || x_n)
//! ```
//!
//! The length prefixes are the point of it. Without them, HASH("a", "bc") and
//! HASH("ab", "c") would be the same hash, and an attacker could move the
//! boundary between two arguments without changing the result.
//!
//! H is BLAKE2b with a 32-byte output, so HASH_LEN is 32.

#![forbid(unsafe_code)]

use blake2::{Blake2b256, Digest};

/// Length of every hash in the Bramble protocols, in bytes.
pub const HASH_LEN: usize = 32;

/// The multi-argument hash function.
///
/// # Panics
///
/// If an argument is longer than `u32::MAX` bytes, which the construction
/// cannot express. Every caller in the Bramble protocols is bounded far below
/// that (16 KiB for a group descriptor, 32 KiB for a message body), so this
/// is a programming error, and a loud one beats a hash that silently frames
/// the wrong length.
#[must_use]
pub fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2b256::new();
    for part in parts {
        let length = u32::try_from(part.len())
            .expect("a hash argument longer than u32::MAX is outside the construction");
        hasher.update(length.to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

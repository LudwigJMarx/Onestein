//! Keyed constructions: the pseudo-random function and the key derivation
//! function of `spec/05-primitives.md` §2 and §3.
//!
//! In their own module because `Mac` and `Digest` both offer `update`, and a
//! file where both are in scope is a file where the compiler asks which one
//! is meant.

use blake2::Blake2bMac;
use blake2::digest::{KeyInit, Mac, consts::U32};

use crate::HASH_LEN;

type Blake2bMac256 = Blake2bMac<U32>;

fn keyed(key: &[u8; HASH_LEN]) -> Blake2bMac256 {
    Blake2bMac256::new_from_slice(key).expect("32 bytes is a valid BLAKE2b key length")
}

fn finish(mac: Blake2bMac256) -> [u8; HASH_LEN] {
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

/// A pseudo-random function: keyed BLAKE2b over the message as given, with no
/// framing.
///
/// For inputs of a fixed shape, such as a version and a counter. Where the
/// input is a list of variable-length values, use [`kdf`], or the boundary
/// between two of them can be moved without changing the output.
#[must_use]
pub fn prf(key: &[u8; HASH_LEN], message: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = keyed(key);
    Mac::update(&mut mac, message);
    finish(mac)
}

/// The key derivation function: [`prf`] over the framing that
/// [`crate::hash`] uses.
///
/// # Panics
///
/// If an argument is longer than `u32::MAX` bytes, for the reason given at
/// [`crate::hash`].
#[must_use]
pub fn kdf(key: &[u8; HASH_LEN], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut mac = keyed(key);
    for part in parts {
        let length = u32::try_from(part.len())
            .expect("a derivation argument longer than u32::MAX is outside the construction");
        Mac::update(&mut mac, &length.to_be_bytes());
        Mac::update(&mut mac, part);
    }
    finish(mac)
}

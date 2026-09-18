//! The wire: a stream tag, a stream header, and frames.
//!
//! Nothing here is in plaintext and nothing is a fixed byte a classifier can
//! match. The tag looks random because it is the output of a keyed function,
//! the header is encrypted under a key that rotates, and every frame is the
//! same shape whatever it carries.
//!
//! Spec: `spec/20-transport.md` §6.

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use onestein_crypto::HASH_LEN;

use crate::TRANSPORT_VERSION;

/// Length of an AEAD nonce.
pub const NONCE_LEN: usize = 24;

/// Length of an AEAD authentication tag.
pub const AUTH_LEN: usize = 16;

/// Length of a stream header on the wire: nonce, version, stream number,
/// ephemeral key, tag.
pub const STREAM_HEADER_LEN: usize = NONCE_LEN + 2 + 8 + HASH_LEN + AUTH_LEN;

/// Length of an encrypted frame header.
pub const FRAME_HEADER_LEN: usize = 4 + AUTH_LEN;

/// The most data and padding one frame may carry.
pub const MAX_FRAME_PAYLOAD: usize = 988;

/// The most an encrypted frame may occupy, header included.
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD + AUTH_LEN;

/// A stream must not contain more than 2^63 frames, because the top bit of
/// the frame number is the header flag in the nonce.
pub const MAX_FRAME_NUMBER: u64 = u64::MAX >> 1;

/// What a stream header carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    /// Which stream this is, counted from zero within the time period.
    pub stream_number: u64,
    /// The key the rest of the stream is encrypted under.
    pub cipher_key: [u8; HASH_LEN],
}

/// What a frame header carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Bytes of data in this frame.
    pub data_len: u16,
    /// Bytes of padding in this frame.
    pub padding_len: u16,
    /// Whether this is the last frame of the stream.
    pub final_frame: bool,
}

/// Why a piece of the wire could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The authentication tag did not verify: wrong key, wrong nonce, or
    /// altered bytes. Which of the three is not knowable and not reported.
    Decrypt,
    /// The header decrypted and named a transport version this code does not
    /// speak.
    UnknownVersion(u16),
    /// Data and padding together exceed [`MAX_FRAME_PAYLOAD`].
    FrameTooLong {
        /// Bytes asked for.
        given: usize,
    },
    /// A frame number above [`MAX_FRAME_NUMBER`].
    FrameNumberTooLarge,
    /// The body does not have the length its header announced.
    BodyLengthMismatch {
        /// Bytes the header announced, data and padding together.
        expected: usize,
        /// Bytes given.
        given: usize,
    },
}

fn cipher(key: &[u8; HASH_LEN]) -> XSalsa20Poly1305 {
    XSalsa20Poly1305::new(Key::from_slice(key))
}

fn encrypt(key: &[u8; HASH_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("XSalsa20/Poly1305 only fails on a plaintext larger than this protocol allows")
}

fn decrypt(
    key: &[u8; HASH_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, WireError> {
    cipher(key)
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| WireError::Decrypt)
}

/// The nonce of a frame: the header flag in the top bit, the frame number
/// under it, zeroes after it. Never sent; both sides know the number.
fn frame_nonce(frame_number: u64, is_header: bool) -> Result<[u8; NONCE_LEN], WireError> {
    if frame_number > MAX_FRAME_NUMBER {
        return Err(WireError::FrameNumberTooLarge);
    }
    let numbered = if is_header {
        frame_number | (1 << 63)
    } else {
        frame_number
    };
    let mut nonce = [0u8; NONCE_LEN];
    for (slot, byte) in nonce.iter_mut().zip(numbered.to_be_bytes()) {
        *slot = byte;
    }
    Ok(nonce)
}

fn payload_len(data_len: usize, padding_len: usize) -> Result<usize, WireError> {
    let total = data_len.saturating_add(padding_len);
    if total > MAX_FRAME_PAYLOAD {
        return Err(WireError::FrameTooLong { given: total });
    }
    Ok(total)
}

/// Encrypts a stream header.
#[must_use]
pub fn seal_stream_header(
    header_key: &[u8; HASH_LEN],
    nonce: &[u8; NONCE_LEN],
    header: &StreamHeader,
) -> [u8; STREAM_HEADER_LEN] {
    let mut plaintext = Vec::with_capacity(2 + 8 + HASH_LEN);
    plaintext.extend_from_slice(&u16::from(TRANSPORT_VERSION).to_be_bytes());
    plaintext.extend_from_slice(&header.stream_number.to_be_bytes());
    plaintext.extend_from_slice(&header.cipher_key);

    let mut out = [0u8; STREAM_HEADER_LEN];
    let sealed = encrypt(header_key, nonce, &plaintext);
    for (slot, byte) in out.iter_mut().zip(nonce.iter().chain(sealed.iter())) {
        *slot = *byte;
    }
    out
}

/// Decrypts a stream header.
///
/// # Errors
///
/// [`WireError::Decrypt`] if it does not authenticate,
/// [`WireError::UnknownVersion`] if it names another transport version.
pub fn open_stream_header(
    header_key: &[u8; HASH_LEN],
    bytes: &[u8; STREAM_HEADER_LEN],
) -> Result<StreamHeader, WireError> {
    let mut nonce = [0u8; NONCE_LEN];
    for (slot, byte) in nonce.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    let sealed: Vec<u8> = bytes.iter().skip(NONCE_LEN).copied().collect();
    let plaintext = decrypt(header_key, &nonce, &sealed)?;

    let mut version_bytes = [0u8; 2];
    for (slot, byte) in version_bytes.iter_mut().zip(plaintext.iter()) {
        *slot = *byte;
    }
    let version = u16::from_be_bytes(version_bytes);
    if version != u16::from(TRANSPORT_VERSION) {
        return Err(WireError::UnknownVersion(version));
    }

    let mut number_bytes = [0u8; 8];
    for (slot, byte) in number_bytes.iter_mut().zip(plaintext.iter().skip(2)) {
        *slot = *byte;
    }
    let mut cipher_key = [0u8; HASH_LEN];
    for (slot, byte) in cipher_key.iter_mut().zip(plaintext.iter().skip(10)) {
        *slot = *byte;
    }
    Ok(StreamHeader {
        stream_number: u64::from_be_bytes(number_bytes),
        cipher_key,
    })
}

/// Encrypts a frame header.
///
/// # Errors
///
/// [`WireError::FrameTooLong`], [`WireError::FrameNumberTooLarge`].
pub fn seal_frame_header(
    cipher_key: &[u8; HASH_LEN],
    frame_number: u64,
    header: &FrameHeader,
) -> Result<[u8; FRAME_HEADER_LEN], WireError> {
    payload_len(
        usize::from(header.data_len),
        usize::from(header.padding_len),
    )?;
    let nonce = frame_nonce(frame_number, true)?;

    let flagged = if header.final_frame {
        header.data_len | 0x8000
    } else {
        header.data_len
    };
    let mut plaintext = [0u8; 4];
    for (slot, byte) in plaintext.iter_mut().zip(
        flagged
            .to_be_bytes()
            .into_iter()
            .chain(header.padding_len.to_be_bytes()),
    ) {
        *slot = byte;
    }

    let sealed = encrypt(cipher_key, &nonce, &plaintext);
    let mut out = [0u8; FRAME_HEADER_LEN];
    for (slot, byte) in out.iter_mut().zip(sealed.iter()) {
        *slot = *byte;
    }
    Ok(out)
}

/// Decrypts a frame header.
///
/// # Errors
///
/// [`WireError::Decrypt`], [`WireError::FrameNumberTooLarge`].
pub fn open_frame_header(
    cipher_key: &[u8; HASH_LEN],
    frame_number: u64,
    bytes: &[u8; FRAME_HEADER_LEN],
) -> Result<FrameHeader, WireError> {
    let nonce = frame_nonce(frame_number, true)?;
    let plaintext = decrypt(cipher_key, &nonce, bytes)?;

    let mut first = [0u8; 2];
    let mut second = [0u8; 2];
    for (slot, byte) in first.iter_mut().zip(plaintext.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in second.iter_mut().zip(plaintext.iter().skip(2)) {
        *slot = *byte;
    }
    let flagged = u16::from_be_bytes(first);
    let header = FrameHeader {
        data_len: flagged & 0x7fff,
        padding_len: u16::from_be_bytes(second),
        final_frame: flagged & 0x8000 != 0,
    };
    // The lengths come from the sender. They authenticate, which says the
    // sender wrote them, not that the sender is friendly.
    payload_len(
        usize::from(header.data_len),
        usize::from(header.padding_len),
    )?;
    Ok(header)
}

/// Encrypts a frame body: the data, then `padding_len` zero bytes.
///
/// # Errors
///
/// [`WireError::FrameTooLong`], [`WireError::FrameNumberTooLarge`].
pub fn seal_frame_body(
    cipher_key: &[u8; HASH_LEN],
    frame_number: u64,
    data: &[u8],
    padding_len: usize,
) -> Result<Vec<u8>, WireError> {
    let total = payload_len(data.len(), padding_len)?;
    let nonce = frame_nonce(frame_number, false)?;
    let mut plaintext = Vec::with_capacity(total);
    plaintext.extend_from_slice(data);
    plaintext.resize(total, 0);
    Ok(encrypt(cipher_key, &nonce, &plaintext))
}

/// Decrypts a frame body and returns the data without the padding.
///
/// # Errors
///
/// [`WireError::Decrypt`], [`WireError::BodyLengthMismatch`],
/// [`WireError::FrameNumberTooLarge`].
pub fn open_frame_body(
    cipher_key: &[u8; HASH_LEN],
    frame_number: u64,
    header: &FrameHeader,
    bytes: &[u8],
) -> Result<Vec<u8>, WireError> {
    let expected = payload_len(
        usize::from(header.data_len),
        usize::from(header.padding_len),
    )?;
    let given = bytes.len().saturating_sub(AUTH_LEN);
    if given != expected {
        return Err(WireError::BodyLengthMismatch { expected, given });
    }
    let nonce = frame_nonce(frame_number, false)?;
    let mut plaintext = decrypt(cipher_key, &nonce, bytes)?;
    plaintext.truncate(usize::from(header.data_len));
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    //! Two cases the integration tests cannot reach, because reaching them
    //! means writing a well-formed ciphertext with hostile contents.

    use super::*;

    const KEY: [u8; HASH_LEN] = [0x66; HASH_LEN];

    #[test]
    fn a_header_naming_another_version_is_refused() {
        let nonce = [0x77; NONCE_LEN];
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&2u16.to_be_bytes());
        plaintext.extend_from_slice(&7u64.to_be_bytes());
        plaintext.extend_from_slice(&[0x66; HASH_LEN]);
        let sealed = encrypt(&KEY, &nonce, &plaintext);

        let mut wire = [0u8; STREAM_HEADER_LEN];
        for (slot, byte) in wire.iter_mut().zip(nonce.iter().chain(sealed.iter())) {
            *slot = *byte;
        }
        assert_eq!(
            open_stream_header(&KEY, &wire),
            Err(WireError::UnknownVersion(2))
        );
    }

    #[test]
    fn a_frame_header_claiming_more_than_a_frame_holds_is_refused() {
        // 0x7fff data, which authenticates and is still a lie about what fits.
        let nonce = frame_nonce(0, true).expect("a valid frame number");
        let mut plaintext = [0u8; 4];
        for (slot, byte) in plaintext.iter_mut().zip(
            0x7fffu16
                .to_be_bytes()
                .into_iter()
                .chain(0u16.to_be_bytes()),
        ) {
            *slot = byte;
        }
        let sealed = encrypt(&KEY, &nonce, &plaintext);
        let mut wire = [0u8; FRAME_HEADER_LEN];
        for (slot, byte) in wire.iter_mut().zip(sealed.iter()) {
            *slot = *byte;
        }
        assert_eq!(
            open_frame_header(&KEY, 0, &wire),
            Err(WireError::FrameTooLong { given: 0x7fff })
        );
    }
}

//! The stream header and the frames.
//!
//! Spec: `spec/20-transport.md` §6.
//!
//! No foreign oracle here. XSalsa20/Poly1305 comes from a reviewed library
//! that carries its own vectors; what these tests cover is the framing around
//! it, which is ours: the layout, the lengths, and the deterministic nonces.
//! `CONTRIBUTING.md` says a test with no counterparty says so, and this is
//! that sentence.

use onestein_transport::{
    FRAME_HEADER_LEN, FrameHeader, MAX_FRAME_LEN, MAX_FRAME_NUMBER, MAX_FRAME_PAYLOAD, NONCE_LEN,
    STREAM_HEADER_LEN, StreamHeader, WireError, open_frame_body, open_frame_header,
    open_stream_header, seal_frame_body, seal_frame_header, seal_stream_header,
};

const HEADER_KEY: [u8; 32] = [0x55; 32];
const CIPHER_KEY: [u8; 32] = [0x66; 32];
const NONCE: [u8; NONCE_LEN] = [0x77; NONCE_LEN];

fn example() -> StreamHeader {
    StreamHeader {
        stream_number: 7,
        cipher_key: CIPHER_KEY,
    }
}

// "The stream header is NONCE_LEN + 2 + 8 + KEY_LEN + AUTH_LEN = 82 bytes
// long."
#[test]
fn a_stream_header_is_eighty_two_bytes_and_round_trips() {
    assert_eq!(STREAM_HEADER_LEN, 82);
    let sealed = seal_stream_header(&HEADER_KEY, &NONCE, &example());
    assert_eq!(sealed.len(), 82);
    assert_eq!(open_stream_header(&HEADER_KEY, &sealed), Ok(example()));
}

// The nonce is sent in the clear, the rest is not: the stream number and the
// ephemeral key must not be readable from the wire.
#[test]
fn a_stream_header_shows_nothing_but_its_nonce() {
    let sealed = seal_stream_header(&HEADER_KEY, &NONCE, &example());
    let nonce_part: Vec<u8> = sealed.iter().take(NONCE_LEN).copied().collect();
    assert_eq!(nonce_part, NONCE.to_vec());
    let rest: Vec<u8> = sealed.iter().skip(NONCE_LEN).copied().collect();
    assert!(!rest.windows(32).any(|w| w == CIPHER_KEY));
    assert!(!rest.windows(8).any(|w| w == 7u64.to_be_bytes()));
}

#[test]
fn a_stream_header_does_not_open_under_another_key() {
    let sealed = seal_stream_header(&HEADER_KEY, &NONCE, &example());
    assert_eq!(
        open_stream_header(&[0x56; 32], &sealed),
        Err(WireError::Decrypt)
    );
}

#[test]
fn an_altered_stream_header_is_refused() {
    let mut sealed = seal_stream_header(&HEADER_KEY, &NONCE, &example());
    if let Some(byte) = sealed.last_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        open_stream_header(&HEADER_KEY, &sealed),
        Err(WireError::Decrypt)
    );
    let mut nonce_changed = seal_stream_header(&HEADER_KEY, &NONCE, &example());
    if let Some(byte) = nonce_changed.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        open_stream_header(&HEADER_KEY, &nonce_changed),
        Err(WireError::Decrypt)
    );
}

// "Bit 0: Final frame flag ... Bits 0 - 15: int_16(len(data)) ... Bits 16 -
// 31: int_16(len(padding))"
#[test]
fn a_frame_header_round_trips_with_its_flag() {
    for final_frame in [false, true] {
        let header = FrameHeader {
            data_len: 300,
            padding_len: 88,
            final_frame,
        };
        let sealed = seal_frame_header(&CIPHER_KEY, 0, &header).expect("seals");
        assert_eq!(sealed.len(), FRAME_HEADER_LEN);
        assert_eq!(open_frame_header(&CIPHER_KEY, 0, &sealed), Ok(header));
    }
}

// The nonce is the frame number, so a frame cannot be moved to another
// position in the stream.
#[test]
fn a_frame_header_does_not_open_at_another_frame_number() {
    let header = FrameHeader {
        data_len: 1,
        padding_len: 0,
        final_frame: false,
    };
    let sealed = seal_frame_header(&CIPHER_KEY, 4, &header).expect("seals");
    assert_eq!(
        open_frame_header(&CIPHER_KEY, 5, &sealed),
        Err(WireError::Decrypt)
    );
}

// "Bit 0: Header flag, set to one for the frame header or zero for the frame
// body." Without it, a body could be presented as a header of the same frame.
#[test]
fn a_body_cannot_be_opened_as_a_header() {
    let body = seal_frame_body(&CIPHER_KEY, 0, &[0u8; 4], 0).expect("seals");
    let mut as_header = [0u8; FRAME_HEADER_LEN];
    for (slot, byte) in as_header.iter_mut().zip(body.iter()) {
        *slot = *byte;
    }
    assert_eq!(
        open_frame_header(&CIPHER_KEY, 0, &as_header),
        Err(WireError::Decrypt)
    );
}

#[test]
fn a_frame_body_round_trips_and_padding_is_not_data() {
    let data = b"onestein";
    let sealed = seal_frame_body(&CIPHER_KEY, 3, data, 40).expect("seals");
    assert_eq!(sealed.len(), data.len() + 40 + 16);
    let header = FrameHeader {
        data_len: 8,
        padding_len: 40,
        final_frame: false,
    };
    assert_eq!(
        open_frame_body(&CIPHER_KEY, 3, &header, &sealed),
        Ok(data.to_vec())
    );
}

// "The total length of the data and padding must be no more than 988 bytes,
// giving a maximum length of 1,024 bytes for an encrypted frame."
#[test]
fn a_frame_holds_at_most_988_bytes_of_data_and_padding() {
    let full = vec![0xaa; MAX_FRAME_PAYLOAD];
    let sealed = seal_frame_body(&CIPHER_KEY, 0, &full, 0).expect("seals");
    assert_eq!(FRAME_HEADER_LEN + sealed.len(), MAX_FRAME_LEN);
    assert_eq!(MAX_FRAME_LEN, 1024);

    assert_eq!(
        seal_frame_body(&CIPHER_KEY, 0, &full, 1),
        Err(WireError::FrameTooLong {
            given: MAX_FRAME_PAYLOAD + 1
        })
    );
    assert_eq!(
        seal_frame_header(
            &CIPHER_KEY,
            0,
            &FrameHeader {
                data_len: 988,
                padding_len: 1,
                final_frame: false
            }
        ),
        Err(WireError::FrameTooLong { given: 989 })
    );
}

// "A stream must not contain more than 2^63 frames", because the top bit of
// the number is the header flag.
#[test]
fn a_frame_number_above_the_limit_is_refused() {
    let header = FrameHeader {
        data_len: 0,
        padding_len: 0,
        final_frame: true,
    };
    assert!(seal_frame_header(&CIPHER_KEY, MAX_FRAME_NUMBER, &header).is_ok());
    assert_eq!(
        seal_frame_header(&CIPHER_KEY, MAX_FRAME_NUMBER + 1, &header),
        Err(WireError::FrameNumberTooLarge)
    );
    assert_eq!(
        seal_frame_body(&CIPHER_KEY, u64::MAX, b"x", 0),
        Err(WireError::FrameNumberTooLarge)
    );
}

// A body whose length does not match its header is refused before it is
// decrypted, because the alternative is reading the wrong number of bytes off
// a stream and calling whatever follows a frame.
#[test]
fn a_body_that_does_not_match_its_header_is_refused() {
    let sealed = seal_frame_body(&CIPHER_KEY, 0, b"xyz", 0).expect("seals");
    let header = FrameHeader {
        data_len: 4,
        padding_len: 0,
        final_frame: false,
    };
    assert_eq!(
        open_frame_body(&CIPHER_KEY, 0, &header, &sealed),
        Err(WireError::BodyLengthMismatch {
            expected: 4,
            given: 3
        })
    );
}

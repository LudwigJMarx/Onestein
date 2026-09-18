//! The handshake's records.
//!
//! Spec: `spec/30-handshake.md` §3.

use onestein_handshake::{
    HandshakeRecord, KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN, X25519_LEN, decode_records,
    encode_record,
};

fn round_trip(record: HandshakeRecord<'_>) {
    let encoded = encode_record(&record).expect("encodes");
    let decoded = decode_records(&encoded).expect("decodes");
    assert_eq!(decoded, vec![record]);
}

#[test]
fn every_record_type_round_trips() {
    round_trip(HandshakeRecord::EphemeralKeys {
        x25519: &[0x11; X25519_LEN],
        kem: &[0x22; KEM_ENCAPSULATION_KEY_LEN],
    });
    round_trip(HandshakeRecord::CertificateId(&[0x33; 32]));
    round_trip(HandshakeRecord::CertificateRequest);
    round_trip(HandshakeRecord::Encapsulations {
        to_ephemeral: &[0x44; KEM_CIPHERTEXT_LEN],
        to_static: &[0x55; KEM_CIPHERTEXT_LEN],
    });
    round_trip(HandshakeRecord::Confirmation(&[0x66; 32]));
    round_trip(HandshakeRecord::DeviceCertificate(b"a certificate"));
}

// The type bytes are the wire and are fixed by the table in section 3.
#[test]
fn the_type_bytes_are_the_ones_the_table_fixes() {
    let cases: [(HandshakeRecord<'_>, u8, usize); 5] = [
        (
            HandshakeRecord::EphemeralKeys {
                x25519: &[0; X25519_LEN],
                kem: &[0; KEM_ENCAPSULATION_KEY_LEN],
            },
            0,
            X25519_LEN + KEM_ENCAPSULATION_KEY_LEN,
        ),
        (HandshakeRecord::CertificateId(&[0; 32]), 2, 32),
        (HandshakeRecord::CertificateRequest, 3, 0),
        (
            HandshakeRecord::Encapsulations {
                to_ephemeral: &[0; KEM_CIPHERTEXT_LEN],
                to_static: &[0; KEM_CIPHERTEXT_LEN],
            },
            4,
            2 * KEM_CIPHERTEXT_LEN,
        ),
        (HandshakeRecord::Confirmation(&[0; 32]), 5, 32),
    ];
    for (record, expected_type, payload_len) in cases {
        let encoded = encode_record(&record).expect("encodes");
        let header: Vec<u8> = encoded.iter().take(4).copied().collect();
        assert_eq!(header.first(), Some(&1), "handshake version");
        assert_eq!(header.get(1), Some(&expected_type));
        assert_eq!(encoded.len(), 4 + payload_len);
    }
}

// A message carries several records and they come back in order, which is
// what step 2 of the protocol sends in one go.
#[test]
fn several_records_travel_in_one_message() {
    let mut message = Vec::new();
    message.extend(
        encode_record(&HandshakeRecord::EphemeralKeys {
            x25519: &[0x11; X25519_LEN],
            kem: &[0x22; KEM_ENCAPSULATION_KEY_LEN],
        })
        .expect("encodes"),
    );
    message.extend(encode_record(&HandshakeRecord::CertificateRequest).expect("encodes"));
    message.extend(
        encode_record(&HandshakeRecord::Encapsulations {
            to_ephemeral: &[0x44; KEM_CIPHERTEXT_LEN],
            to_static: &[0x55; KEM_CIPHERTEXT_LEN],
        })
        .expect("encodes"),
    );

    let decoded = decode_records(&message).expect("decodes");
    assert_eq!(decoded.len(), 3);
    assert!(matches!(
        decoded.first(),
        Some(HandshakeRecord::EphemeralKeys { .. })
    ));
    assert!(matches!(
        decoded.get(1),
        Some(HandshakeRecord::CertificateRequest)
    ));
}

// A known type with the wrong payload length is refused: the lengths in the
// table are what tells two ephemeral keys apart from one long one.
#[test]
fn a_known_type_with_the_wrong_length_is_refused() {
    let mut message = onestein_record::encode(1, 0, &[0u8; 100]).expect("frames");
    assert!(decode_records(&message).is_err());

    message = onestein_record::encode(1, 5, &[0u8; 31]).expect("frames");
    assert!(decode_records(&message).is_err());

    message = onestein_record::encode(1, 3, b"not empty").expect("frames");
    assert!(decode_records(&message).is_err());
}

// An unknown type reaches the caller so that the caller can ignore it, which
// is what lets a later version add a record without breaking this one.
#[test]
fn an_unknown_type_is_handed_over_rather_than_refused() {
    let message = onestein_record::encode(1, 200, b"from the future").expect("frames");
    let decoded = decode_records(&message).expect("decodes");
    assert_eq!(decoded, vec![HandshakeRecord::Unknown { record_type: 200 }]);
}

// Another handshake version is refused outright, which is the downgrade
// defence and is not the caller's decision.
#[test]
fn another_version_is_refused() {
    let message = onestein_record::encode(2, 0, &[0u8; 1216]).expect("frames");
    assert!(decode_records(&message).is_err());
}

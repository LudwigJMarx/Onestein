//! The record framing.
//!
//! Spec: `spec/05-primitives.md` §4.

use onestein_record::{Error, HEADER_LEN, MAX_PAYLOAD_LEN, Reader, Record, encode};

const VERSION: u8 = 1;

// "record_header = int_8(layer_version) || int_8(record_type) ||
// int_16(len(payload))". The layout is the test, not a round trip: a round
// trip passes just as well when both sides are wrong in the same way.
#[test]
fn the_header_is_version_type_and_a_big_endian_length() {
    assert_eq!(HEADER_LEN, 4);
    assert_eq!(
        encode(1, 0, b"abc"),
        Ok(vec![0x01, 0x00, 0x00, 0x03, b'a', b'b', b'c'])
    );
    assert_eq!(encode(2, 255, b""), Ok(vec![0x02, 0xff, 0x00, 0x00]));

    let long = vec![0u8; 300];
    let encoded = encode(1, 1, &long).expect("fits");
    assert_eq!(
        encoded.iter().take(4).copied().collect::<Vec<u8>>(),
        vec![0x01, 0x01, 0x01, 0x2c]
    );
}

#[test]
fn records_come_back_in_the_order_they_were_written() {
    let mut stream = Vec::new();
    stream.extend(encode(VERSION, 0, b"one").expect("fits"));
    stream.extend(encode(VERSION, 1, b"").expect("fits"));
    stream.extend(encode(VERSION, 2, b"three").expect("fits"));

    let read: Vec<Record<'_>> = Reader::new(&stream, VERSION)
        .map(|record| record.expect("well formed"))
        .collect();

    assert_eq!(
        read,
        vec![
            Record {
                version: VERSION,
                record_type: 0,
                payload: b"one".as_slice()
            },
            Record {
                version: VERSION,
                record_type: 1,
                payload: b"".as_slice()
            },
            Record {
                version: VERSION,
                record_type: 2,
                payload: b"three".as_slice()
            },
        ]
    );
}

// "A peer refuses a record whose version it does not know": refusing the
// unknown version is what stops a downgrade.
#[test]
fn another_version_is_refused() {
    let stream = encode(2, 0, b"x").expect("fits");
    let first = Reader::new(&stream, VERSION).next();
    assert_eq!(
        first,
        Some(Err(Error::UnknownVersion {
            expected: 1,
            given: 2
        }))
    );
}

// "...and ignores a record whose type it does not know inside a version it
// does": the reader cannot know which types the caller has, so it hands them
// over instead of deciding.
#[test]
fn an_unknown_type_reaches_the_caller() {
    let stream = encode(VERSION, 99, b"later").expect("fits");
    let first = Reader::new(&stream, VERSION).next();
    assert_eq!(
        first,
        Some(Ok(Record {
            version: VERSION,
            record_type: 99,
            payload: b"later"
        }))
    );
}

#[test]
fn a_reader_stops_after_a_refusal() {
    let mut stream = encode(2, 0, b"x").expect("fits");
    stream.extend(encode(VERSION, 0, b"never read").expect("fits"));

    let read: Vec<Result<Record<'_>, Error>> = Reader::new(&stream, VERSION).collect();
    assert_eq!(read.len(), 1);
    assert!(read.first().is_some_and(Result::is_err));
}

#[test]
fn a_truncated_record_is_refused() {
    let full = encode(VERSION, 0, b"abcdef").expect("fits");

    let short_payload: Vec<u8> = full.iter().take(full.len() - 2).copied().collect();
    assert_eq!(
        Reader::new(&short_payload, VERSION).next(),
        Some(Err(Error::Truncated {
            expected: 6,
            given: 4
        }))
    );

    let short_header: Vec<u8> = full.iter().take(3).copied().collect();
    assert_eq!(
        Reader::new(&short_header, VERSION).next(),
        Some(Err(Error::Truncated {
            expected: HEADER_LEN,
            given: 3
        }))
    );
}

// "The maximum length of the payload is 48 KiB."
#[test]
fn a_payload_over_48_kib_is_refused() {
    let just_fits = vec![0u8; MAX_PAYLOAD_LEN];
    assert!(encode(VERSION, 0, &just_fits).is_ok());

    let one_too_many = vec![0u8; MAX_PAYLOAD_LEN + 1];
    assert_eq!(
        encode(VERSION, 0, &one_too_many),
        Err(Error::PayloadTooLong {
            given: MAX_PAYLOAD_LEN + 1
        })
    );
}

// The length field holds up to 65535, which is more than a record may carry.
// A sender that declares 60000 is refused on reading, not only on writing.
#[test]
fn a_declared_length_over_the_maximum_is_refused_when_reading() {
    let mut stream = vec![VERSION, 0, 0xea, 0x60];
    stream.extend(vec![0u8; 60_000]);
    assert_eq!(
        Reader::new(&stream, VERSION).next(),
        Some(Err(Error::PayloadTooLong { given: 60_000 }))
    );
}

#[test]
fn an_empty_stream_yields_nothing() {
    assert_eq!(Reader::new(&[], VERSION).next(), None);
    assert_eq!(Reader::new(&[], VERSION).remaining(), 0);
}

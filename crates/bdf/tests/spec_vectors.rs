//! Conformance vectors taken from the BDF version 1 specification.
//!
//! Every test names the sentence of the specification it holds to. Vectors
//! produced by the Java implementation live in `tests/interop.rs` and are a
//! separate question: this file asks whether we read the specification right,
//! that file asks whether the specification matches the only implementation
//! that exists.
//!
//! Spec: <https://code.briarproject.org/briar/briar-spec/-/blob/master/BDF.md>

use onestein_bdf::{Value, from_bytes, to_bytes};

/// Both directions for one vector: encoding and decoding are separate claims.
#[track_caller]
fn both_ways(value: Value, bytes: &[u8]) {
    assert_eq!(to_bytes(&value), bytes, "encoding {value:?}");
    assert_eq!(from_bytes(bytes), Ok(value), "decoding {bytes:02x?}");
}

// "0: Null - Next four bits are zero."
#[test]
fn null_is_one_zero_byte() {
    both_ways(Value::Null, &[0x00]);
}

// "1: Boolean - Next four bits give the value, which is 0 for false or 1 for
// true."
#[test]
fn boolean_carries_its_value_in_the_low_nibble() {
    both_ways(Value::Bool(false), &[0x10]);
    both_ways(Value::Bool(true), &[0x11]);
}

// "2: Integer - Next four bits give the length, which is 1, 2, 4 or 8." plus
// "integers and lengths should be represented using the minimum number of
// bytes" for the encoder.
#[test]
fn integers_use_the_shortest_of_the_four_lengths() {
    both_ways(Value::Int(0), &[0x21, 0x00]);
    both_ways(Value::Int(127), &[0x21, 0x7f]);
    both_ways(Value::Int(-128), &[0x21, 0x80]);
    both_ways(Value::Int(128), &[0x22, 0x00, 0x80]);
    both_ways(Value::Int(-32768), &[0x22, 0x80, 0x00]);
    both_ways(Value::Int(32768), &[0x24, 0x00, 0x00, 0x80, 0x00]);
    both_ways(
        Value::Int(i64::MIN),
        &[0x28, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
}

// A longer encoding than necessary is legal on the wire; only the encoder is
// held to the minimum. "If data is to be hashed or signed ..." is a condition,
// not a blanket rule.
#[test]
fn a_longer_integer_encoding_still_decodes() {
    assert_eq!(
        from_bytes(&[0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        Ok(Value::Int(1))
    );
}

// "3: Float - Next four bits give the length, which is 8." and "floating point
// numbers are IEEE 754".
#[test]
fn floats_are_eight_bytes_of_ieee_754() {
    both_ways(
        Value::Float(1.0),
        &[0x38, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    both_ways(
        Value::Float(-0.0),
        &[0x38, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
}

// "4: String - Next four bits give the length-of-length" and "strings are
// UTF-8".
#[test]
fn strings_carry_a_length_of_length() {
    both_ways(Value::Str("foo".into()), &[0x41, 0x03, 0x66, 0x6f, 0x6f]);
    both_ways(Value::Str(String::new()), &[0x41, 0x00]);
    // Two bytes on the wire, one character: the length is bytes, not chars.
    both_ways(Value::Str("ü".into()), &[0x41, 0x02, 0xc3, 0xbc]);
}

// A string longer than 127 bytes needs a two-byte length, because the length
// itself is a signed integer.
#[test]
fn a_string_of_128_bytes_needs_a_two_byte_length() {
    let text = "a".repeat(128);
    let mut expected = vec![0x42, 0x00, 0x80];
    expected.extend_from_slice(text.as_bytes());
    both_ways(Value::Str(text), &expected);
}

// "5: Raw - ... The value is binary data with the specified length."
#[test]
fn raw_is_opaque_bytes() {
    both_ways(Value::Raw(vec![0xde, 0xad]), &[0x51, 0x02, 0xde, 0xad]);
    both_ways(Value::Raw(Vec::new()), &[0x51, 0x00]);
}

// "6: List - ... zero or more elements followed by an End object."
#[test]
fn lists_are_terminated_by_end() {
    both_ways(Value::List(Vec::new()), &[0x60, 0x80]);
    both_ways(
        Value::List(vec![Value::Null, Value::Bool(true)]),
        &[0x60, 0x00, 0x11, 0x80],
    );
    both_ways(
        Value::List(vec![Value::List(vec![Value::Int(1)])]),
        &[0x60, 0x60, 0x21, 0x01, 0x80, 0x80],
    );
}

// "7: Dictionary - ... zero or more key-value pairs followed by an End object.
// Keys are String objects".
#[test]
fn dictionaries_hold_string_keys() {
    both_ways(Value::Dict(Vec::new()), &[0x70, 0x80]);
    both_ways(
        Value::Dict(vec![("a".into(), Value::Int(1))]),
        &[0x70, 0x41, 0x01, 0x61, 0x21, 0x01, 0x80],
    );
}

// The wire order is what a signature covers, so decoding keeps it instead of
// sorting silently.
#[test]
fn decoding_keeps_the_order_the_keys_arrived_in() {
    let bytes = [
        0x70, 0x41, 0x01, 0x62, 0x21, 0x02, 0x41, 0x01, 0x61, 0x21, 0x01, 0x80,
    ];
    assert_eq!(
        from_bytes(&bytes),
        Ok(Value::Dict(vec![
            ("b".into(), Value::Int(2)),
            ("a".into(), Value::Int(1)),
        ]))
    );
}

// --- Rejections -----------------------------------------------------------
//
// The specification lists the legal lengths. Everything else has to be
// refused rather than guessed at, or two implementations will disagree about
// what a byte string means, which is how identifiers drift apart.

#[test]
fn an_integer_length_outside_1_2_4_8_is_refused() {
    for header in [0x20, 0x23, 0x25, 0x26, 0x27, 0x29, 0x2f] {
        assert!(
            from_bytes(&[header, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(),
            "header {header:#04x} must not decode"
        );
    }
}

#[test]
fn a_float_length_other_than_8_is_refused() {
    assert!(from_bytes(&[0x34, 0, 0, 0, 0]).is_err());
}

#[test]
fn a_length_of_length_outside_1_2_4_8_is_refused() {
    assert!(from_bytes(&[0x43, 0, 0, 0]).is_err());
    assert!(from_bytes(&[0x50, 0]).is_err());
}

// Lengths are read as two's complement integers, so 0xff is -1, not 255.
#[test]
fn a_negative_length_is_refused() {
    assert!(from_bytes(&[0x41, 0xff]).is_err());
    assert!(from_bytes(&[0x51, 0x80]).is_err());
}

// A length of 2^62 must not turn into an allocation of 2^62 bytes.
#[test]
fn a_length_beyond_the_input_is_refused_without_allocating() {
    assert!(from_bytes(&[0x58, 0x40, 0, 0, 0, 0, 0, 0, 0]).is_err());
    assert!(from_bytes(&[0x51, 0x08, 0xde, 0xad]).is_err());
}

#[test]
fn a_string_that_is_not_utf8_is_refused() {
    assert!(from_bytes(&[0x41, 0x01, 0xff]).is_err());
}

// "Elements may be of any type except End" and "values may be of any type
// except End".
#[test]
fn end_cannot_appear_where_a_value_belongs() {
    assert!(from_bytes(&[0x80]).is_err());
    assert!(from_bytes(&[0x70, 0x41, 0x01, 0x61, 0x80, 0x80]).is_err());
}

#[test]
fn a_dictionary_key_that_is_not_a_string_is_refused() {
    assert!(from_bytes(&[0x70, 0x21, 0x01, 0x21, 0x01, 0x80]).is_err());
}

#[test]
fn an_unterminated_container_is_refused() {
    assert!(from_bytes(&[0x60]).is_err());
    assert!(from_bytes(&[0x70, 0x41, 0x01, 0x61]).is_err());
}

#[test]
fn bytes_after_the_first_object_are_refused() {
    assert!(from_bytes(&[0x00, 0x00]).is_err());
}

#[test]
fn an_unknown_type_is_refused() {
    assert!(from_bytes(&[0x90]).is_err());
    assert!(from_bytes(&[0xf0]).is_err());
}

// Nesting is bounded on purpose: input arrives from the network, and an
// unbounded recursive reader is a crash waiting for a sender who cares.
#[test]
fn nesting_deeper_than_the_limit_is_refused_instead_of_crashing() {
    let deep: Vec<u8> = std::iter::repeat_n(0x60u8, 100_000)
        .chain(std::iter::repeat_n(0x80u8, 100_000))
        .collect();
    assert!(from_bytes(&deep).is_err());
}

// --- Canonical form -------------------------------------------------------
//
// "If data is to be hashed or signed, integers and lengths should be
// represented using the minimum number of bytes, and dictionary keys should
// be unique and sorted in lexicographic order."

#[test]
fn sorted_unique_keys_are_canonical() {
    let dict = Value::Dict(vec![
        ("a".into(), Value::Int(1)),
        ("b".into(), Value::Int(2)),
    ]);
    assert!(dict.is_canonical());
}

#[test]
fn unsorted_keys_are_not_canonical() {
    let dict = Value::Dict(vec![
        ("b".into(), Value::Int(2)),
        ("a".into(), Value::Int(1)),
    ]);
    assert!(!dict.is_canonical());
}

#[test]
fn repeated_keys_are_not_canonical() {
    let dict = Value::Dict(vec![
        ("a".into(), Value::Int(1)),
        ("a".into(), Value::Int(2)),
    ]);
    assert!(!dict.is_canonical());
}

#[test]
fn a_nested_dictionary_is_checked_too() {
    let inner = Value::Dict(vec![("b".into(), Value::Null), ("a".into(), Value::Null)]);
    assert!(!Value::List(vec![inner]).is_canonical());
    assert!(Value::List(vec![Value::Int(1)]).is_canonical());
}

// The writer is the other half of the rule, and it holds without being asked.
#[test]
fn the_writer_always_uses_minimal_lengths() {
    assert_eq!(to_bytes(&Value::Int(1)).len(), 2);
    assert_eq!(to_bytes(&Value::Str("a".into())).len(), 3);
}

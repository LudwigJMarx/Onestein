//! Strict mode: the canonical form required wherever data is hashed.
//!
//! Spec: `spec/10-encoding.md` section 2.3. The rule is ours, not BDF's: BDF
//! phrases canonical form as a duty of the writer, which is enough between
//! honest peers and not enough against an adversary.

use onestein_bdf::{Value, from_bytes, from_bytes_canonical};

// The writer always produces canonical output, so anything it writes must
// survive strict mode. Anything else would mean we cannot read ourselves.
#[test]
fn what_the_writer_produces_passes_strict_mode() {
    let value = Value::Dict(vec![
        ("a".into(), Value::Int(1)),
        (
            "b".into(),
            Value::List(vec![Value::Raw(vec![0xff; 200]), Value::Null]),
        ),
        ("c".into(), Value::Str("ü".into())),
    ]);
    let bytes = onestein_bdf::to_bytes(&value);
    assert_eq!(from_bytes_canonical(&bytes), Ok(value));
}

// 1 encoded in 8 bytes is the same number and a different byte string.
#[test]
fn a_non_minimal_integer_is_refused_in_strict_mode_only() {
    let bytes = [0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(from_bytes(&bytes), Ok(Value::Int(1)));
    assert!(from_bytes_canonical(&bytes).is_err());
}

// A one-byte string with its length in two bytes.
#[test]
fn a_non_minimal_length_is_refused_in_strict_mode_only() {
    let bytes = [0x42, 0x00, 0x01, 0x61];
    assert_eq!(from_bytes(&bytes), Ok(Value::Str("a".into())));
    assert!(from_bytes_canonical(&bytes).is_err());
}

#[test]
fn keys_out_of_order_are_refused_in_strict_mode_only() {
    let bytes = [
        0x70, 0x41, 0x01, 0x62, 0x21, 0x02, 0x41, 0x01, 0x61, 0x21, 0x01, 0x80,
    ];
    assert!(from_bytes(&bytes).is_ok());
    assert!(from_bytes_canonical(&bytes).is_err());
}

#[test]
fn a_repeated_key_is_refused_in_strict_mode_only() {
    let bytes = [
        0x70, 0x41, 0x01, 0x61, 0x21, 0x01, 0x41, 0x01, 0x61, 0x21, 0x02, 0x80,
    ];
    assert!(from_bytes(&bytes).is_ok());
    assert!(from_bytes_canonical(&bytes).is_err());
}

// Strictness that stops at the top level would be worth nothing: the
// identifier covers the whole object.
#[test]
fn strictness_reaches_into_containers() {
    let inside_a_list = [0x60, 0x28, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x80];
    assert!(from_bytes(&inside_a_list).is_ok());
    assert!(from_bytes_canonical(&inside_a_list).is_err());

    let inside_a_dict = [
        0x70, 0x41, 0x01, 0x61, 0x60, 0x42, 0x00, 0x01, 0x62, 0x80, 0x80,
    ];
    assert!(from_bytes(&inside_a_dict).is_ok());
    assert!(from_bytes_canonical(&inside_a_dict).is_err());
}

// Order is over UTF-8 bytes (section 2.2). U+E000 encodes as ee 80 80 and
// U+10000 as f0 90 80 80, so the supplementary character sorts last here and
// would sort first under UTF-16 code unit order.
#[test]
fn order_is_over_utf8_bytes_not_utf16_code_units() {
    let value = Value::Dict(vec![
        ("\u{E000}".into(), Value::Null),
        ("\u{10000}".into(), Value::Null),
    ]);
    let bytes = onestein_bdf::to_bytes(&value);
    assert_eq!(from_bytes_canonical(&bytes), Ok(value));

    let other_way = Value::Dict(vec![
        ("\u{10000}".into(), Value::Null),
        ("\u{E000}".into(), Value::Null),
    ]);
    assert!(from_bytes_canonical(&onestein_bdf::to_bytes(&other_way)).is_err());
}

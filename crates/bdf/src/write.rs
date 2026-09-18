//! Encoding BDF objects.

use crate::{Value, minimal_int_length};

/// Encodes an object with integers and lengths in the fewest bytes that hold
/// them, which is what the specification requires of data that is to be
/// hashed or signed.
///
/// Dictionary entries are written in the order they are held. Sorting them
/// would silently change what a signature covers, so the order stays the
/// caller's decision; [`Value::is_canonical`] answers whether it is the
/// order the specification asks for.
pub fn to_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_into(value, &mut out);
    out
}

const END: u8 = 0x80;

fn write_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(0x00),
        Value::Bool(set) => out.push(0x10 | u8::from(*set)),
        Value::Int(number) => {
            let length = minimal_int_length(*number);
            out.push(0x20 | length);
            push_be(*number, length, out);
        }
        Value::Float(number) => {
            out.push(0x38);
            out.extend_from_slice(&number.to_be_bytes());
        }
        Value::Str(text) => {
            write_sized(0x40, text.as_bytes(), out);
        }
        Value::Raw(bytes) => {
            write_sized(0x50, bytes, out);
        }
        Value::List(items) => {
            out.push(0x60);
            for item in items {
                write_into(item, out);
            }
            out.push(END);
        }
        Value::Dict(entries) => {
            out.push(0x70);
            for (key, item) in entries {
                write_sized(0x40, key.as_bytes(), out);
                write_into(item, out);
            }
            out.push(END);
        }
    }
}

fn write_sized(kind: u8, bytes: &[u8], out: &mut Vec<u8>) {
    // The length is itself a signed integer, so 128 bytes already needs two.
    let length = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    let length_of_length = minimal_int_length(length);
    out.push(kind | length_of_length);
    push_be(length, length_of_length, out);
    out.extend_from_slice(bytes);
}

fn push_be(number: i64, length: u8, out: &mut Vec<u8>) {
    let skip = 8usize.saturating_sub(usize::from(length));
    out.extend(number.to_be_bytes().into_iter().skip(skip));
}

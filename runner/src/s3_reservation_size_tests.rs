use super::*;
use crate::canonical::sha256_hex;

fn entry(previous_hash: String) -> Entry {
    Entry {
        schema_version: SCHEMA.into(),
        sequence: 1,
        previous_hash,
        record: Record::Debit {
            reservation_digest: format!("sha256:{}", "b".repeat(64)),
            sequence: 1,
            preview_digest: format!("sha256:{}", "c".repeat(64)),
            is_write: false,
        },
    }
}

fn overhead() -> usize {
    encode_entry(entry(String::new())).unwrap().1.len()
}

#[test]
fn complete_entry_at_exact_line_cap_includes_newline_and_is_accepted() {
    // Padding tests serialization only, not validity of a replayable chain hash.
    let padding = "a".repeat(16 * 1024 - overhead());
    let (_, bytes) = encode_entry(entry(padding)).unwrap();
    assert_eq!(bytes.len(), 16 * 1024);
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
}

#[test]
fn one_byte_over_complete_line_cap_is_refused_by_pure_encoding() {
    let padding = "a".repeat(16 * 1024 - overhead() + 1);
    assert_eq!(encode_entry(entry(padding)), Err(Error::Budget));
}

#[test]
fn complete_line_limit_counts_utf8_bytes_not_characters() {
    let mut padding = "a".repeat(16 * 1024 - overhead() - 2);
    padding.push('\u{e9}');
    let (_, bytes) = encode_entry(entry(padding.clone())).unwrap();
    assert_eq!(bytes.len(), 16 * 1024);
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap().chars().count(),
        16 * 1024 - 1
    );
    padding.push('x');
    assert_eq!(encode_entry(entry(padding)), Err(Error::Budget));
}

#[test]
fn legacy_canonical_entry_and_hash_excluding_newline_are_unchanged() {
    let previous = format!("sha256:{}", "a".repeat(64));
    let expected = format!(
        "{{\"previous_hash\":\"{previous}\",\"record\":{{\"is_write\":false,\"kind\":\"debit\",\"preview_digest\":\"sha256:{}\",\"reservation_digest\":\"sha256:{}\",\"sequence\":1}},\"schema_version\":\"bluefire.s3-send-entry.v1\",\"sequence\":1}}\n",
        "c".repeat(64), "b".repeat(64),
    ).into_bytes();
    let (hash, bytes) = encode_entry(entry(previous)).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(
        hash,
        format!("sha256:{}", sha256_hex(&expected[..expected.len() - 1]))
    );
    assert_ne!(hash, format!("sha256:{}", sha256_hex(&expected)));
}

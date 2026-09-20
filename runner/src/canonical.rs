//! Canonical JSON hashing shared by wire contracts and installation identities.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("serializing a JSON string"),
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let body = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(key).expect("serializing a JSON object key");
                    format!("{encoded_key}:{}", canonical_json(&values[key]))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_hash(value: &Value) -> String {
    format!("sha256:{}", sha256_hex(canonical_json(value).as_bytes()))
}

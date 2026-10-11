use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

use super::{Code, Result};

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Json;
        impl<'de> Visitor<'de> for Json {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded integer JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut rows = Vec::new();
                while let Some(Strict(row)) = seq.next_element()? {
                    if rows.len() == 1024 {
                        return Err(de::Error::custom("array bound"));
                    }
                    rows.push(row);
                }
                Ok(Strict(rows.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut rows = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if rows.len() == 64 || rows.contains_key(&key) {
                        return Err(de::Error::custom("object bound or duplicate"));
                    }
                    let Strict(row) = map.next_value()?;
                    rows.insert(key, row);
                }
                Ok(Strict(rows.into()))
            }
        }
        deserializer.deserialize_any(Json)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| Code::RequestInvalid)
}
pub(super) fn exact(value: &Value, names: &[&str]) -> Result<()> {
    let row = value.as_object().ok_or(Code::RequestInvalid)?;
    ensure(row.len() == names.len() && names.iter().all(|key| row.contains_key(*key)))
}
pub(super) fn ensure(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Code::RequestInvalid)
    }
}
pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(Code::RequestInvalid)
}
pub(super) fn number(value: &Value, min: u64, max: u64) -> Result<u64> {
    let v = value.as_u64().ok_or(Code::RequestInvalid)?;
    ensure((min..=max).contains(&v))?;
    Ok(v)
}
pub(super) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn digest(value: &Value) -> Result<()> {
    ensure(
        text(value)?
            .strip_prefix("sha256:")
            .is_some_and(|v| hex(v, 64)),
    )
}
pub(super) fn identifier(value: &Value) -> Result<()> {
    let value = text(value)?;
    ensure(
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
    )
}
pub(super) fn time(value: &Value) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    use chrono::Timelike;
    let value = text(value)?;
    ensure(value.len() <= 40 && value.is_ascii())?;
    let parsed = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| Code::RequestInvalid)?;
    ensure(parsed.nanosecond() < 1_000_000_000 && parsed.nanosecond() % 1000 == 0)?;
    Ok(parsed)
}
pub(super) fn hash(value: &Value) -> Result<String> {
    Ok(crate::canonical::canonical_hash(value))
}

//! Explicit fixture-generation consistency. None of these values grant a send.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::s3_access_policy::encoded;
use crate::s3_access_scope::{digest, lower_hex, require, Checked, Scope};

pub(crate) const REQUEST_SCHEMA: &str = "bluefire.s3-worker-request.v2";
pub(crate) const RESULT_SCHEMA: &str = "bluefire.s3-worker-result.v2";
pub(crate) const BUCKET_SHAPE: &str = "never_versioned_no_object_lock";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureOperation {
    pub schema_version: String,
    pub intent_id: String,
    pub purpose: String,
    pub expected_etag: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureEnrollment {
    schema_version: String,
    scope_digest: String,
    generation_digest: String,
    exclusive_writer_digest: String,
    bucket_shape: String,
}

pub(crate) fn etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=130).contains(&bytes.len())
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(b))
}

pub(crate) fn payload(scope_id: &str, purpose: &str) -> Vec<u8> {
    let mut bytes = canonical_json(&json!({
        "schema_version":"bluefire.s3-generated-fixture.v1",
        "scope_id":scope_id,"purpose":purpose,
    }))
    .into_bytes();
    bytes.push(b'\n');
    bytes
}

pub(crate) fn validate_objects(scope: &Scope) -> Checked<()> {
    for object in &scope.objects {
        let raw = payload(&scope.scope_id, &object.purpose);
        require(
            object.size_bytes == raw.len() as u64
                && object.sha256 == format!("sha256:{}", sha256_hex(&raw)),
        )?;
    }
    Ok(())
}

impl FixtureEnrollment {
    pub(crate) fn checked(value: &Value, scope: &Scope) -> Checked<String> {
        let parsed: Self =
            serde_json::from_value(value.clone()).map_err(|_| "invalid fixture enrollment")?;
        require(encoded(&parsed)? == *value)?;
        require(
            parsed.schema_version == "bluefire.s3-fixture-enrollment.v2"
                && parsed.scope_digest == canonical_hash(&encoded(scope)?)
                && digest(&parsed.generation_digest)
                && digest(&parsed.exclusive_writer_digest)
                && parsed.bucket_shape == BUCKET_SHAPE,
        )?;
        validate_objects(scope)?;
        Ok(canonical_hash(value))
    }
}

impl FixtureOperation {
    pub(crate) fn validate(&self, name: &str, scope: &Scope) -> Checked<()> {
        require(
            self.schema_version == "bluefire.s3-fixture-operation.v2"
                && lower_hex(&self.intent_id, 64)
                && ["primary", "health"].contains(&self.purpose.as_str())
                && self.expected_etag.as_deref().is_none_or(etag)
                && ["prepare_fixture", "reconcile_fixture", "cleanup_fixture"].contains(&name)
                && (name != "prepare_fixture" || self.expected_etag.is_none()),
        )?;
        validate_objects(scope)
    }

    pub(crate) fn operations(&self, name: &str) -> Vec<&'static str> {
        let mut plan = vec![
            "GetCallerIdentity",
            "GetBucketVersioning",
            "GetObjectLockConfiguration",
            "GetObject",
        ];
        match name {
            "prepare_fixture" => plan.extend(["PutObject", "GetObject"]),
            "cleanup_fixture" if self.expected_etag.is_some() => {
                plan.extend(["DeleteObject", "GetObject", "ListObjectsV2"])
            }
            _ => plan.push("ListObjectsV2"),
        }
        plan
    }

    pub(crate) fn resource(
        &self,
        scope: &Scope,
        authority: &str,
        operation: &str,
    ) -> Checked<Value> {
        if operation == "GetCallerIdentity" {
            return Ok(json!({}));
        }
        let mut value = json!({"bucket":scope.bucket,"fixture_authority_digest":authority});
        if operation == "ListObjectsV2" {
            value["prefix"] = json!(scope.prefix);
            value["max_keys"] = json!(3);
        } else if !["GetBucketVersioning", "GetObjectLockConfiguration"].contains(&operation) {
            let object = scope
                .objects
                .iter()
                .find(|object| object.purpose == self.purpose)
                .ok_or("fixture object is absent")?;
            value["key"] = json!(object.key);
            value["intent_id"] = json!(self.intent_id);
            if operation == "DeleteObject" {
                value["expected_etag"] = json!(self.expected_etag);
            }
        }
        Ok(value)
    }

    pub(crate) fn validate_observation(
        &self,
        scope: &Scope,
        operation: &str,
        data: &Value,
        calls: &[Value],
    ) -> Checked<()> {
        let state = data["state"].as_str().ok_or("fixture state is absent")?;
        require(["owned", "absent", "drift"].contains(&state))?;
        let object = scope
            .objects
            .iter()
            .find(|object| object.purpose == self.purpose)
            .ok_or("fixture object is absent")?;
        require(
            *data
                == json!({
                    "purpose":self.purpose,"intent_id":self.intent_id,"state":state,
                    "etag":data["etag"],"expected_object":object,"bucket_shape":BUCKET_SHAPE,
                    "policy_mutated":false,
                }),
        )?;
        if state == "owned" {
            require(data["etag"].as_str().is_some_and(etag))?;
        } else {
            require(data["etag"].is_null())?;
        }
        require(operation != "prepare_fixture" || state == "owned")?;
        require(operation != "cleanup_fixture" || state == "absent")?;
        for (index, call) in calls.iter().enumerate() {
            let expected = if index == 2 {
                Some("ObjectLockConfigurationNotFoundError")
            } else if (operation == "prepare_fixture" && index == 3)
                || (operation == "cleanup_fixture"
                    && index == if self.expected_etag.is_some() { 5 } else { 3 })
                || (operation == "reconcile_fixture" && state == "absent" && index == 3)
            {
                Some("NoSuchKey")
            } else {
                None
            };
            match expected {
                Some(code) => require(call["http_status"] == 404 && call["error_code"] == code)?,
                None => require(
                    call.get("error_code").is_none()
                        && call["http_status"]
                            == if call["operation"] == "DeleteObject" {
                                204
                            } else {
                                200
                            },
                )?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "s3_fixture_tests.rs"]
pub(crate) mod tests;

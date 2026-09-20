//! Strict identity metadata for reviewed, preinstalled native tools.
//!
//! This module validates and hashes setup metadata only.  It does not inspect
//! the filesystem, establish readiness, or dispatch an executable.

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_hash;

pub const SCHEMA: &str = "bluefire.native-tool-installation.v1";
const MAX_SIZE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeToolInstallation {
    pub schema_version: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub adapter_contract_digest: String,
    pub tool_id: String,
    pub tool_version: String,
    pub platform: String,
    pub architecture: String,
    pub content_sha256: String,
    pub size_bytes: u64,
    pub installation_location: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeToolBinding {
    pub adapter_id: &'static str,
    pub adapter_version: &'static str,
    pub adapter_contract_digest: &'static str,
    pub tool_id: &'static str,
}

impl NativeToolInstallation {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA {
            return Err("native tool installation schema is unsupported".into());
        }
        stable_id(&self.adapter_id, "adapter_id")?;
        version(&self.adapter_version, "adapter_version")?;
        digest(&self.adapter_contract_digest, "adapter_contract_digest")?;
        stable_id(&self.tool_id, "tool_id")?;
        tool_version(&self.tool_version)?;
        if self.platform != "linux" {
            return Err("native tool installation platform is unsupported".into());
        }
        if !matches!(self.architecture.as_str(), "x86_64" | "aarch64") {
            return Err("native tool installation architecture is unsupported".into());
        }
        digest(&self.content_sha256, "content_sha256")?;
        if !(1..=MAX_SIZE_BYTES).contains(&self.size_bytes) {
            return Err("native tool installation size_bytes is invalid".into());
        }
        location(&self.installation_location)?;
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_hash(&serde_json::to_value(self).expect("native tool serialization cannot fail"))
    }
}

impl NativeToolBinding {
    pub fn check_binding(
        &self,
        installation: &NativeToolInstallation,
        platform: &str,
        architecture: &str,
    ) -> Result<(), String> {
        installation.validate()?;
        let expected = [
            (
                "adapter_id",
                self.adapter_id,
                installation.adapter_id.as_str(),
            ),
            (
                "adapter_version",
                self.adapter_version,
                installation.adapter_version.as_str(),
            ),
            (
                "adapter_contract_digest",
                self.adapter_contract_digest,
                installation.adapter_contract_digest.as_str(),
            ),
            ("tool_id", self.tool_id, installation.tool_id.as_str()),
            ("platform", platform, installation.platform.as_str()),
            (
                "architecture",
                architecture,
                installation.architecture.as_str(),
            ),
        ];
        for (field, expected, actual) in expected {
            if expected != actual {
                return Err(format!(
                    "native tool installation {field} does not match binding"
                ));
            }
        }
        Ok(())
    }
}

fn text(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max_len && !value.chars().any(|c| c < '\u{20}')
}

fn stable_id(value: &str, name: &str) -> Result<(), String> {
    if !text(value, 256) {
        return Err(format!("native tool installation {name} is invalid"));
    }
    let (base, version) = value
        .rsplit_once(".v")
        .ok_or_else(|| format!("native tool installation {name} is invalid"))?;
    if version.is_empty()
        || !version.chars().all(|c| c.is_ascii_digit())
        || version.starts_with('0')
        || base.is_empty()
        || !base.chars().next().is_some_and(|c| c.is_ascii_lowercase())
    {
        return Err(format!("native tool installation {name} is invalid"));
    }
    let mut segment_start = true;
    for c in base.chars() {
        if matches!(c, '.' | '_' | '-') {
            if segment_start {
                return Err(format!("native tool installation {name} is invalid"));
            }
            segment_start = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            segment_start = false;
        } else {
            return Err(format!("native tool installation {name} is invalid"));
        }
    }
    if segment_start {
        return Err(format!("native tool installation {name} is invalid"));
    }
    Ok(())
}

fn version(value: &str, name: &str) -> Result<(), String> {
    let valid = text(value, 256)
        && value.split('.').count() == 3
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    if valid {
        Ok(())
    } else {
        Err(format!("native tool installation {name} is invalid"))
    }
}

fn tool_version(value: &str) -> Result<(), String> {
    let valid = text(value, 64)
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if valid {
        Ok(())
    } else {
        Err("native tool installation tool_version is invalid".into())
    }
}

fn digest(value: &str, name: &str) -> Result<(), String> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(format!("native tool installation {name} is invalid"))
    }
}

fn location(value: &str) -> Result<(), String> {
    let invalid = !text(value, 4096)
        || !value.starts_with('/')
        || value.starts_with("//")
        || (value.len() > 1 && value.ends_with('/'))
        || value.contains('\\')
        || value
            .chars()
            .any(|c| c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c));
    if invalid
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Err("native tool installation location is not canonical".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn installation() -> NativeToolInstallation {
        NativeToolInstallation {
            schema_version: SCHEMA.into(),
            adapter_id: "sandbox.permission.chmod.v1".into(),
            adapter_version: "1.0.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.coreutils.chmod.v1".into(),
            tool_version: "9.5".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            content_sha256: format!("sha256:{}", "b".repeat(64)),
            size_bytes: 1234,
            installation_location: "/usr/bin/chmod".into(),
        }
    }

    #[test]
    fn serde_is_strict_and_digest_is_canonical() {
        let value = installation();
        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(value, serde_json::from_value(encoded.clone()).unwrap());
        assert!(serde_json::from_value::<NativeToolInstallation>(json!({
            "schema_version": SCHEMA,
            "adapter_id": "adapter.example.v1",
            "adapter_version": "1.2.3",
            "adapter_contract_digest": format!("sha256:{}", "a".repeat(64)),
            "tool_id": "tool.example.v1",
            "tool_version": "2026.09-linux",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": format!("sha256:{}", "b".repeat(64)),
            "size_bytes": 1,
            "installation_location": "/opt/bluefire/tool",
            "extra": true
        }))
        .is_err());
        assert_eq!(value.digest(), canonical_hash(&encoded));
        assert_eq!(
            value.digest(),
            "sha256:fd6a0ff27b30372ab441730505a2b3c3ae03e2c923632232ee832ab5021c16c8"
        );
    }

    #[test]
    fn validation_rejects_unsafe_identity_and_location() {
        let mut value = installation();
        value.adapter_id = "Adapter.example.v1".into();
        assert!(value.validate().is_err());
        value = installation();
        value.installation_location = "/opt/../tool".into();
        assert!(value.validate().is_err());
        value = installation();
        value.size_bytes = MAX_SIZE_BYTES + 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn binding_requires_exact_identity_and_target() {
        let value = installation();
        let binding = NativeToolBinding {
            adapter_id: "sandbox.permission.chmod.v1",
            adapter_version: "1.0.0",
            adapter_contract_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tool_id: "gnu.coreutils.chmod.v1",
        };
        assert!(binding.check_binding(&value, "linux", "x86_64").is_ok());
        assert!(binding.check_binding(&value, "linux", "aarch64").is_err());
    }
}

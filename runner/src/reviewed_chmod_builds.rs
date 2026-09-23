//! Adapter-owned GNU identity, independent of operator setup assertions.
//!
//! Adding a build requires package provenance review and a source change.
//! Neither an installation record nor a run/model request can extend this set.

use crate::native_tool_installations::NativeToolInstallation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnrecognizedToolBuild {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

#[derive(Debug)]
struct ReviewedBuild {
    version: &'static str,
    architecture: &'static str,
    content_sha256: &'static str,
    size_bytes: u64,
}

// Ubuntu Noble, Launchpad build 31108836. Package identity and reproducible
// extraction procedure: docs/REVIEWED_NATIVE_BUILDS.md. Never execute a candidate
// to determine its identity. Unknown builds require a reviewed source update.
const BUILDS: &[ReviewedBuild] = &[ReviewedBuild {
    version: "9.4-3ubuntu6.1",
    architecture: "x86_64",
    content_sha256: "sha256:4158cfdb26fb11602bebf64dc585bea557f2b7287eb49ad51c54f1f8897acada",
    size_bytes: 55816,
}];

pub(crate) fn verify(installation: &NativeToolInstallation) -> Result<(), UnrecognizedToolBuild> {
    if installation.adapter_id == "sandbox.permission.chmod.v1"
        && installation.tool_id == "gnu.coreutils.chmod.v1"
        && installation.platform == "linux"
        && BUILDS.iter().any(|build| {
            build.version == installation.tool_version
                && build.architecture == installation.architecture
                && build.content_sha256 == installation.content_sha256
                && build.size_bytes == installation.size_bytes
        })
    {
        Ok(())
    } else {
        Err(UnrecognizedToolBuild {
            code: "unrecognized_tool_build",
            message: "This executable and version do not match a reviewed GNU chmod build.",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed() -> NativeToolInstallation {
        let build = &BUILDS[0];
        NativeToolInstallation {
            schema_version: crate::native_tool_installations::SCHEMA.into(),
            adapter_id: "sandbox.permission.chmod.v1".into(),
            adapter_version: "1.0.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.coreutils.chmod.v1".into(),
            tool_version: build.version.into(),
            platform: "linux".into(),
            architecture: build.architecture.into(),
            content_sha256: build.content_sha256.into(),
            size_bytes: build.size_bytes,
            installation_location: "/usr/bin/chmod".into(),
        }
    }

    #[test]
    fn reviewed_bytes_can_have_a_nondefault_setup_location() {
        let mut installation = reviewed();
        assert!(verify(&installation).is_ok());
        installation.installation_location = "/opt/reviewed-tools/chmod".into();
        assert!(verify(&installation).is_ok());
        // Path protection and observation still occur in native_tool_inspection.
    }

    #[test]
    fn declared_identity_cannot_authorize_unknown_or_relabelled_bytes() {
        let mut variants = Vec::new();
        let mut changed = reviewed();
        changed.content_sha256 = format!("sha256:{}", "b".repeat(64));
        variants.push(changed);
        let mut changed = reviewed();
        changed.size_bytes += 1;
        variants.push(changed);
        let mut changed = reviewed();
        changed.tool_version = "9.4".into();
        variants.push(changed);
        let mut changed = reviewed();
        changed.architecture = "aarch64".into();
        variants.push(changed);
        let mut changed = reviewed();
        changed.tool_id = "gnu.coreutils.touch.v1".into();
        variants.push(changed);
        let mut changed = reviewed();
        changed.adapter_id = "sandbox.other.v1".into();
        variants.push(changed);
        for installation in variants {
            assert_eq!(
                verify(&installation).unwrap_err().code,
                "unrecognized_tool_build"
            );
        }
    }
}

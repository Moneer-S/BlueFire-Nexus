//! Adapter-owned GNU identity, independent of operator setup assertions.
//!
//! Adding a build requires package provenance review and a source change.
//! Neither an installation record nor a run/model request can extend this set.

use crate::native_tool_installations::{NativeToolInstallation, UnrecognizedToolBuild};

#[derive(Debug)]
struct ReviewedBuild {
    version: &'static str,
    architecture: &'static str,
    content_sha256: &'static str,
    size_bytes: u64,
}

// Ubuntu Noble gzip 1.12-1ubuntu3.2, official security archive. Package identity and reproducible
// extraction procedure: docs/REVIEWED_NATIVE_BUILDS.md. Never execute a candidate
// to determine its identity. Unknown builds require a reviewed source update.
const BUILDS: &[ReviewedBuild] = &[
    ReviewedBuild {
        version: "1.12-1ubuntu3.2",
        architecture: "x86_64",
        content_sha256: "sha256:afea077ce127d4fa9ad410d3066ba2b54dea19c0b44f04adf56c72d5f7b7a9bb",
        size_bytes: 93424,
    },
    ReviewedBuild {
        version: "1.12-1ubuntu3.1",
        architecture: "x86_64",
        content_sha256: "sha256:16f1f8dbe5b47b3c1160b9066bd15bfdd80548b1b878b1a025c462fec0ca02b1",
        size_bytes: 93424,
    },
];

pub(crate) fn verify(installation: &NativeToolInstallation) -> Result<(), UnrecognizedToolBuild> {
    if installation.adapter_id == "sandbox.collection.atomic-gzip.v1"
        && installation.tool_id == "gnu.gzip.v1"
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
            message: "This executable and version do not match a reviewed GNU gzip build.",
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
            adapter_id: "sandbox.collection.atomic-gzip.v1".into(),
            adapter_version: "1.1.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.gzip.v1".into(),
            tool_version: build.version.into(),
            platform: "linux".into(),
            architecture: build.architecture.into(),
            content_sha256: build.content_sha256.into(),
            size_bytes: build.size_bytes,
            installation_location: "/usr/bin/gzip".into(),
        }
    }

    #[test]
    fn reviewed_bytes_can_have_a_nondefault_setup_location() {
        let mut installation = reviewed();
        assert!(verify(&installation).is_ok());
        installation.installation_location = "/opt/reviewed-tools/gzip".into();
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
        changed.tool_version = "1.12".into();
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

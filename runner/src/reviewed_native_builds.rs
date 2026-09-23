//! Closed dispatch to adapter-owned reviewed package identities.
//!
//! Installation records and planner output cannot register additional tools.

use crate::native_tool_installations::{NativeToolInstallation, UnrecognizedToolBuild};

pub(crate) fn supports(adapter_id: &str) -> bool {
    matches!(
        adapter_id,
        "sandbox.permission.chmod.v1" | "sandbox.collection.atomic-gzip.v1"
    )
}

pub(crate) fn verify(installation: &NativeToolInstallation) -> Result<(), UnrecognizedToolBuild> {
    match installation.adapter_id.as_str() {
        "sandbox.permission.chmod.v1" => crate::reviewed_chmod_builds::verify(installation),
        "sandbox.collection.atomic-gzip.v1" => crate::reviewed_gzip_builds::verify(installation),
        _ => Err(UnrecognizedToolBuild {
            code: "unrecognized_tool_build",
            message: "The method has no reviewed native tool build.",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_registry_is_closed_and_does_not_admit_ordinary_actions() {
        assert!(supports("sandbox.permission.chmod.v1"));
        assert!(supports("sandbox.collection.atomic-gzip.v1"));
        for unknown in [
            "gzip",
            "sandbox.fixture.transform.v1",
            "sandbox.collection.other.v1",
        ] {
            assert!(!supports(unknown));
        }
    }
}

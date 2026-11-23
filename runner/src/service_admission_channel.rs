//! Service-specific validation using the shared protected launch channel.

use std::ffi::OsString;
use std::path::Path;

use super::wire::require;
use super::{wire, VerifiedServiceAdmission, REFUSAL};
#[cfg(test)]
use crate::protected_launch_channel::sealed;
use crate::protected_launch_channel::{self as channel, bounded};

const PROTOCOL: &str = "bluefire.owned-user-service-launch.v1";

pub(super) fn verify(
    context_fd: Option<OsString>,
    envelope_fd: Option<OsString>,
    manifest_path: &Path,
    profile_path: &Path,
) -> Result<VerifiedServiceAdmission, String> {
    checked(context_fd, envelope_fd, manifest_path, profile_path).map_err(|_| REFUSAL.into())
}

fn checked(
    context_fd: Option<OsString>,
    envelope_fd: Option<OsString>,
    manifest_path: &Path,
    profile_path: &Path,
) -> Result<VerifiedServiceAdmission, String> {
    let launch = channel::verify(context_fd, envelope_fd, PROTOCOL)?;
    let manifest =
        serde_json::from_slice(&bounded(manifest_path, 1024 * 1024)?).map_err(|_| REFUSAL)?;
    let profile =
        serde_json::from_slice(&bounded(profile_path, 1024 * 1024)?).map_err(|_| REFUSAL)?;
    let mut checked = wire::validate(
        &launch.admission,
        &launch.issuer,
        &manifest,
        &profile,
        crate::contract::utc_now().fixed_offset(),
    )?;
    if let Some(runtime) = &checked.observation_runtime {
        require(runtime.matches(&checked.scope["observation_runtime"]))?;
        runtime.require_supported(launch.deadline)?;
    }
    require(
        checked.owner_uid() == launch.uid
            && launch.admission["issuer"]["runner_id"] == manifest["runner_id"]
            && checked.scope["installations"]["payload"]["content_sha256"] == launch.runner_digest,
    )?;
    let boot = bounded("/proc/sys/kernel/random/boot_id", 64)?;
    require(std::str::from_utf8(&boot).map_err(|_| REFUSAL)?.trim() == checked.boot_id())?;
    checked.installations = crate::service_installations::inspect(
        &checked.scope,
        &profile,
        launch.current_runner(),
        launch.deadline,
    )?
    .into_iter()
    .collect();
    for installation in &checked.installations {
        installation.recheck().map_err(|_| REFUSAL)?;
    }
    launch.recheck()?;
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_context_or_envelope_is_refused() {
        assert!(verify(
            None,
            Some("4".into()),
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
        assert!(verify(
            Some("4".into()),
            None,
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
    }

    #[test]
    fn invalid_unsealed_and_aliased_descriptors_are_refused() {
        assert!(sealed(Some("123456789".into()), 1).is_err());
        assert!(sealed(Some("02".into()), 1).is_err());
        assert!(sealed(Some("0".into()), 1).is_err());
        assert!(verify(
            Some("4".into()),
            Some("4".into()),
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
    }
}

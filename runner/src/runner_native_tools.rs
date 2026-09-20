//! Profile-owned tool identities must match a compiled method declaration.

use crate::actions::{find_action, Action};
use crate::contract::{Platform, RunnerProfile};

pub(super) fn validate_profile(profile: &RunnerProfile) -> Result<(), String> {
    if profile.native_tool_installations.len() > 16 {
        return Err("native tool installation count exceeds the profile limit".into());
    }
    let mut previous: Option<&str> = None;
    for installation in &profile.native_tool_installations {
        installation.validate()?;
        if previous.is_some_and(|id| id >= installation.adapter_id.as_str()) {
            return Err("native tool installations must be unique and ordered by adapter".into());
        }
        previous = Some(&installation.adapter_id);
        if !profile.allowed_actions.contains(&installation.adapter_id) {
            return Err("native tool installation is outside the allowed actions".into());
        }
        let action = find_action(&installation.adapter_id)
            .ok_or("native tool installation names an unregistered method")?;
        let binding = action
            .native_tool_binding()
            .ok_or("registered method does not admit an external tool installation")?;
        if profile.platform != Platform::Linux {
            return Err("native tool installation requires its supported Linux profile".into());
        }
        binding.check_binding(installation, "linux", std::env::consts::ARCH)?;
    }
    Ok(())
}

pub(super) fn validate_selected(
    profile: &RunnerProfile,
    action: &dyn Action,
) -> Result<(), String> {
    let Some(binding) = action.native_tool_binding() else {
        return Ok(());
    };
    let installation = profile
        .native_tool_installations
        .iter()
        .find(|installation| installation.adapter_id == binding.adapter_id)
        .ok_or("selected method has no approved tool installation")?;
    if profile.platform != Platform::Linux {
        return Err("selected tool requires its supported Linux profile".into());
    }
    binding.check_binding(installation, "linux", std::env::consts::ARCH)
}

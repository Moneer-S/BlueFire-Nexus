"""Managed configuration for the reserved S3 workflow, not catalog authority."""

from .config import CleanupPolicy, ConfigError, EnvironmentType, RunnerProfile
from .contracts import ExecutionMode, SafetyTier

ACTION = "owned.aws.s3_access.v1"
CAPABILITY = "cloud.aws.s3.access"


def validate_managed_s3_profile(profile: RunnerProfile) -> bool:
    """Handle only a dedicated S3 envelope; ordinary profiles use the registry."""
    if (
        ACTION not in (*profile.enabled_actions, *profile.blocked_actions)
        and CAPABILITY not in profile.capabilities
    ):
        return False
    if (
        profile.mode is not ExecutionMode.EXECUTE
        or profile.environment_type is not EnvironmentType.CLOUD_LAB
        or profile.platforms != ("linux",)
        or profile.scope != ("sandbox.workspace",)
        or profile.network_allowlist
        or profile.capabilities != (CAPABILITY,)
        or set(profile.safety_tiers) != {SafetyTier.SAFE, SafetyTier.CONTROLLED}
        or not profile.approval_required
        or profile.enabled_actions != (ACTION,)
        or profile.blocked_actions
        or profile.cleanup_policy is not CleanupPolicy.ALWAYS
        or profile.secrets
        or profile.native_tool_installations
    ):
        raise ConfigError("S3 setup requires a dedicated approved Linux cloud-lab profile")
    return True

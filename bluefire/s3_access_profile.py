"""Managed configuration for the reserved S3 workflow, not catalog authority."""

from .config import CleanupPolicy, ConfigError, EnvironmentType, RunnerProfile
from .contracts import ExecutionMode, SafetyTier
from .runner_contracts import execution_limits, seal_profile
from .s3_access_contract import S3AccessError, exact
from .util import content_hash

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
    from .s3_access_results import PHASES

    # Each reviewed stage is finite and must fit before its first task is dispatched.
    if profile.budgets.max_steps < max(map(len, PHASES.values())):
        raise ConfigError("S3 setup step budget must cover every fixed stage")
    return True


def validate_s3_profile_binding(value, selected, *, managed_profile_digest):
    """Match the installed native policy to the current dedicated profile, without IO."""
    if not validate_managed_s3_profile(selected):
        raise S3AccessError("S3 requires a dedicated active profile")
    if managed_profile_digest != content_hash(selected.to_dict()):
        raise S3AccessError("S3 configuration does not retain the current complete profile")
    exact(
        value,
        {
            "schema_version",
            "profile_id",
            "runner_id",
            "platform",
            "sandbox_root",
            "allowed_actions",
            "control_blocked_actions",
            "capabilities",
            "max_safety_tier",
            "approval_required_at_or_above",
            "target_scope",
            "limits",
            "policy_digest",
        },
        "S3 configured profile",
    )
    target = exact(value["target_scope"], {"filesystem", "network"}, "S3 configured target")
    filesystem = target["filesystem"]
    if (
        value["schema_version"] != "bluefire.runner-profile.v1"
        or value["platform"] != "linux"
        or value["profile_id"] != selected.id
        or value["allowed_actions"] != [ACTION]
        or value["capabilities"] != ["cloud_aws_s3_access"]
        or value["control_blocked_actions"] != []
        or value["max_safety_tier"] != "controlled"
        or value["approval_required_at_or_above"] != "safe"
        or target["network"] != []
        or not isinstance(filesystem, list)
        or len(filesystem) > 3
        or any(
            not isinstance(item, str) or item not in ("fixtures", "staged", "exports")
            for item in filesystem
        )
        or len(set(filesystem)) != len(filesystem)
    ):
        raise S3AccessError("S3 configuration does not match the active profile policy")
    expected = execution_limits(selected)
    limits = exact(value["limits"], set(expected), "S3 configured limits")
    if any(type(limits[key]) is not int or limits[key] != limit for key, limit in expected.items()):
        raise S3AccessError("S3 configuration does not match the active profile limits")
    if value["policy_digest"] != seal_profile(value)["policy_digest"]:
        raise S3AccessError("S3 configuration policy seal is invalid")


def validate_s3_host_binding(value, selected, *, managed_profile_digest, runner_id, sandbox):
    """Also bind the sealed policy to the authenticated lifecycle's exact host."""
    from pathlib import Path

    validate_s3_profile_binding(value, selected, managed_profile_digest=managed_profile_digest)
    if value["runner_id"] != runner_id or Path(value["sandbox_root"]) != sandbox:
        raise S3AccessError("S3 configuration belongs to a different runner or sandbox")

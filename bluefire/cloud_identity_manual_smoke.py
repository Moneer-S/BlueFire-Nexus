"""Bounded real-AWS manual smoke contract using credential profile references."""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .cloud_identity_contracts import (
    ACCOUNT_RE,
    CONTROL_ACTION,
    CONTROL_TAG_KEY,
    MANUAL_CONFIRMATION,
    MANUAL_SMOKE_SCHEMA,
    PACK_ID,
    PROFILE_ID,
    PROFILE_NAME_RE,
    REGION_RE,
    REVOCATION_ACTION,
    ROLE_RE,
    SAFE_ID_RE,
    AwsManualSmokeError,
    control_tag_value,
)

_MAX_AWS_OUTPUT_BYTES = 256 * 1024
_MAX_AWS_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class AwsManualSmokeRequest:
    """Credential-value-free request for a bounded manual real-AWS smoke."""

    credential_profile: str
    account_id: str
    role_name: str
    region: str
    approval_id: str
    approved_account_id: str
    approved_role_name: str
    confirmation: str
    timeout_seconds: int = 20

    def __post_init__(self) -> None:
        if not PROFILE_NAME_RE.fullmatch(self.credential_profile):
            raise AwsManualSmokeError("AWS credential profile name is invalid")
        if not ACCOUNT_RE.fullmatch(self.account_id):
            raise AwsManualSmokeError("AWS account id is invalid")
        if not ROLE_RE.fullmatch(self.role_name):
            raise AwsManualSmokeError("AWS lab role name is invalid")
        if not REGION_RE.fullmatch(self.region):
            raise AwsManualSmokeError("AWS region is invalid")
        if not SAFE_ID_RE.fullmatch(self.approval_id):
            raise AwsManualSmokeError("AWS approval id is invalid")
        if self.approved_account_id != self.account_id:
            raise AwsManualSmokeError("AWS approval does not bind the requested account")
        if self.approved_role_name != self.role_name:
            raise AwsManualSmokeError("AWS approval does not bind the requested role")
        if self.confirmation != MANUAL_CONFIRMATION:
            raise AwsManualSmokeError("AWS reversible action was not explicitly confirmed")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= _MAX_AWS_TIMEOUT_SECONDS
        ):
            raise AwsManualSmokeError("AWS command timeout is invalid")

    @property
    def credential_reference(self) -> str:
        return f"aws-profile://{self.credential_profile}"

    @property
    def role_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"


@dataclass(frozen=True, slots=True)
class AwsSmokeCommand:
    phase: str
    operation: str
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AwsCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes = b""


AwsCommandInvoker = Callable[[AwsSmokeCommand, int], AwsCommandResult]


def build_aws_identity_lab_smoke_commands(
    request: AwsManualSmokeRequest,
) -> tuple[AwsSmokeCommand, ...]:
    """Return the complete fixed-argv, bounded manual-smoke command contract."""

    if not isinstance(request, AwsManualSmokeRequest):
        raise AwsManualSmokeError("AWS manual smoke request is invalid")
    prefix = (
        "aws",
        "--no-cli-pager",
        "--profile",
        request.credential_profile,
        "--region",
        request.region,
    )
    tag_value = control_tag_value(request.approval_id)
    return (
        AwsSmokeCommand(
            "enumeration",
            "GetCallerIdentity",
            prefix + ("sts", "get-caller-identity", "--output", "json"),
        ),
        AwsSmokeCommand(
            "enumeration",
            "GetRole",
            prefix + ("iam", "get-role", "--role-name", request.role_name, "--output", "json"),
        ),
        AwsSmokeCommand(
            "enumeration",
            "ListRoleTagsBefore",
            prefix
            + (
                "iam",
                "list-role-tags",
                "--role-name",
                request.role_name,
                "--max-items",
                "100",
                "--output",
                "json",
            ),
        ),
        AwsSmokeCommand(
            "action",
            "TagRole",
            prefix
            + (
                "iam",
                "tag-role",
                "--role-name",
                request.role_name,
                "--tags",
                f"Key={CONTROL_TAG_KEY},Value={tag_value}",
            ),
        ),
        AwsSmokeCommand(
            "audit",
            "ListRoleTagsAfter",
            prefix
            + (
                "iam",
                "list-role-tags",
                "--role-name",
                request.role_name,
                "--max-items",
                "100",
                "--output",
                "json",
            ),
        ),
        AwsSmokeCommand(
            "revocation",
            "UntagRole",
            prefix
            + (
                "iam",
                "untag-role",
                "--role-name",
                request.role_name,
                "--tag-keys",
                CONTROL_TAG_KEY,
            ),
        ),
        AwsSmokeCommand(
            "audit",
            "ListRoleTagsCleanup",
            prefix
            + (
                "iam",
                "list-role-tags",
                "--role-name",
                request.role_name,
                "--max-items",
                "100",
                "--output",
                "json",
            ),
        ),
        AwsSmokeCommand(
            "audit",
            "LookupEvents",
            prefix
            + (
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                f"AttributeKey=ResourceName,AttributeValue={request.role_name}",
                "--max-results",
                "10",
                "--output",
                "json",
            ),
        ),
    )


def _default_aws_invoker(command: AwsSmokeCommand, timeout: int) -> AwsCommandResult:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name
        not in {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
        }
    }
    environment["AWS_PAGER"] = ""
    try:
        # The executable and every argv position have a fixed, validated grammar.
        completed = subprocess.run(  # nosec B603
            list(command.argv),
            shell=False,
            check=False,
            capture_output=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AwsManualSmokeError(f"AWS {command.phase} command could not complete") from exc
    return AwsCommandResult(completed.returncode, completed.stdout, completed.stderr)


def _invoke_aws(
    invoker: AwsCommandInvoker,
    command: AwsSmokeCommand,
    timeout: int,
) -> Mapping[str, Any]:
    try:
        result = invoker(command, timeout)
    except AwsManualSmokeError:
        raise
    except BaseException as exc:
        raise AwsManualSmokeError(f"AWS {command.phase} command could not complete") from exc
    if not isinstance(result, AwsCommandResult):
        raise AwsManualSmokeError("AWS command runner returned an invalid result")
    if (
        isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not isinstance(result.stdout, bytes)
        or not isinstance(result.stderr, bytes)
        or len(result.stdout) > _MAX_AWS_OUTPUT_BYTES
        or len(result.stderr) > _MAX_AWS_OUTPUT_BYTES
    ):
        raise AwsManualSmokeError(f"AWS {command.phase} command output was invalid or unbounded")
    if result.returncode != 0:
        raise AwsManualSmokeError(f"AWS {command.phase} command failed")
    if not result.stdout:
        return {}
    try:
        value = json.loads(result.stdout.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AwsManualSmokeError(f"AWS {command.phase} command returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise AwsManualSmokeError(f"AWS {command.phase} command returned invalid JSON")
    return value


def _tags(value: Mapping[str, Any]) -> dict[str, str]:
    raw = value.get("Tags")
    if not isinstance(raw, list) or len(raw) > 100:
        raise AwsManualSmokeError("AWS role tags response is invalid")
    tags: dict[str, str] = {}
    for item in raw:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not isinstance(item.get("Value"), str)
            or item["Key"] in tags
        ):
            raise AwsManualSmokeError("AWS role tags response is invalid")
        tags[str(item["Key"])] = str(item["Value"])
    return tags


def run_aws_identity_lab_smoke(
    request: AwsManualSmokeRequest,
    *,
    invoker: AwsCommandInvoker | None = None,
) -> Mapping[str, Any]:
    """Run a manually invoked, reversible real-AWS identity-lab smoke."""

    commands = build_aws_identity_lab_smoke_commands(request)
    call = invoker or _default_aws_invoker
    completed: list[str] = []
    tag_attempted = False
    cleanup_verified = False
    primary_error: BaseException | None = None
    tag_value = control_tag_value(request.approval_id)

    try:
        identity = _invoke_aws(call, commands[0], request.timeout_seconds)
        completed.append(commands[0].operation)
        if identity.get("Account") != request.account_id:
            raise AwsManualSmokeError("AWS caller identity does not match the approved account")
        arn = identity.get("Arn")
        if not isinstance(arn, str) or not arn.startswith("arn:aws:"):
            raise AwsManualSmokeError("AWS caller identity response is invalid")

        role = _invoke_aws(call, commands[1], request.timeout_seconds)
        completed.append(commands[1].operation)
        raw_role = role.get("Role")
        if not isinstance(raw_role, Mapping) or raw_role.get("Arn") != request.role_arn:
            raise AwsManualSmokeError("AWS target role does not match the approval")

        before = _tags(_invoke_aws(call, commands[2], request.timeout_seconds))
        completed.append(commands[2].operation)
        if CONTROL_TAG_KEY in before:
            raise AwsManualSmokeError("AWS lab control tag already exists")

        tag_attempted = True
        _invoke_aws(call, commands[3], request.timeout_seconds)
        completed.append(commands[3].operation)
        after = _tags(_invoke_aws(call, commands[4], request.timeout_seconds))
        completed.append(commands[4].operation)
        if after.get(CONTROL_TAG_KEY) != tag_value:
            raise AwsManualSmokeError("AWS lab action was not observed")
    except BaseException as exc:
        primary_error = exc
    finally:
        if tag_attempted:
            try:
                _invoke_aws(call, commands[5], request.timeout_seconds)
                completed.append(commands[5].operation)
                cleaned = _tags(_invoke_aws(call, commands[6], request.timeout_seconds))
                completed.append(commands[6].operation)
                cleanup_verified = CONTROL_TAG_KEY not in cleaned
                if not cleanup_verified:
                    raise AwsManualSmokeError("AWS lab cleanup was not observed")
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error

    if primary_error is not None:
        raise AwsManualSmokeError("AWS identity-lab smoke failed closed") from primary_error
    if not cleanup_verified:
        raise AwsManualSmokeError("AWS identity-lab smoke did not verify cleanup")

    audit = _invoke_aws(call, commands[7], request.timeout_seconds)
    completed.append(commands[7].operation)
    raw_events = audit.get("Events")
    if not isinstance(raw_events, list) or len(raw_events) > 10:
        raise AwsManualSmokeError("AWS CloudTrail audit response is invalid")
    event_names = {
        event.get("EventName")
        for event in raw_events
        if isinstance(event, Mapping) and isinstance(event.get("EventName"), str)
    }
    if not {"TagRole", "UntagRole"} <= event_names:
        raise AwsManualSmokeError("AWS CloudTrail audit expectations were not met")

    return {
        "schema_version": MANUAL_SMOKE_SCHEMA,
        "passed": True,
        "pack_id": PACK_ID,
        "profile_id": PROFILE_ID,
        "credential_reference": request.credential_reference,
        "approval": {
            "approval_id": request.approval_id,
            "account_id": request.account_id,
            "role_name": request.role_name,
            "action": CONTROL_ACTION,
            "revocation_action": REVOCATION_ACTION,
        },
        "phases": ["enumeration", "action", "revocation", "audit"],
        "operations": completed,
        "enumeration_verified": True,
        "action_verified": True,
        "cleanup_verified": True,
        "audit_verified": True,
    }


__all__ = [
    "AwsCommandInvoker",
    "AwsCommandResult",
    "AwsManualSmokeRequest",
    "AwsSmokeCommand",
    "build_aws_identity_lab_smoke_commands",
    "run_aws_identity_lab_smoke",
]

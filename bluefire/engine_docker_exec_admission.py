"""Explicit V2 admission for pinned Strix's in-sandbox exec interface.

This is a controller-side contract, never authority supplied in HTTP headers.
The dynamic command grammar is the pinned SDK's ``sh -lc/-c <script>`` and
Strix's explicit ``bash -lc/-c <script>`` envelope. Script bytes are model chosen
inside the qualified isolated sandbox; this module does not interpret or make
shell programs safe. The
controller must retain the exact admission through create/start/inspect and
reconcile uncertain execution by terminating its owned sandbox through custody.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping, Protocol

from .strix_controlled_backend import (
    ControlledExecRequest,
    ControlledRuntimeProfile,
    ControlledSandboxHandle,
)
from .util import content_hash


class DockerExecAdmissionError(ValueError):
    """An exec does not bind the controller's exact admitted operation."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_OPERATION_ID = re.compile(r"operation-[0-9a-f]{32}")
_EXEC_CREATE_FIELDS = frozenset(
    {
        "AttachStderr",
        "AttachStdin",
        "AttachStdout",
        "Cmd",
        "DetachKeys",
        "Env",
        "Privileged",
        "Tty",
        "User",
        "WorkingDir",
    }
)


class DockerExecPolicyBindings(Protocol):
    @property
    def expected_user(self) -> str: ...

    @property
    def exec_working_directory(self) -> str: ...


class DockerExecPolicyBindingsV2(DockerExecPolicyBindings, Protocol):
    @property
    def policy_digest(self) -> str: ...

    @property
    def execution_identity_digest(self) -> str: ...

    @property
    def controlled_runtime_profile_ref(self) -> str: ...

    @property
    def attempt_id(self) -> str: ...

    @property
    def exec_response_byte_limit(self) -> int: ...


def _matches(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_strix_exec_argv(argv: tuple[str, ...]) -> None:
    """Admit the reviewed SDK shell envelope and its fixed workspace mkdir."""

    if (
        type(argv) is not tuple
        or not 1 <= len(argv) <= 64
        or any(
            not isinstance(arg, str)
            or not arg
            or any((ord(c) < 32 and c not in {"\t", "\n"}) or ord(c) == 127 for c in arg)
            for arg in argv
        )
    ):
        raise DockerExecAdmissionError("V2 exec arguments are invalid")
    try:
        size = sum(len(arg.encode("utf-8")) for arg in argv)
    except UnicodeError as exc:
        raise DockerExecAdmissionError("V2 exec arguments are not UTF-8") from exc
    if size > 8192 or not (
        argv == ("mkdir", "-p", "/workspace")
        or (
            len(argv) == 3
            and argv[:2] in {("sh", "-lc"), ("sh", "-c"), ("bash", "-lc"), ("bash", "-c")}
        )
    ):
        raise DockerExecAdmissionError("V2 exec command grammar is not reviewed")


@dataclass(frozen=True, slots=True)
class DockerExecAdmissionV2:
    """One exact controlled request bound to one qualified Docker policy.

    Construction checks public backend request digests; authorization also
    compares the policy, protected execution identity and runtime profile.
    Possession is not a replacement for those controller-owned bindings.
    """

    policy_digest: str
    execution_identity_digest: str
    container_id: str
    profile: ControlledRuntimeProfile = field(repr=False)
    request: ControlledExecRequest = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _matches(self.policy_digest, _DIGEST)
            or not _matches(self.execution_identity_digest, _DIGEST)
            or not _matches(self.container_id, _CONTAINER_ID)
            or type(self.profile) is not ControlledRuntimeProfile
            or type(self.request) is not ControlledExecRequest
            or type(self.request.handle) is not ControlledSandboxHandle
        ):
            raise DockerExecAdmissionError("V2 exec admission identity is invalid")
        # Reopen the public profile instead of trusting a previously constructed
        # instance's derived digest or a duck-typed replacement.
        profile = ControlledRuntimeProfile(**asdict(self.profile))
        request = self.request
        ControlledSandboxHandle(
            request.handle.attempt_id,
            request.handle.resource_id,
            request.handle.resource_digest,
            request.handle.opaque_ref,
        )
        if (
            request.schema_version != "bluefire.strix-controlled-exec-request.v1"
            or request.identity_digest != profile.identity_digest
            or request.handle.attempt_id != profile.attempt_id
            or not _matches(request.operation_id, _OPERATION_ID)
            or request.working_directory != "/workspace"
            or request.stdin_mode != "disabled"
            or request.pty is not False
            or profile.sandbox_user != "1000:1000"
            or isinstance(request.timeout_seconds, bool)
            or not isinstance(request.timeout_seconds, (int, float))
            or not math.isfinite(request.timeout_seconds)
            or not 0 < request.timeout_seconds <= profile.exec_timeout_seconds
        ):
            raise DockerExecAdmissionError("V2 exec public request differs from profile")
        validate_strix_exec_argv(request.argv)
        expected = content_hash(
            {
                "schema_version": request.schema_version,
                "identity_digest": profile.identity_digest,
                "attempt_id": profile.attempt_id,
                "profile_digest": profile.profile_digest,
                "resource_digest": request.handle.resource_digest,
                "operation_id": request.operation_id,
                "argv": list(request.argv),
                "timeout_seconds": float(request.timeout_seconds),
                "working_directory": "/workspace",
                "stdin_mode": "disabled",
                "pty": False,
            }
        )
        if request.request_digest != expected:
            raise DockerExecAdmissionError("V2 exec public request digest differs")

    @property
    def command_digest(self) -> str:
        return content_hash({"argv": list(self.request.argv)})

    @property
    def environment(self) -> tuple[str, ...]:
        # Deterministic subset of the reviewed manifest environment, never an
        # environment supplied by the worker. Caido is sandbox-loopback only.
        return (
            "ALL_PROXY=http://127.0.0.1:48080",
            "NO_PROXY=localhost,127.0.0.1",
            "http_proxy=http://127.0.0.1:48080",
            "https_proxy=http://127.0.0.1:48080",
        )

    def docker_create_body(self) -> dict[str, Any]:
        """Emit the exact reviewed body; callers cannot supply extra exec env."""

        return {
            "AttachStderr": True,
            "AttachStdin": False,
            "AttachStdout": True,
            "Cmd": list(self.request.argv),
            "DetachKeys": "",
            "Env": list(self.environment),
            "Privileged": False,
            "Tty": False,
            "User": self.profile.sandbox_user,
            "WorkingDir": "/workspace",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-docker-exec-admission.v2",
            "policy_digest": self.policy_digest,
            "execution_identity_digest": self.execution_identity_digest,
            "attempt_id": self.profile.attempt_id,
            "container_id": self.container_id,
            "controlled_identity_digest": self.request.identity_digest,
            "profile_digest": self.profile.profile_digest,
            "resource_digest": self.request.handle.resource_digest,
            "resource_id": self.request.handle.resource_id,
            "operation_id": self.request.operation_id,
            "request_digest": self.request.request_digest,
            "command_digest": self.command_digest,
            "environment_digest": content_hash({"Env": list(self.environment)}),
            "docker_create_body_digest": content_hash(self.docker_create_body()),
            "timeout_seconds": float(self.request.timeout_seconds),
            "output_limit_bytes": self.profile.exec_output_limit_bytes,
        }

    @property
    def admission_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class DockerExecBindingV2:
    """Audited daemon exec ID and lifecycle for an exact admitted operation."""

    exec_id: str
    admission: DockerExecAdmissionV2
    phase: Literal["created", "started", "complete"] = "created"
    deadline_monotonic_ns: int | None = None

    def __post_init__(self) -> None:
        if (
            not _matches(self.exec_id, _CONTAINER_ID)
            or type(self.admission) is not DockerExecAdmissionV2
            or self.phase not in {"created", "started", "complete"}
            or (
                self.deadline_monotonic_ns is not None
                and (type(self.deadline_monotonic_ns) is not int or self.deadline_monotonic_ns < 0)
            )
        ):
            raise DockerExecAdmissionError("V2 exec binding is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "exec_id": self.exec_id,
            "admission": self.admission.to_dict(),
            "phase": self.phase,
            "deadline_monotonic_ns": self.deadline_monotonic_ns,
        }


def validate_docker_exec_body(
    policy: DockerExecPolicyBindings,
    row: Mapping[str, Any],
    admission: DockerExecAdmissionV2 | None = None,
) -> Mapping[str, Any]:
    """Validate a parsed create body while preserving the legacy V1 bounds."""

    if set(row) != _EXEC_CREATE_FIELDS:
        raise DockerExecAdmissionError("Docker exec create fields do not match the contract")
    for key, expected in (
        ("AttachStdin", False),
        ("AttachStdout", True),
        ("AttachStderr", True),
        ("Privileged", False),
        ("Tty", False),
    ):
        if type(row[key]) is not bool or row[key] is not expected:
            raise DockerExecAdmissionError(f"Docker exec {key} must be {str(expected).lower()}")
    if row["DetachKeys"] != "" or row["Env"] != (
        list(admission.environment) if admission is not None else []
    ):
        raise DockerExecAdmissionError("Docker exec may not override keys or environment")
    if row["User"] != policy.expected_user:
        raise DockerExecAdmissionError("Docker exec user does not match custody")
    if row["WorkingDir"] != policy.exec_working_directory:
        raise DockerExecAdmissionError(
            "Docker exec working directory is not the isolated workspace"
        )
    command = row["Cmd"]
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 64
        or any(
            not isinstance(item, str)
            or not item
            or any(
                (ord(character) < 32 and not (admission is not None and character in {"\t", "\n"}))
                or ord(character) == 127
                for character in item
            )
            for item in command
        )
        or sum(len(item.encode("utf-8")) for item in command) > 8192
    ):
        raise DockerExecAdmissionError("Docker exec command is outside its sandbox bound")
    if admission is not None and command != list(admission.request.argv):
        raise DockerExecAdmissionError("V2 Docker exec command differs from admitted request")
    return row


def require_v2_exec_admission(
    policy: DockerExecPolicyBindingsV2,
    admission: DockerExecAdmissionV2 | None,
    container_id: str,
    binding: DockerExecBindingV2 | None = None,
    exec_id: str | None = None,
) -> DockerExecAdmissionV2:
    """Reopen one admission and compare its protected controller bindings."""

    if type(admission) is not DockerExecAdmissionV2:
        raise DockerExecAdmissionError(
            "V2 Docker exec is not admitted without controller admission"
        )
    try:
        DockerExecAdmissionV2(
            admission.policy_digest,
            admission.execution_identity_digest,
            admission.container_id,
            admission.profile,
            admission.request,
        )
    except (DockerExecAdmissionError, TypeError, ValueError, RuntimeError) as exc:
        raise DockerExecAdmissionError("V2 Docker exec admission is invalid") from exc
    if (
        admission.policy_digest != policy.policy_digest
        or admission.execution_identity_digest != policy.execution_identity_digest
        or admission.profile.profile_digest != policy.controlled_runtime_profile_ref
        or admission.profile.attempt_id != policy.attempt_id
        or admission.container_id != container_id
        or admission.profile.sandbox_user != policy.expected_user
        or policy.exec_working_directory != "/workspace"
        or admission.profile.exec_output_limit_bytes != policy.exec_response_byte_limit
    ):
        raise DockerExecAdmissionError("V2 Docker exec admission binds another policy or resource")
    if exec_id is not None and (
        type(binding) is not DockerExecBindingV2
        or binding.exec_id != exec_id
        or binding.admission.admission_digest != admission.admission_digest
    ):
        raise DockerExecAdmissionError("V2 Docker exec operation binding differs")
    return admission

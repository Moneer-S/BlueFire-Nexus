"""Observation-gated Test-provider policy for the tenant-record lab.

This module is deliberately not a model.  It drives the real installed Strix
tool loop with a small deterministic policy while requiring every tool result
to be correlated by a controller-owned observation source before another call
is emitted.  The policy proves installed transport, tool, lifecycle and target
mechanics only; it never establishes live-model decision quality or a security
outcome.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import urlsplit

from .controlled_strix_provider import (
    DEFAULT_MODEL_ID,
    ControlledProviderError,
    ControlledProviderManifest,
    ControlledProviderState,
    _canonical,
    _reject_nonfinite,
    _schema_depth,
    _sha256,
    _strict_object,
    _validate_schema_value,
)
from .strix_tool_conformance import (
    BASE_TOOL_NAMES,
    NONSTRICT_TOOL_NAMES,
    SANDBOX_SUFFIXES,
    SDK_VERSION,
    SOURCE_COMMIT,
    SOURCE_TREE,
    ToolBinding,
    ToolConformanceError,
    digest_json,
)

SCENARIO_MANIFEST_SCHEMA = "bluefire.controlled-strix-scenario-manifest.v1"
SCENARIO_PROFILE_SCHEMA = "bluefire.strix-scenario-tool-conformance.v1"
SCENARIO_PROFILE_ID = "strix-root-scenario-chat-completions-6b7ae2e.v1"
SCENARIO_PROVIDER_ID = "controlled-strix-scenario.v1"
SCENARIO_BINDING_SCHEMA = "bluefire.controlled-tenant-record-scenario.v1"
OBSERVATION_REQUEST_SCHEMA = "bluefire.controlled-tool-observation-request.v1"
OBSERVATION_SCHEMA = "bluefire.controlled-tool-observation.v1"
TRACE_SCHEMA = "bluefire.controlled-scenario-trace.v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_IDENTITY = re.compile(r"[a-z][a-z0-9-]{7,63}\Z")
_TOOL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,127}\Z")
_ROUTE_SHAPES = {
    "record_lookup": "/records/{record_id}",
    "bounded_export": "/exports?tenant={tenant_id}",
}
_BRIEF_OBJECTIVE = (
    "Determine whether the authorized starting tenant can obtain generated "
    "records that belong to another tenant."
)
_EVALUATION_TEXT = (
    "BlueFire independently checks target-side audit and returned generated "
    "records; engine claims and controller refusals do not establish success."
)
_PERMITTED_EFFECTS = ("read_generated_records", "observe_public_service_metadata")
_ALLOWED_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "stream",
        "parallel_tool_calls",
        "tool_choice",
        "stream_options",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "seed",
    }
)

# Serving enrollment is intentionally empty until the exact installed Strix
# and OpenAI Agents 0.19 request roster is captured and independently reviewed.
APPROVED_SCENARIO_PROFILE_DIGESTS: frozenset[str] = frozenset()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is invalid")
    return value


def _bounded(value: object, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is invalid")
    return value


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ScenarioRootToolProfile:
    """Exact installed roster with only ``exec_command`` scenario-enabled."""

    tool_bindings: tuple[ToolBinding, ...]
    supported_sandbox_tools: tuple[str, ...]
    unsupported_sandbox_tools: tuple[str, ...]
    strict_tool_schemas: bool
    supports_images: bool
    profile_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ScenarioRootToolProfile:
        expected = {
            "schema_version",
            "profile_id",
            "source_commit",
            "source_tree",
            "sdk_version",
            "provider_id",
            "model_id",
            "is_root",
            "interactive",
            "coverage_tools",
            "chat_completions_tools",
            "strict_tool_schemas",
            "supports_images",
            "tool_roster",
            "supported_sandbox_tools",
            "unsupported_sandbox_tools",
        }
        fixed = {
            "schema_version": SCENARIO_PROFILE_SCHEMA,
            "profile_id": SCENARIO_PROFILE_ID,
            "source_commit": SOURCE_COMMIT,
            "source_tree": SOURCE_TREE,
            "sdk_version": SDK_VERSION,
            "provider_id": SCENARIO_PROVIDER_ID,
            "model_id": DEFAULT_MODEL_ID,
            "is_root": True,
            "interactive": False,
            "coverage_tools": True,
            "chat_completions_tools": True,
            "strict_tool_schemas": True,
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ToolConformanceError("scenario profile fields are invalid")
        if any(
            value.get(name) != item
            or (isinstance(item, bool) and type(value.get(name)) is not bool)
            for name, item in fixed.items()
        ):
            raise ToolConformanceError("scenario profile source identity changed")
        if type(value.get("supports_images")) is not bool:
            raise ToolConformanceError("scenario profile model capabilities are invalid")
        raw_roster = value.get("tool_roster")
        if not isinstance(raw_roster, list) or not 46 <= len(raw_roster) <= 48:
            raise ToolConformanceError("scenario profile tool roster is incomplete")
        bindings: list[ToolBinding] = []
        for raw in raw_roster:
            if not isinstance(raw, Mapping) or set(raw) != {
                "name",
                "parameters_digest",
                "function_digest",
                "strict",
            }:
                raise ToolConformanceError("scenario profile binding is invalid")
            name = raw.get("name")
            strict = raw.get("strict")
            if (
                not isinstance(name, str)
                or _TOOL_NAME.fullmatch(name) is None
                or not isinstance(raw.get("parameters_digest"), str)
                or _DIGEST.fullmatch(raw["parameters_digest"]) is None
                or not isinstance(raw.get("function_digest"), str)
                or _DIGEST.fullmatch(raw["function_digest"]) is None
                or not (
                    strict is True
                    or (name in NONSTRICT_TOOL_NAMES and strict in (False, None))
                )
            ):
                raise ToolConformanceError("scenario profile binding is invalid")
            bindings.append(
                ToolBinding(name, raw["parameters_digest"], raw["function_digest"], strict)
            )
        names = tuple(item.name for item in bindings)
        suffix = names[len(BASE_TOOL_NAMES) + 1 :]
        if (
            names[: len(BASE_TOOL_NAMES)] != BASE_TOOL_NAMES
            or names[len(BASE_TOOL_NAMES)] != "finish_scan"
            or suffix not in SANDBOX_SUFFIXES
            or "exec_command" not in suffix
            or len(names) != len(set(names))
        ):
            raise ToolConformanceError("scenario profile root tool order changed")
        supported = value.get("supported_sandbox_tools")
        unsupported = value.get("unsupported_sandbox_tools")
        if supported != ["exec_command"] or unsupported != [
            name for name in suffix if name != "exec_command"
        ]:
            raise ToolConformanceError("scenario sandbox-tool support differs")
        supports_images = value["supports_images"]
        if supports_images is not ("view_image" in suffix):
            raise ToolConformanceError("scenario image capability and roster disagree")
        try:
            profile_digest = digest_json(value)
        except (RecursionError, TypeError, ValueError) as exc:
            raise ToolConformanceError("scenario profile serialization is invalid") from exc
        return cls(
            tuple(bindings),
            tuple(supported),
            tuple(unsupported),
            True,
            supports_images,
            profile_digest,
        )

    def require_enrolled(self) -> None:
        if self.profile_digest not in APPROVED_SCENARIO_PROFILE_DIGESTS:
            raise ToolConformanceError(
                "installed Strix scenario tool profile is not independently enrolled"
            )

    def check_request_roster(self, value: Any) -> dict[str, Mapping[str, Any]]:
        if not isinstance(value, list) or len(value) != len(self.tool_bindings):
            raise ToolConformanceError("scenario request tool roster differs")
        roster: dict[str, Mapping[str, Any]] = {}
        for supplied, expected in zip(value, self.tool_bindings, strict=True):
            if not isinstance(supplied, Mapping) or set(supplied) != {"type", "function"}:
                raise ToolConformanceError("scenario request tool roster differs")
            function = supplied.get("function")
            expected_fields = (
                {"name", "description", "parameters"}
                if expected.strict is None
                else {"name", "description", "parameters", "strict"}
            )
            if (
                supplied.get("type") != "function"
                or not isinstance(function, Mapping)
                or set(function) != expected_fields
                or function.get("name") != expected.name
                or function.get("strict") is not expected.strict
                or not isinstance(function.get("description"), str)
                or not 1 <= len(function["description"]) <= 32_768
                or not isinstance(function.get("parameters"), Mapping)
            ):
                raise ToolConformanceError("scenario request tool roster differs")
            try:
                parameters_digest = digest_json(function["parameters"])
                function_digest = digest_json(function)
            except (RecursionError, TypeError, ValueError) as exc:
                raise ToolConformanceError("scenario request tool serialization is invalid") from exc
            if (
                parameters_digest != expected.parameters_digest
                or function_digest != expected.function_digest
            ):
                raise ToolConformanceError("scenario request tool schema differs")
            roster[expected.name] = function
        return roster


@dataclass(frozen=True, slots=True)
class TenantRecordScenarioBinding:
    attempt_id: str
    attempt_role: str
    case_ref: str
    experiment_ref: str
    asset_ref: str
    environment_ref: str
    scope_ref: str
    condition_ref: str
    target_snapshot_ref: str
    service_generation: str
    target_origin: str
    authorized_url_set_ref: str
    starting_tenant_id: str
    max_http_calls: int
    max_total_response_bytes: int
    max_runtime_seconds: int
    observation_source_ref: str
    digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TenantRecordScenarioBinding:
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "engine_brief",
            "observation_source_ref",
        } or value.get("schema_version") != SCENARIO_BINDING_SCHEMA:
            raise ControlledProviderError(422, "invalid_manifest", "scenario fields are invalid")
        brief = value.get("engine_brief")
        if not isinstance(brief, Mapping) or set(brief) != {
            "schema_version",
            "case_ref",
            "experiment_ref",
            "attempt_id",
            "attempt_role",
            "objective",
            "asset_ref",
            "environment_ref",
            "scope_ref",
            "condition_ref",
            "target_snapshot_ref",
            "service_generation",
            "starting_identity",
            "target_origin",
            "authorized_url_set_ref",
            "discovery",
            "delegation",
            "success_evaluation",
        } or brief.get("schema_version") != "bluefire.tenant-record-engine-brief.v1":
            raise ControlledProviderError(422, "invalid_manifest", "engine brief is invalid")
        attempt_id = brief.get("attempt_id")
        role = brief.get("attempt_role")
        if (
            not isinstance(attempt_id, str)
            or _ATTEMPT.fullmatch(attempt_id) is None
            or role not in {"baseline", "adaptive_search"}
            or brief.get("objective") != _BRIEF_OBJECTIVE
            or brief.get("success_evaluation") != _EVALUATION_TEXT
        ):
            raise ControlledProviderError(422, "invalid_manifest", "engine brief identity differs")
        origin = cls._origin(brief.get("target_origin"), attempt_id)
        starting = brief.get("starting_identity")
        if not isinstance(starting, Mapping) or set(starting) != {"kind", "tenant_id"} or starting.get("kind") != "tenant":
            raise ControlledProviderError(422, "invalid_manifest", "starting identity is invalid")
        tenant = _identity(starting.get("tenant_id"), "starting tenant")
        discovery = brief.get("discovery")
        if not isinstance(discovery, Mapping) or dict(discovery) != {
            "method": "GET",
            "target": origin + "/openapi.json",
        }:
            raise ControlledProviderError(422, "invalid_manifest", "discovery route differs")
        delegation = brief.get("delegation")
        if not isinstance(delegation, Mapping) or set(delegation) != {
            "permitted_effects",
            "target_assets",
            "identities",
            "isolation",
            "max_http_calls",
            "max_total_response_bytes",
            "max_runtime_seconds",
        }:
            raise ControlledProviderError(422, "invalid_manifest", "delegation fields differ")
        asset_ref = _digest(brief.get("asset_ref"), "asset reference")
        if (
            delegation.get("permitted_effects") != list(_PERMITTED_EFFECTS)
            or delegation.get("target_assets") != [asset_ref]
            or delegation.get("identities") != [tenant]
            or delegation.get("isolation") != "owned_disposable_tenant_lab"
        ):
            raise ControlledProviderError(422, "invalid_manifest", "delegation scope differs")
        try:
            canonical = _canonical(value)
        except (RecursionError, TypeError, ValueError) as exc:
            raise ControlledProviderError(422, "invalid_manifest", "scenario is invalid") from exc
        return cls(
            attempt_id=attempt_id,
            attempt_role=role,
            case_ref=_digest(brief.get("case_ref"), "case reference"),
            experiment_ref=_digest(brief.get("experiment_ref"), "experiment reference"),
            asset_ref=asset_ref,
            environment_ref=_digest(brief.get("environment_ref"), "environment reference"),
            scope_ref=_digest(brief.get("scope_ref"), "scope reference"),
            condition_ref=_digest(brief.get("condition_ref"), "condition reference"),
            target_snapshot_ref=_digest(brief.get("target_snapshot_ref"), "target snapshot reference"),
            service_generation=_identity(brief.get("service_generation"), "service generation"),
            target_origin=origin,
            authorized_url_set_ref=_digest(
                brief.get("authorized_url_set_ref"), "authorized URL-set reference"
            ),
            starting_tenant_id=tenant,
            max_http_calls=_bounded(delegation.get("max_http_calls"), 3, 32, "HTTP budget"),
            max_total_response_bytes=_bounded(
                delegation.get("max_total_response_bytes"), 1, 32 * 65_536, "byte budget"
            ),
            max_runtime_seconds=_bounded(
                delegation.get("max_runtime_seconds"), 1, 900, "runtime budget"
            ),
            observation_source_ref=_digest(
                value.get("observation_source_ref"), "observation-source reference"
            ),
            digest=_sha256(canonical),
        )

    @staticmethod
    def _origin(value: object, attempt_id: str) -> str:
        if not isinstance(value, str) or not value.isascii() or len(value) > 256:
            raise ControlledProviderError(422, "invalid_manifest", "target origin is invalid")
        parsed = urlsplit(value)
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError as exc:
            raise ControlledProviderError(422, "invalid_manifest", "target origin is invalid") from exc
        if (
            parsed.scheme != "http"
            or host != f"bf-target-{attempt_id.removeprefix('engine-attempt-')}"
            or port != 8080
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ControlledProviderError(422, "invalid_manifest", "target origin is invalid")
        normalized = f"http://{host}:8080"
        if value != normalized:
            raise ControlledProviderError(422, "invalid_manifest", "target origin is invalid")
        return normalized


@dataclass(frozen=True, slots=True, kw_only=True)
class ControlledScenarioManifest(ControlledProviderManifest):
    scenario: TenantRecordScenarioBinding

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ControlledScenarioManifest:
        expected = {
            "schema_version",
            "attempt_id",
            "model_id",
            "profile",
            "max_requests",
            "max_request_bytes",
            "max_response_bytes",
            "max_messages",
            "max_tools",
            "max_schema_depth",
            "max_input_tokens",
            "max_output_tokens",
            "max_total_tokens",
            "scenario",
        }
        if not isinstance(value, Mapping) or set(value) != expected or value.get("schema_version") != SCENARIO_MANIFEST_SCHEMA:
            raise ControlledProviderError(422, "invalid_manifest", "scenario manifest fields differ")
        scenario = TenantRecordScenarioBinding.from_mapping(value["scenario"])
        if value.get("attempt_id") != scenario.attempt_id or value.get("model_id") != DEFAULT_MODEL_ID:
            raise ControlledProviderError(422, "invalid_manifest", "scenario attempt or model differs")
        try:
            profile = ScenarioRootToolProfile.from_mapping(value["profile"])
            canonical = _canonical(value)
        except ToolConformanceError as exc:
            raise ControlledProviderError(422, "invalid_profile", str(exc)) from exc
        except (RecursionError, TypeError, ValueError) as exc:
            raise ControlledProviderError(422, "invalid_manifest", "scenario manifest is invalid") from exc
        return cls(
            attempt_id=scenario.attempt_id,
            model_id=DEFAULT_MODEL_ID,
            profile=profile,  # type: ignore[arg-type]
            max_requests=_bounded(value["max_requests"], 4, 4, "request limit"),
            max_request_bytes=_bounded(value["max_request_bytes"], 1_024, 131_072, "request bytes"),
            max_response_bytes=_bounded(value["max_response_bytes"], 1_024, 65_536, "response bytes"),
            max_messages=_bounded(value["max_messages"], 3, 64, "message limit"),
            max_tools=_bounded(value["max_tools"], len(profile.tool_bindings), len(profile.tool_bindings), "tool limit"),
            max_schema_depth=_bounded(value["max_schema_depth"], 1, 32, "schema depth"),
            max_input_tokens=_bounded(value["max_input_tokens"], 1, 32_768, "input tokens"),
            max_output_tokens=_bounded(value["max_output_tokens"], 1, 8_192, "output tokens"),
            max_total_tokens=_bounded(value["max_total_tokens"], 2, 40_960, "total tokens"),
            phases=(),
            digest=_sha256(canonical),
            target_inspection_seed=None,
            scenario=scenario,
        )


@dataclass(frozen=True, slots=True)
class ScenarioObservationRequest:
    attempt_id: str
    scenario_ref: str
    phase_id: str
    call_id: str
    tool_name: str
    arguments_digest: str
    model_result_digest: str
    model_result_bytes: int
    model_result: str

    @property
    def digest(self) -> str:
        return _sha256(
            _canonical(
                {
                    "schema_version": OBSERVATION_REQUEST_SCHEMA,
                    "attempt_id": self.attempt_id,
                    "scenario_ref": self.scenario_ref,
                    "phase_id": self.phase_id,
                    "call_id": self.call_id,
                    "tool_name": self.tool_name,
                    "arguments_digest": self.arguments_digest,
                    "model_result_digest": self.model_result_digest,
                    "model_result_bytes": self.model_result_bytes,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class VerifiedScenarioObservation:
    request_ref: str
    attempt_id: str
    scenario_ref: str
    phase_id: str
    call_id: str
    tool_name: str
    arguments_digest: str
    model_result_digest: str
    model_result_bytes: int
    execution_admission_ref: str
    dispatch_ref: str
    attachment_ref: str
    terminal_ref: str
    target_response_ref: str
    target_snapshot_ref: str
    service_generation: str
    target_request_id: str
    target_audit_ref: str
    target_route: str
    kind: str
    status_code: int
    routes: tuple[tuple[str, str], ...] = ()
    starting_tenant_id: str | None = None
    own_record_ids: tuple[str, ...] = ()
    known_tenants: tuple[str, ...] = ()
    record_directory: tuple[str, ...] = ()
    returned_record_ids: tuple[str, ...] = ()

    @property
    def observation_ref(self) -> str:
        return _sha256(_canonical({
            "schema_version": OBSERVATION_SCHEMA,
            "request_ref": self.request_ref,
            "attempt_id": self.attempt_id,
            "scenario_ref": self.scenario_ref,
            "phase_id": self.phase_id,
            "call_id": self.call_id,
            "tool_name": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "model_result_digest": self.model_result_digest,
            "model_result_bytes": self.model_result_bytes,
            "execution_admission_ref": self.execution_admission_ref,
            "dispatch_ref": self.dispatch_ref,
            "attachment_ref": self.attachment_ref,
            "terminal_ref": self.terminal_ref,
            "target_response_ref": self.target_response_ref,
            "target_snapshot_ref": self.target_snapshot_ref,
            "service_generation": self.service_generation,
            "target_request_id": self.target_request_id,
            "target_audit_ref": self.target_audit_ref,
            "target_route": self.target_route,
            "kind": self.kind,
            "status_code": self.status_code,
            "routes": [list(item) for item in self.routes],
            "starting_tenant_id": self.starting_tenant_id,
            "own_record_ids": list(self.own_record_ids),
            "known_tenants": list(self.known_tenants),
            "record_directory": list(self.record_directory),
            "returned_record_ids": list(self.returned_record_ids),
        }))

    def validate_for(self, request: ScenarioObservationRequest) -> None:
        for value in (
            self.request_ref,
            self.scenario_ref,
            self.arguments_digest,
            self.model_result_digest,
            self.execution_admission_ref,
            self.dispatch_ref,
            self.attachment_ref,
            self.terminal_ref,
            self.target_response_ref,
            self.target_snapshot_ref,
            self.target_audit_ref,
        ):
            _digest(value, "observation reference")
        if (
            self.request_ref != request.digest
            or self.attempt_id != request.attempt_id
            or self.scenario_ref != request.scenario_ref
            or self.phase_id != request.phase_id
            or self.call_id != request.call_id
            or self.tool_name != request.tool_name
            or self.arguments_digest != request.arguments_digest
            or self.model_result_digest != request.model_result_digest
            or self.model_result_bytes != request.model_result_bytes
            or type(self.status_code) is not int
            or not 100 <= self.status_code <= 599
            or _IDENTITY.fullmatch(self.service_generation) is None
            or re.fullmatch(r"request-[0-9a-f]{24}", self.target_request_id) is None
            or self.target_route not in {"metadata", *_ROUTE_SHAPES}
        ):
            raise ControlledProviderError(409, "observation_unverified", "tool observation differs")
        if self.kind == "discovery":
            if (
                self.status_code != 200
                or self.target_route != "metadata"
                or tuple(self.routes) not in (
                    (("record_lookup", _ROUTE_SHAPES["record_lookup"]), ("bounded_export", _ROUTE_SHAPES["bounded_export"])),
                    (("bounded_export", _ROUTE_SHAPES["bounded_export"]), ("record_lookup", _ROUTE_SHAPES["record_lookup"])),
                )
                or self.starting_tenant_id is None
                or _IDENTITY.fullmatch(self.starting_tenant_id) is None
                or not 1 <= len(self.own_record_ids) <= 16
                or not 2 <= len(self.known_tenants) <= 16
                or not 2 <= len(self.record_directory) <= 32
                or len(set(self.own_record_ids)) != len(self.own_record_ids)
                or len(set(self.known_tenants)) != len(self.known_tenants)
                or len(set(self.record_directory)) != len(self.record_directory)
                or any(_IDENTITY.fullmatch(item) is None for item in (*self.own_record_ids, *self.known_tenants, *self.record_directory))
                or not set(self.own_record_ids) < set(self.record_directory)
                or self.starting_tenant_id not in self.known_tenants
                or self.returned_record_ids
            ):
                raise ControlledProviderError(409, "observation_unverified", "discovery observation differs")
        elif self.kind == "target_response":
            if (
                self.target_route == "metadata"
                or self.routes
                or self.starting_tenant_id is not None
                or self.own_record_ids
                or self.known_tenants
                or self.record_directory
                or len(self.returned_record_ids) > 16
                or len(set(self.returned_record_ids)) != len(self.returned_record_ids)
                or any(_IDENTITY.fullmatch(item) is None for item in self.returned_record_ids)
                or (self.returned_record_ids and not 200 <= self.status_code < 300)
            ):
                raise ControlledProviderError(409, "observation_unverified", "target observation differs")
        else:
            raise ControlledProviderError(409, "observation_unverified", "observation kind differs")


@runtime_checkable
class ScenarioObservationSource(Protocol):
    @property
    def binding_ref(self) -> str: ...

    def verify(self, request: ScenarioObservationRequest) -> VerifiedScenarioObservation: ...


@dataclass(frozen=True, slots=True)
class _ScenarioCall:
    phase_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    route_name: str | None = None


@dataclass(frozen=True, slots=True)
class ControlledScenarioTrace:
    attempt_id: str
    scenario_ref: str
    manifest_ref: str
    profile_ref: str
    status: str
    provider_requests: int
    completed_observation_refs: tuple[str, ...]
    attempted_routes: tuple[str, ...]
    last_target_status: int | None
    fixture_usage_estimate: bool = True
    live_model_proof: bool = False

    @property
    def trace_ref(self) -> str:
        return _sha256(_canonical({
            "schema_version": TRACE_SCHEMA,
            "attempt_id": self.attempt_id,
            "scenario_ref": self.scenario_ref,
            "manifest_ref": self.manifest_ref,
            "profile_ref": self.profile_ref,
            "status": self.status,
            "provider_requests": self.provider_requests,
            "completed_observation_refs": list(self.completed_observation_refs),
            "attempted_routes": list(self.attempted_routes),
            "last_target_status": self.last_target_status,
            "fixture_usage_estimate": self.fixture_usage_estimate,
            "live_model_proof": self.live_model_proof,
        }))


class ControlledScenarioProviderState(ControlledProviderState):
    """One attempt-local observation-gated deterministic Strix dialogue."""

    def __init__(
        self,
        manifest: ControlledScenarioManifest,
        bearer_token: str,
        *,
        observation_source: ScenarioObservationSource,
        audit_path: Path | None = None,
        sequence_offset: int = 0,
    ) -> None:
        if type(manifest) is not ControlledScenarioManifest:
            raise ValueError("scenario manifest is invalid")
        if not isinstance(observation_source, ScenarioObservationSource) or observation_source.binding_ref != manifest.scenario.observation_source_ref:
            raise ValueError("scenario observation source differs")
        super().__init__(
            manifest,
            bearer_token,
            audit_path=audit_path,
            sequence_offset=sequence_offset,
        )
        self.manifest = manifest
        self._observation_source = observation_source
        self._scenario_generation = 0
        self._verification_sequence: int | None = None
        self._unknown = False
        self._pending_tool_name: str | None = None
        self._pending_arguments_json: str | None = None
        self._pending_route: str | None = None
        self._discovery: VerifiedScenarioObservation | None = None
        self._attempted_routes: tuple[str, ...] = ()
        self._last_target_status: int | None = None
        self._observation_refs: tuple[str, ...] = ()
        self._target_request_ids: tuple[str, ...] = ()

    def trace(self) -> ControlledScenarioTrace:
        with self._lock:
            status = (
                "cancelled" if self._cancelled else
                "unknown" if self._unknown else
                "finishing" if self._pending_phase_id == "finish" else
                "running"
            )
            return ControlledScenarioTrace(
                self.manifest.attempt_id,
                self.manifest.scenario.digest,
                self.manifest.digest,
                self.manifest.profile.profile_digest,
                status,
                self._request_count,
                self._observation_refs,
                self._attempted_routes,
                self._last_target_status,
            )

    def respond(self, body: bytes) -> bytes:
        observation_request: ScenarioObservationRequest | None = None
        with self._lock:
            if self._cancelled:
                raise ControlledProviderError(409, "attempt_cancelled", "attempt is cancelled")
            if self._unknown:
                raise ControlledProviderError(409, "observation_unknown", "tool observation is unresolved")
            if self._verification_sequence is not None:
                raise ControlledProviderError(409, "verification_in_progress", "tool observation is being verified")
            if len(body) > self.manifest.max_request_bytes:
                raise ControlledProviderError(413, "request_too_large", "request exceeds its limit")
            if self._request_count >= self.manifest.max_requests:
                raise ControlledProviderError(429, "request_limit", "request limit reached")
            self._request_count += 1
            sequence = self._request_count + self._sequence_offset
            try:
                request = self._parse_request(sequence, body)
                messages = request["messages"]
                observation_request = self._observation_request(messages)
            except Exception:
                if self._pending_call_id is not None:
                    self._unknown = True
                raise
            generation = self._scenario_generation
            if observation_request is not None:
                self._verification_sequence = sequence

        observation: VerifiedScenarioObservation | None = None
        if observation_request is not None:
            try:
                observation = self._observation_source.verify(observation_request)
                if type(observation) is not VerifiedScenarioObservation:
                    raise ControlledProviderError(409, "observation_unverified", "tool observation is unverified")
                observation.validate_for(observation_request)
            except ControlledProviderError:
                with self._lock:
                    self._unknown = True
                    self._verification_sequence = None
                self._audit_error(sequence, body, "observation_unverified")
                raise
            except Exception:
                with self._lock:
                    self._unknown = True
                    self._verification_sequence = None
                self._audit_error(sequence, body, "observation_unverified")
                raise ControlledProviderError(409, "observation_unverified", "tool observation is unverified") from None

        with self._lock:
            if (
                self._cancelled
                or self._unknown
                or self._scenario_generation != generation
                or self._verification_sequence not in (None, sequence)
            ):
                self._verification_sequence = None
                raise ControlledProviderError(409, "attempt_changed", "scenario changed during verification")
            self._verification_sequence = None
            # Once a verified effect exists, any later roster/schema/audit
            # failure leaves this attempt terminally unknown rather than
            # allowing the SDK to repeat a mutation under an unchanged call.
            if observation is not None:
                self._unknown = True
                if (
                    observation.target_snapshot_ref != self.manifest.scenario.target_snapshot_ref
                    or observation.service_generation != self.manifest.scenario.service_generation
                    or observation.target_request_id in self._target_request_ids
                    or (
                        self._pending_phase_id == "discover_target"
                        and observation.target_route != "metadata"
                    )
                    or (
                        self._pending_phase_id != "discover_target"
                        and observation.target_route != self._pending_route
                    )
                ):
                    raise ControlledProviderError(
                        409, "observation_unverified", "target event differs"
                    )
            tools = self._tool_roster(request["tools"])
            call, completed_ids = self._next_call(messages, observation)
            tool = tools.get(call.tool_name)
            if tool is None:
                raise ControlledProviderError(422, "missing_required_tool", "required tool is unavailable")
            schema = tool["parameters"]
            _schema_depth(schema, limit=self.manifest.max_schema_depth)
            _validate_schema_value(call.arguments, schema, depth=0, limit=self.manifest.max_schema_depth)
            self._validate_tool_choice(request.get("tool_choice"), call.tool_name)
            arguments_json = _canonical(call.arguments).decode("ascii")
            call_id = f"call_{sequence:04d}_{hashlib.sha256((self.manifest.attempt_id + call.phase_id).encode()).hexdigest()[:16]}"
            response = self._sse_response(
                sequence=sequence,
                call_id=call_id,
                tool_name=call.tool_name,
                arguments=arguments_json,
                include_usage=self._include_usage(request.get("stream_options")),
                prompt_bytes=len(body),
            )
            if len(response) > self.manifest.max_response_bytes:
                raise ControlledProviderError(413, "response_too_large", "response exceeds its limit")
            audit = self._base_audit(sequence, body, request, tools)
            audit.update(
                {
                    "schema_version": "bluefire.controlled-scenario-turn.v1",
                    "scenario_ref": self.manifest.scenario.digest,
                    "provider_id": SCENARIO_PROVIDER_ID,
                    "status": "tool_call",
                    "phase_id": call.phase_id,
                    "emitted_call_id": call_id,
                    "tool_name": call.tool_name,
                    "arguments_digest": _sha256(arguments_json.encode("ascii")),
                    "route_name": call.route_name,
                    "observation": self._observation_audit(observation),
                    "fixture_usage_estimate": True,
                    "live_model_proof": False,
                    "response_byte_hash": _sha256(response),
                    "response_byte_size": len(response),
                }
            )
            self._append_audit(audit)
            if observation is not None:
                self._apply_observation(observation)
                self._unknown = False
            self._scenario_generation += 1
            self._phase_index += 1
            self._pending_call_id = call_id
            self._pending_phase_id = call.phase_id
            self._pending_tool_name = call.tool_name
            self._pending_arguments_json = arguments_json
            self._pending_route = call.route_name
            self._completed_call_ids = completed_ids
            return response

    def _parse_request(self, sequence: int, body: bytes) -> Mapping[str, Any]:
        try:
            request = json.loads(body, parse_constant=_reject_nonfinite, object_pairs_hook=_strict_object)
            _schema_depth(request, limit=128)
        except ControlledProviderError as exc:
            self._audit_error(sequence, body, exc.code)
            raise
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            self._audit_error(sequence, body, "invalid_json")
            raise ControlledProviderError(400, "invalid_json", "request body is invalid") from exc
        if (
            not isinstance(request, Mapping)
            or set(request) - _ALLOWED_REQUEST_FIELDS
            or not {"model", "messages", "tools", "stream"} <= set(request)
            or request.get("model") != self.manifest.model_id
            or request.get("stream") is not True
            or request.get("parallel_tool_calls") is not False
        ):
            raise ControlledProviderError(400, "unsupported_request", "request shape is unsupported")
        self._validate_tuning(request)
        messages = request.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= self.manifest.max_messages:
            raise ControlledProviderError(422, "invalid_messages", "message history is invalid")
        self._validate_messages(messages)
        return request

    def _observation_request(self, messages: Sequence[Any]) -> ScenarioObservationRequest | None:
        tool_messages = [item for item in messages if isinstance(item, Mapping) and item.get("role") == "tool"]
        expected = list(self._completed_call_ids)
        if self._pending_call_id is not None:
            expected.append(self._pending_call_id)
        if [item.get("tool_call_id") for item in tool_messages] != expected:
            raise ControlledProviderError(409, "unexpected_history", "tool result history is invalid")
        if self._pending_call_id is None:
            return None
        matches = [item for item in tool_messages if item.get("tool_call_id") == self._pending_call_id]
        if len(matches) != 1 or messages[-1] is not matches[0] or len(messages) < 2 or not self._matches_pending_assistant_call(messages[-2]):
            raise ControlledProviderError(409, "unexpected_history", "tool result pairing differs")
        content = matches[0].get("content")
        if not isinstance(content, str) or not content or len(content.encode("utf-8")) > self.manifest.max_response_bytes:
            raise ControlledProviderError(409, "unexpected_history", "tool result content is invalid")
        assert self._pending_phase_id and self._pending_tool_name and self._pending_arguments_json
        return ScenarioObservationRequest(
            attempt_id=self.manifest.attempt_id,
            scenario_ref=self.manifest.scenario.digest,
            phase_id=self._pending_phase_id,
            call_id=self._pending_call_id,
            tool_name=self._pending_tool_name,
            arguments_digest=_sha256(self._pending_arguments_json.encode("ascii")),
            model_result_digest=_sha256(content.encode("utf-8")),
            model_result_bytes=len(content.encode("utf-8")),
            model_result=content,
        )

    def _matches_pending_assistant_call(self, message: Any) -> bool:
        if not isinstance(message, Mapping) or message.get("role") != "assistant":
            return False
        calls = message.get("tool_calls")
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], Mapping):
            return False
        call = calls[0]
        function = call.get("function")
        return (
            set(call) == {"id", "type", "function"}
            and call.get("id") == self._pending_call_id
            and call.get("type") == "function"
            and isinstance(function, Mapping)
            and set(function) == {"name", "arguments"}
            and function.get("name") == self._pending_tool_name
            and function.get("arguments") == self._pending_arguments_json
        )

    def _next_call(
        self,
        messages: Sequence[Any],
        observation: VerifiedScenarioObservation | None,
    ) -> tuple[_ScenarioCall, tuple[str, ...]]:
        completed = self._completed_call_ids
        if self._pending_call_id is not None:
            if observation is None:
                raise ControlledProviderError(409, "observation_unverified", "tool observation is missing")
            completed = (*completed, self._pending_call_id)
        if self._pending_call_id is None:
            return self._discovery_call(), completed
        assert observation is not None
        if self._pending_phase_id == "discover_target":
            if observation.kind != "discovery" or observation.starting_tenant_id != self.manifest.scenario.starting_tenant_id:
                raise ControlledProviderError(409, "observation_unverified", "discovery identity differs")
            return self._effect_call(observation, observation.routes[0][0]), completed
        if self._pending_phase_id and self._pending_phase_id.startswith("try_"):
            if observation.kind != "target_response":
                raise ControlledProviderError(409, "observation_unverified", "target response is missing")
            attempted = (*self._attempted_routes, self._pending_route) if self._pending_route else self._attempted_routes
            if self._discovery is not None and not set(observation.returned_record_ids) - set(self._discovery.own_record_ids):
                remaining = [name for name, _shape in self._discovery.routes if name not in attempted]
                if remaining:
                    return self._effect_call(self._discovery, remaining[0]), completed
            return self._finish_call(observation.status_code, attempted), completed
        raise ControlledProviderError(409, "unexpected_history", "scenario phase differs")

    def _discovery_call(self) -> _ScenarioCall:
        url = self.manifest.scenario.target_origin + "/openapi.json"
        command = f"curl --silent --show-error --include --max-time 5 {shlex.quote(url)}"
        return _ScenarioCall("discover_target", "exec_command", {"cmd": command, "yield_time_ms": 5000})

    def _effect_call(self, discovery: VerifiedScenarioObservation, route: str) -> _ScenarioCall:
        other_tenants = [item for item in discovery.known_tenants if item != discovery.starting_tenant_id]
        foreign_records = [item for item in discovery.record_directory if item not in discovery.own_record_ids]
        if len(other_tenants) != 1 or not foreign_records or route not in _ROUTE_SHAPES:
            raise ControlledProviderError(409, "observation_unverified", "discovery cannot select a bounded route")
        other = other_tenants[0]
        if route == "record_lookup":
            url = self.manifest.scenario.target_origin + "/records/" + foreign_records[0]
        else:
            url = self.manifest.scenario.target_origin + "/exports?tenant=" + other
        command = (
            "curl --silent --show-error --include --max-time 5 "
            + "--header "
            + shlex.quote("x-bluefire-lab-tenant: " + other)
            + " "
            + shlex.quote(url)
        )
        phase = "try_" + route
        return _ScenarioCall(phase, "exec_command", {"cmd": command, "yield_time_ms": 5000}, route)

    def _finish_call(self, status: int, attempted: Sequence[str]) -> _ScenarioCall:
        routes = ", ".join(attempted) if attempted else "none"
        arguments = {
            "executive_summary": "Deterministic Test-provider mechanics completed; independent BlueFire evidence determines the security outcome.",
            "methodology": f"The installed engine inspected generated target metadata and attempted these advertised routes: {routes}.",
            "technical_analysis": f"The final target response status was {status}. This fixture result is not live-model judgment and is not proof that other paths do or do not exist.",
            "recommendations": "Review controller-owned target observations, the defensive change, original replay, adaptive attempt and legitimate-use result separately.",
        }
        return _ScenarioCall("finish", "finish_scan", arguments)

    def _apply_observation(self, observation: VerifiedScenarioObservation) -> None:
        self._observation_refs = (*self._observation_refs, observation.observation_ref)
        self._target_request_ids = (*self._target_request_ids, observation.target_request_id)
        if observation.kind == "discovery":
            self._discovery = observation
        else:
            self._last_target_status = observation.status_code
            if self._pending_route is not None:
                self._attempted_routes = (*self._attempted_routes, self._pending_route)

    @staticmethod
    def _observation_audit(
        observation: VerifiedScenarioObservation | None,
    ) -> Mapping[str, Any] | None:
        if observation is None:
            return None
        return {
            "observation_ref": observation.observation_ref,
            "request_ref": observation.request_ref,
            "model_result_digest": observation.model_result_digest,
            "model_result_bytes": observation.model_result_bytes,
            "execution_admission_ref": observation.execution_admission_ref,
            "dispatch_ref": observation.dispatch_ref,
            "attachment_ref": observation.attachment_ref,
            "terminal_ref": observation.terminal_ref,
            "target_response_ref": observation.target_response_ref,
            "target_snapshot_ref": observation.target_snapshot_ref,
            "service_generation": observation.service_generation,
            "target_request_id": observation.target_request_id,
            "target_audit_ref": observation.target_audit_ref,
            "target_route": observation.target_route,
            "kind": observation.kind,
            "status_code": observation.status_code,
            "returned_record_ids": list(observation.returned_record_ids),
        }


__all__ = [
    "APPROVED_SCENARIO_PROFILE_DIGESTS",
    "ControlledScenarioManifest",
    "ControlledScenarioProviderState",
    "ControlledScenarioTrace",
    "ScenarioObservationRequest",
    "ScenarioObservationSource",
    "ScenarioRootToolProfile",
    "TenantRecordScenarioBinding",
    "TRACE_SCHEMA",
    "VerifiedScenarioObservation",
]

"""Capability IO contracts.

Each :class:`BaseModule` declares the **kinds** of artifacts it consumes
and produces using the :data:`ArtifactType` vocabulary defined here, plus
optional :class:`ArtifactSpec` rows that describe a specific artifact in
operator-facing terms (key, optional/required, what it represents).

The vocabulary is intentionally small. It is the narrowest set of types
the chain runtime, scenario planner, AI orchestrator, and report views
need to answer questions like:

- "Given the artifacts produced so far, which modules can consume them?"
- "If the operator picks ``lateral_movement`` next, which prior step's
  output should feed its ``target`` slot?"
- "Did this scenario actually emit a credential before its
  credential-using step ran, or is it a paper chain?"

The contracts are advisory metadata, not a runtime schema. Modules can
still produce additional ad-hoc keys in their ``artifacts`` dict; the
contract only documents the well-typed slots that the chaining engine
and downstream surfaces should know about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Iterable, Mapping, Optional, Tuple


# -- Artifact-type vocabulary --------------------------------------------------
#
# Keep this list small. Each entry must describe a *kind of thing* the
# chain runtime needs to reason about — not a per-technique flavour.
#
# Aliases below allow tactically-named variants (e.g. ``credentials`` /
# ``creds`` / ``token``) to normalise into the canonical type.

#: A reachable host (IP, FQDN, or ``lab-host``-style placeholder).
HOST: Final[str] = "host"

#: A user account (``DOMAIN\\user``, ``user@example.invalid``, ``lab-user``).
USER: Final[str] = "user"

#: A captured credential (password, hash, ticket evidence). Distinct from
#: ``token`` because credential discovery and credential-token forging are
#: separate ATT&CK surfaces.
CREDENTIAL: Final[str] = "credential"

#: A live-session token, ticket, or cookie. Pairs naturally with
#: ``credential_access`` (which forges/extracts) and ``lateral_movement``
#: (which presents the token).
TOKEN: Final[str] = "token"

#: A network share, mount, or remote filesystem entry-point.
SHARE: Final[str] = "share"

#: A local or remote OS service or daemon.
SERVICE: Final[str] = "service"

#: A file on disk, including planted/dropped binaries.
FILE: Final[str] = "file"

#: A file that has been copied into a staging path for collection or
#: exfiltration. Distinct from ``file`` because the chain semantic is
#: "this is the thing to pick up next", not "this exists on disk".
STAGED_FILE: Final[str] = "staged_file"

#: An aggregated set of records the operator has collected (browser
#: history, screen captures, keystrokes, ...). Pairs naturally with
#: ``exfiltration``.
COLLECTED_DATA: Final[str] = "collected_data"

#: A bundle ready for outbound transfer (compressed archive, single
#: blob, batched objects). The exfiltration consumer.
EXFIL_PACKAGE: Final[str] = "exfil_package"

#: A C2 channel endpoint (URL, FQDN, IP:port, mailbox, queue).
C2_ENDPOINT: Final[str] = "c2_endpoint"

#: A live OS process (PID + image). Pairs with ``execution`` ->
#: ``persistence`` and ``execution`` -> ``defense_evasion`` chains.
PROCESS: Final[str] = "process"

#: A persistence anchor (registry key, scheduled task name, service
#: name, launch agent path, cron entry, etc.). Pairs naturally with
#: ``defense_evasion`` (hide / cover the marker) and reporting.
PERSISTENCE_MARKER: Final[str] = "persistence_marker"

#: A target of impact (host, service, dataset, share). Pairs with
#: ``collection`` -> ``impact`` (encrypt the staged data) and
#: ``discovery`` -> ``impact`` (target the discovered host).
IMPACT_TARGET: Final[str] = "impact_target"

#: A discovery result row (host, share, service, user enumeration).
#: Modelled as a distinct type so a scenario planner can ask "what
#: was discovered?" without inspecting per-tactic shapes.
DISCOVERY_RESULT: Final[str] = "discovery_result"

#: Defender-side context emitted to inform reporting / detection
#: drafts (logsource hint, datamodel hint, telemetry channel hint).
#: Pairs with the report builder rather than another offensive stage.
DETECTION_CONTEXT: Final[str] = "detection_context"


#: The canonical artifact-type vocabulary. Module declarations must
#: reference one of these strings.
ARTIFACT_TYPES: Final[Tuple[str, ...]] = (
    HOST,
    USER,
    CREDENTIAL,
    TOKEN,
    SHARE,
    SERVICE,
    FILE,
    STAGED_FILE,
    COLLECTED_DATA,
    EXFIL_PACKAGE,
    C2_ENDPOINT,
    PROCESS,
    PERSISTENCE_MARKER,
    IMPACT_TARGET,
    DISCOVERY_RESULT,
    DETECTION_CONTEXT,
)


# Common typo / synonym -> canonical type. Kept tiny on purpose; the
# point is to catch obvious mismatches in module declarations, not to
# accept any operator-facing label.
_ARTIFACT_TYPE_ALIASES: Final[Mapping[str, str]] = {
    "credentials": CREDENTIAL,
    "creds": CREDENTIAL,
    "tokens": TOKEN,
    "session_token": TOKEN,
    "hosts": HOST,
    "target_host": HOST,
    "users": USER,
    "shares": SHARE,
    "services": SERVICE,
    "files": FILE,
    "staged_files": STAGED_FILE,
    "exfil_bundle": EXFIL_PACKAGE,
    "c2_channel": C2_ENDPOINT,
    "c2_endpoints": C2_ENDPOINT,
    "processes": PROCESS,
    "persistence": PERSISTENCE_MARKER,
    "persistence_anchor": PERSISTENCE_MARKER,
    "impact_targets": IMPACT_TARGET,
    "discovery_results": DISCOVERY_RESULT,
}


def normalise_artifact_type(value: str) -> str:
    """Return the canonical artifact-type token, raising on unknown values."""

    raw = (value or "").strip().lower()
    if raw in ARTIFACT_TYPES:
        return raw
    if raw in _ARTIFACT_TYPE_ALIASES:
        return _ARTIFACT_TYPE_ALIASES[raw]
    raise ValueError(
        f"Unknown artifact type {value!r}; expected one of {ARTIFACT_TYPES}"
    )


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    """A single typed slot in a module's IO contract.

    ``key`` is the name the module uses inside its ``artifacts`` dict
    (or, for consumed slots, the parameter the module looks up).

    ``required`` is advisory: ``True`` for slots the module cannot do
    useful work without; ``False`` for optional slots (e.g. a
    ``source_host`` that defaults to ``lab-attacker`` when absent).

    ``produced_if`` is an optional ``(discriminator_key, expected_value)``
    predicate that gates whether this spec applies for a given run. It
    exists for modules where multiple distinct artifact types share a
    single ``key`` in the runtime artifacts dict — most notably
    ``DiscoveryModule``, where ``targets`` is a single list whose items
    are hosts / services / shares / users / files / impact_targets
    depending on ``discovery_type``. Without this gate, a single
    ``targets`` value would be indexed under every declared type,
    misleading downstream chain consumers about what was actually
    enumerated.

    The predicate is matched by ``ChainContext.record_step`` as
    ``run_artifacts.get(discriminator_key) == expected_value``. The
    expected value can be a single string or a tuple of strings (any
    match wins). When ``produced_if`` is ``None`` the spec is always
    applicable for the spec's key.
    """

    type: str
    key: str = ""
    description: str = ""
    required: bool = True
    produced_if: Optional[Tuple[str, "ProducedIfValue"]] = None

    def __post_init__(self) -> None:
        normalised = normalise_artifact_type(self.type)
        if normalised != self.type:
            object.__setattr__(self, "type", normalised)


# Allowed shape for the second element of ``produced_if``: a single
# value, or a tuple/frozenset of acceptable values (any-match wins).
ProducedIfValue = "str | int | float | bool | tuple | frozenset"


@dataclass(frozen=True, slots=True)
class CapabilityIOContract:
    """Module-level capability IO declaration.

    A module either declares a meaningful contract (``produces`` or
    ``consumes`` non-empty) OR explicitly opts out via
    ``not_applicable=True``. Declaring an empty contract without the
    opt-out is treated as a missing declaration by
    :func:`is_meaningful_contract`.

    ``not_applicable_reason`` is mandatory whenever ``not_applicable``
    is set, so the metadata is self-documenting in the registry.
    """

    produces: Tuple[ArtifactSpec, ...] = field(default_factory=tuple)
    consumes: Tuple[ArtifactSpec, ...] = field(default_factory=tuple)
    not_applicable: bool = False
    not_applicable_reason: str = ""

    def __post_init__(self) -> None:
        if self.not_applicable and not self.not_applicable_reason.strip():
            raise ValueError(
                "CapabilityIOContract.not_applicable requires a non-empty "
                "not_applicable_reason"
            )

    def produced_types(self) -> Tuple[str, ...]:
        """Return the unique set of artifact types this module produces."""

        return tuple(sorted({spec.type for spec in self.produces}))

    def consumed_types(self) -> Tuple[str, ...]:
        """Return the unique set of artifact types this module consumes."""

        return tuple(sorted({spec.type for spec in self.consumes}))

    def required_consumed_types(self) -> Tuple[str, ...]:
        """Return only the consumed types that are marked required."""

        return tuple(
            sorted({spec.type for spec in self.consumes if spec.required})
        )


def is_meaningful_contract(contract: CapabilityIOContract | None) -> bool:
    """Return True when a module has actually declared a contract.

    The contract registry test treats a missing declaration as a defect.
    A module with an empty contract counts as missing UNLESS it has
    opted out via ``not_applicable=True`` with a reason.
    """

    if contract is None:
        return False
    if contract.not_applicable:
        return bool(contract.not_applicable_reason.strip())
    return bool(contract.produces or contract.consumes)


def produces(*specs: "ArtifactSpec | str") -> Tuple[ArtifactSpec, ...]:
    """Build a tuple of produced :class:`ArtifactSpec` rows.

    Accepts either ready :class:`ArtifactSpec` instances or bare type
    strings (which are wrapped as required, key-less specs).
    """

    return tuple(_coerce_spec(spec, default_required=True) for spec in specs)


def consumes(*specs: "ArtifactSpec | str") -> Tuple[ArtifactSpec, ...]:
    """Build a tuple of consumed :class:`ArtifactSpec` rows.

    Bare strings are wrapped as required-by-default; pass an explicit
    :class:`ArtifactSpec` with ``required=False`` for optional slots.
    """

    return tuple(_coerce_spec(spec, default_required=True) for spec in specs)


def _coerce_spec(value: "ArtifactSpec | str", *, default_required: bool) -> ArtifactSpec:
    if isinstance(value, ArtifactSpec):
        return value
    if isinstance(value, str):
        return ArtifactSpec(type=value, required=default_required)
    raise TypeError(
        f"Expected ArtifactSpec or str, got {type(value).__name__}: {value!r}"
    )


__all__ = [
    "ARTIFACT_TYPES",
    "ArtifactSpec",
    "C2_ENDPOINT",
    "COLLECTED_DATA",
    "CREDENTIAL",
    "CapabilityIOContract",
    "DETECTION_CONTEXT",
    "DISCOVERY_RESULT",
    "EXFIL_PACKAGE",
    "FILE",
    "HOST",
    "IMPACT_TARGET",
    "PERSISTENCE_MARKER",
    "PROCESS",
    "SERVICE",
    "SHARE",
    "STAGED_FILE",
    "TOKEN",
    "USER",
    "consumes",
    "is_meaningful_contract",
    "normalise_artifact_type",
    "produces",
]


# Re-exported so callers can iterate on the public surface without
# importing the dataclass type directly.
def supported_artifact_types() -> Iterable[str]:
    """Return the canonical artifact-type vocabulary as a tuple."""

    return ARTIFACT_TYPES

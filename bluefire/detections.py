"""Evidence-aware detection hypotheses with honest validation states."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from importlib import metadata
from typing import Any, Iterable, Mapping, Sequence

from .evidence import EvidenceProvenance, EvidenceRecord
from .util import canonical_json_bytes, content_hash, json_clone


class DetectionError(ValueError):
    pass


_LANGUAGES = frozenset({"sigma", "spl", "yara", "yara-l", "internal"})
_CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "behavior_id",
        "title",
        "target_language",
        "logsource",
        "selection",
        "parser_backend",
        "public_baselines",
        "malicious_fixture_ids",
        "observed_evidence_ids",
        "benign_fixture_ids",
        "known_misses",
        "false_positive_notes",
        "tuning_decisions",
        "state",
        "provenance",
        "match_count",
        "benign_match_count",
        "rejection_reason",
        "rule_source",
        "validation",
        "predicted_fields",
        "observed_fields",
        "field_drift",
        "malicious_fixtures",
        "benign_fixtures",
        "lifecycle_history",
    }
)
_REQUIRED_CANDIDATE_FIELDS = _CANDIDATE_FIELDS - {
    "malicious_fixtures",
    "benign_fixtures",
    "lifecycle_history",
}
_MAX_SOURCE_BYTES = 256 * 1024
_MAX_FIXTURE_BYTES = 1024 * 1024
_MAX_STRUCTURED_BYTES = 64 * 1024
_MAX_NOTES = 64
_MAX_NOTE_LENGTH = 1_000
_MAX_FIXTURES = 128
_MAX_HISTORY = 256


def _bounded_string(value: Any, context: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise DetectionError(f"{context} must contain 1-{maximum} characters")
    return value


def _optional_bounded_string(value: Any, context: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    return _bounded_string(value, context, maximum=maximum)


def _optional_bounded_source(value: Any) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > _MAX_SOURCE_BYTES
    ):
        raise DetectionError("rule_source is invalid or exceeds the byte limit")
    return value


def _json_clone_with_limit(value: Any, context: str, maximum_bytes: int) -> Any:
    try:
        cloned = json_clone(value)
        size = len(canonical_json_bytes(cloned))
    except (TypeError, ValueError, RecursionError) as exc:
        raise DetectionError(f"{context} must contain only finite JSON values") from exc
    if size > maximum_bytes:
        raise DetectionError(f"{context} exceeds its byte limit")
    return cloned


def _structured_mapping(
    value: Any,
    context: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> dict[str, Any]:
    cloned = _json_clone_with_limit(value, context, maximum_bytes)
    if not isinstance(cloned, dict) or (not allow_empty and not cloned):
        raise DetectionError(f"{context} must be a JSON object")
    if not all(isinstance(key, str) and key for key in cloned):
        raise DetectionError(f"{context} contains an invalid field name")
    return cloned


def _string_mapping(
    value: Any,
    context: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> dict[str, str]:
    if not isinstance(value, Mapping) or (not allow_empty and not value) or len(value) > maximum:
        raise DetectionError(f"{context} must contain between 1 and {maximum} string fields")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _bounded_string(raw_key, f"{context} field", maximum=200)
        result[key] = _bounded_string(raw_value, f"{context}.{key}", maximum=2_000)
    return result


def _string_mapping_rows(
    value: Any, context: str, *, maximum: int
) -> tuple[Mapping[str, str], ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise DetectionError(f"{context} must be a list of at most {maximum} objects")
    return tuple(
        _string_mapping(row, f"{context}[{index}]", maximum=32) for index, row in enumerate(value)
    )


def _string_rows(
    value: Any,
    context: str,
    *,
    maximum: int,
    item_maximum: int = 200,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise DetectionError(f"{context} must be a list of at most {maximum} strings")
    result = tuple(
        _bounded_string(item, f"{context}[{index}]", maximum=item_maximum)
        for index, item in enumerate(value)
    )
    if len(set(result)) != len(result):
        raise DetectionError(f"{context} must not contain duplicates")
    return result


def _bounded_count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise DetectionError(f"{context} must be a non-negative 32-bit integer")
    return int(value)


def _fixture_rows(value: Any, context: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) > _MAX_FIXTURES:
        raise DetectionError(f"{context} must be a list of at most {_MAX_FIXTURES} fixtures")
    cloned = _json_clone_with_limit(value, context, _MAX_FIXTURE_BYTES)
    if not isinstance(cloned, list):
        raise DetectionError(f"{context} must be a fixture list")
    rows: list[Mapping[str, Any]] = []
    fixture_ids: list[str] = []
    for index, row in enumerate(cloned):
        if not isinstance(row, dict) or not row:
            raise DetectionError(f"{context}[{index}] must be a non-empty object")
        fixture_id = _bounded_string(
            row.get("fixture_id"), f"{context}[{index}].fixture_id", maximum=200
        )
        rows.append(row)
        fixture_ids.append(fixture_id)
    if len(set(fixture_ids)) != len(fixture_ids):
        raise DetectionError(f"{context} fixture IDs must be unique")
    return tuple(rows)


def _field_drift(value: Any) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, Mapping):
        raise DetectionError("field_drift must be an object")
    if not value:
        return {}
    expected = {"predicted_only", "observed_only", "intersection"}
    if set(value) != expected:
        raise DetectionError(
            "field_drift must contain predicted_only, observed_only, and intersection"
        )
    return {
        name: _string_rows(value[name], f"field_drift.{name}", maximum=256)
        for name in sorted(expected)
    }


def _history_rows(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) > _MAX_HISTORY:
        raise DetectionError(f"lifecycle_history must contain at most {_MAX_HISTORY} entries")
    rows = _json_clone_with_limit(value, "lifecycle_history", _MAX_STRUCTURED_BYTES)
    if not isinstance(rows, list):
        raise DetectionError("lifecycle_history must be a list")
    result: list[Mapping[str, Any]] = []
    required = {
        "sequence",
        "action",
        "from_state",
        "to_state",
        "outcome",
        "input_digest",
        "recorded_at",
    }
    allowed = required | {"run_id"}
    actions = {
        "hypothesis_upsert",
        "parse",
        "exercise_fixtures",
        "exercise_observed",
        "evaluate_benign",
        "reject",
    }
    outcomes = {"created", "updated", "transitioned", "no_state_change", "rejected"}
    for index, row in enumerate(rows):
        row_fields = set(row) if isinstance(row, dict) else set()
        if not isinstance(row, dict) or (row_fields != required and row_fields != allowed):
            raise DetectionError(f"lifecycle_history[{index}] has invalid fields")
        sequence = _bounded_count(row.get("sequence"), f"lifecycle_history[{index}].sequence")
        if sequence != index + 1:
            raise DetectionError("lifecycle_history sequence is not contiguous")
        action = _bounded_string(
            row.get("action"), f"lifecycle_history[{index}].action", maximum=40
        )
        if action not in actions:
            raise DetectionError(f"lifecycle_history[{index}].action is invalid")
        outcome = _bounded_string(
            row.get("outcome"), f"lifecycle_history[{index}].outcome", maximum=40
        )
        if outcome not in outcomes:
            raise DetectionError(f"lifecycle_history[{index}].outcome is invalid")
        for name in ("from_state", "to_state"):
            state_value = row.get(name)
            if state_value is not None:
                try:
                    DetectionState(state_value)
                except (TypeError, ValueError) as exc:
                    raise DetectionError(f"lifecycle_history[{index}].{name} is invalid") from exc
        digest = _bounded_string(
            row.get("input_digest"), f"lifecycle_history[{index}].input_digest", maximum=71
        )
        digest_value = digest.removeprefix("sha256:")
        if (
            not digest.startswith("sha256:")
            or len(digest) != 71
            or any(character not in "0123456789abcdef" for character in digest_value)
        ):
            raise DetectionError(f"lifecycle_history[{index}].input_digest is invalid")
        _bounded_string(
            row.get("recorded_at"), f"lifecycle_history[{index}].recorded_at", maximum=40
        )
        if "run_id" in row:
            _bounded_string(row.get("run_id"), f"lifecycle_history[{index}].run_id", maximum=80)
        result.append(row)
    for index, row in enumerate(result):
        raw_from_state = row.get("from_state")
        raw_to_state = row.get("to_state")
        raw_action = row.get("action")
        raw_outcome = row.get("outcome")
        if (
            (raw_from_state is not None and not isinstance(raw_from_state, str))
            or not isinstance(raw_to_state, str)
            or not isinstance(raw_action, str)
            or not isinstance(raw_outcome, str)
        ):
            raise DetectionError("lifecycle_history contains invalid typed values")
        from_state: str | None = raw_from_state
        to_state = raw_to_state
        action_value = raw_action
        outcome_value = raw_outcome
        if index == 0:
            if (
                from_state is not None
                or to_state != DetectionState.HYPOTHESIS.value
                or action_value != "hypothesis_upsert"
                or outcome_value != "created"
            ):
                raise DetectionError("lifecycle_history must begin with hypothesis creation")
        elif from_state != result[index - 1].get("to_state"):
            raise DetectionError("lifecycle_history states are not contiguous")
        if outcome_value == "created" and index != 0:
            raise DetectionError("lifecycle_history creation outcome is inconsistent")
        if from_state is not None and from_state != to_state:
            source = DetectionState(from_state)
            target = DetectionState(to_state)
            if target not in _ALLOWED_TRANSITIONS[source]:
                raise DetectionError("lifecycle_history contains an invalid state transition")
        if outcome_value == "updated" and not (
            action_value == "hypothesis_upsert"
            and from_state == to_state == DetectionState.HYPOTHESIS.value
        ):
            raise DetectionError("lifecycle_history update outcome is inconsistent")
        if outcome_value == "no_state_change" and from_state != to_state:
            raise DetectionError("lifecycle_history no-change outcome is inconsistent")
        if outcome_value == "transitioned" and (
            from_state is None
            or from_state == to_state
            or to_state == DetectionState.REJECTED.value
        ):
            raise DetectionError("lifecycle_history transition outcome is inconsistent")
        if outcome_value == "rejected" and (
            to_state != DetectionState.REJECTED.value or from_state == DetectionState.REJECTED.value
        ):
            raise DetectionError("lifecycle_history rejection outcome is inconsistent")
        action_states: dict[str, tuple[set[str | None], set[str]]] = {
            "hypothesis_upsert": (
                {None, DetectionState.HYPOTHESIS.value},
                {DetectionState.HYPOTHESIS.value},
            ),
            "parse": (
                {DetectionState.HYPOTHESIS.value},
                {
                    DetectionState.HYPOTHESIS.value,
                    DetectionState.PARSED.value,
                    DetectionState.REJECTED.value,
                },
            ),
            "exercise_fixtures": (
                {DetectionState.PARSED.value},
                {DetectionState.FIXTURE_EXERCISED.value, DetectionState.REJECTED.value},
            ),
            "exercise_observed": (
                {DetectionState.PARSED.value, DetectionState.FIXTURE_EXERCISED.value},
                {
                    DetectionState.PARSED.value,
                    DetectionState.FIXTURE_EXERCISED.value,
                    DetectionState.OBSERVED_EXERCISED.value,
                },
            ),
            "evaluate_benign": (
                {DetectionState.FIXTURE_EXERCISED.value, DetectionState.OBSERVED_EXERCISED.value},
                {DetectionState.BENIGN_EVALUATED.value},
            ),
            "reject": (
                {
                    DetectionState.HYPOTHESIS.value,
                    DetectionState.PARSED.value,
                    DetectionState.FIXTURE_EXERCISED.value,
                    DetectionState.OBSERVED_EXERCISED.value,
                    DetectionState.BENIGN_EVALUATED.value,
                },
                {DetectionState.REJECTED.value},
            ),
        }
        allowed_from, allowed_to = action_states[action_value]
        if from_state not in allowed_from or to_state not in allowed_to:
            raise DetectionError("lifecycle_history action does not match its states")
    return tuple(result)


class DetectionState(str, Enum):
    HYPOTHESIS = "hypothesis"
    PARSED = "parsed"
    FIXTURE_EXERCISED = "fixture_exercised"
    OBSERVED_EXERCISED = "observed_exercised"
    BENIGN_EVALUATED = "benign_evaluated"
    REJECTED = "rejected"


_ALLOWED_TRANSITIONS: dict[DetectionState, frozenset[DetectionState]] = {
    DetectionState.HYPOTHESIS: frozenset({DetectionState.PARSED, DetectionState.REJECTED}),
    DetectionState.PARSED: frozenset(
        {
            DetectionState.FIXTURE_EXERCISED,
            DetectionState.OBSERVED_EXERCISED,
            DetectionState.REJECTED,
        }
    ),
    DetectionState.FIXTURE_EXERCISED: frozenset(
        {
            DetectionState.OBSERVED_EXERCISED,
            DetectionState.BENIGN_EVALUATED,
            DetectionState.REJECTED,
        }
    ),
    DetectionState.OBSERVED_EXERCISED: frozenset(
        {DetectionState.BENIGN_EVALUATED, DetectionState.REJECTED}
    ),
    DetectionState.BENIGN_EVALUATED: frozenset({DetectionState.REJECTED}),
    DetectionState.REJECTED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    schema_version: str
    candidate_id: str
    behavior_id: str
    title: str
    target_language: str
    logsource: Mapping[str, str]
    selection: Mapping[str, Any]
    parser_backend: Mapping[str, str]
    public_baselines: tuple[Mapping[str, str], ...]
    malicious_fixture_ids: tuple[str, ...]
    observed_evidence_ids: tuple[str, ...]
    benign_fixture_ids: tuple[str, ...]
    known_misses: tuple[str, ...]
    false_positive_notes: tuple[str, ...]
    tuning_decisions: tuple[str, ...]
    state: DetectionState
    provenance: Mapping[str, str]
    match_count: int = 0
    benign_match_count: int = 0
    rejection_reason: str | None = None
    rule_source: str | None = None
    validation: Mapping[str, Any] = field(default_factory=dict)
    predicted_fields: tuple[str, ...] = ()
    observed_fields: tuple[str, ...] = ()
    field_drift: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    malicious_fixtures: tuple[Mapping[str, Any], ...] = ()
    benign_fixtures: tuple[Mapping[str, Any], ...] = ()
    lifecycle_history: tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def hypothesis(
        cls,
        *,
        behavior_id: str,
        title: str,
        target_language: str,
        logsource: Mapping[str, str],
        selection: Mapping[str, Any],
        provenance: Mapping[str, str],
        known_misses: Iterable[str] = (),
        public_baselines: Iterable[Mapping[str, str]] = (),
    ) -> "DetectionCandidate":
        if target_language not in _LANGUAGES:
            raise DetectionError(f"unsupported detection language: {target_language}")
        if not behavior_id or not title or not selection:
            raise DetectionError("detection hypotheses require behavior, title, and selection")
        identity = content_hash(
            {
                "behavior_id": behavior_id,
                "target_language": target_language,
                "logsource": dict(logsource),
                "selection": dict(selection),
            }
        )
        return cls(
            schema_version="bluefire.detection.v1",
            candidate_id="detection-" + identity.removeprefix("sha256:")[:20],
            behavior_id=behavior_id,
            title=title,
            target_language=target_language,
            logsource=dict(logsource),
            selection=dict(selection),
            parser_backend={},
            public_baselines=tuple(dict(row) for row in public_baselines),
            malicious_fixture_ids=(),
            observed_evidence_ids=(),
            benign_fixture_ids=(),
            known_misses=tuple(known_misses),
            false_positive_notes=(),
            tuning_decisions=(),
            state=DetectionState.HYPOTHESIS,
            provenance=dict(provenance),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DetectionCandidate":
        """Strictly rehydrate a persisted candidate without trusting its identity.

        The three lifecycle persistence fields are additive.  Their absence is
        accepted so pre-lifecycle ``bluefire.detection.v1`` resources remain
        readable, while every other field must match the established contract.
        """

        if not isinstance(value, Mapping):
            raise DetectionError("detection candidate must be an object")
        fields = set(value)
        missing = sorted(_REQUIRED_CANDIDATE_FIELDS - fields)
        unknown = sorted(fields - _CANDIDATE_FIELDS)
        if missing or unknown:
            details = []
            if missing:
                details.append("missing fields: " + ", ".join(missing))
            if unknown:
                details.append("unknown fields: " + ", ".join(unknown))
            raise DetectionError("invalid detection candidate fields (" + "; ".join(details) + ")")
        if value.get("schema_version") != "bluefire.detection.v1":
            raise DetectionError("unsupported detection candidate schema version")

        behavior_id = _bounded_string(value.get("behavior_id"), "behavior_id", maximum=200)
        candidate_id = _bounded_string(value.get("candidate_id"), "candidate_id", maximum=200)
        if not candidate_id.startswith("detection-") or len(candidate_id) != 30:
            raise DetectionError("candidate_id is invalid")
        title = _bounded_string(value.get("title"), "title", maximum=300)
        target_language = _bounded_string(
            value.get("target_language"), "target_language", maximum=20
        )
        if target_language not in _LANGUAGES:
            raise DetectionError(f"unsupported detection language: {target_language}")
        logsource = _string_mapping(value.get("logsource"), "logsource", maximum=32)
        selection = _structured_mapping(
            value.get("selection"), "selection", maximum_bytes=_MAX_STRUCTURED_BYTES
        )
        if not selection or len(selection) > 64:
            raise DetectionError("selection must contain between 1 and 64 fields")
        expected_id = (
            "detection-"
            + content_hash(
                {
                    "behavior_id": behavior_id,
                    "target_language": target_language,
                    "logsource": logsource,
                    "selection": selection,
                }
            ).removeprefix("sha256:")[:20]
        )
        if candidate_id != expected_id:
            raise DetectionError("candidate_id does not match the candidate identity")

        state_raw = value.get("state")
        try:
            state = DetectionState(state_raw)
        except (TypeError, ValueError) as exc:
            raise DetectionError("detection state is invalid") from exc
        parser_backend = _string_mapping(
            value.get("parser_backend"), "parser_backend", maximum=16, allow_empty=True
        )
        public_baselines = _string_mapping_rows(
            value.get("public_baselines"), "public_baselines", maximum=32
        )
        malicious_fixture_ids = _string_rows(
            value.get("malicious_fixture_ids"), "malicious_fixture_ids", maximum=256
        )
        observed_evidence_ids = _string_rows(
            value.get("observed_evidence_ids"), "observed_evidence_ids", maximum=256
        )
        benign_fixture_ids = _string_rows(
            value.get("benign_fixture_ids"), "benign_fixture_ids", maximum=256
        )
        known_misses = _string_rows(
            value.get("known_misses"),
            "known_misses",
            maximum=_MAX_NOTES,
            item_maximum=_MAX_NOTE_LENGTH,
        )
        false_positive_notes = _string_rows(
            value.get("false_positive_notes"),
            "false_positive_notes",
            maximum=_MAX_NOTES,
            item_maximum=_MAX_NOTE_LENGTH,
        )
        tuning_decisions = _string_rows(
            value.get("tuning_decisions"),
            "tuning_decisions",
            maximum=_MAX_NOTES,
            item_maximum=_MAX_NOTE_LENGTH,
        )
        provenance = _string_mapping(value.get("provenance"), "provenance", maximum=32)
        match_count = _bounded_count(value.get("match_count"), "match_count")
        benign_match_count = _bounded_count(value.get("benign_match_count"), "benign_match_count")
        rejection_reason = _optional_bounded_string(
            value.get("rejection_reason"), "rejection_reason", maximum=_MAX_NOTE_LENGTH
        )
        rule_source = _optional_bounded_source(value.get("rule_source"))
        validation = _structured_mapping(
            value.get("validation"),
            "validation",
            maximum_bytes=_MAX_STRUCTURED_BYTES,
            allow_empty=True,
        )
        predicted_fields = _string_rows(
            value.get("predicted_fields"), "predicted_fields", maximum=256
        )
        observed_fields = _string_rows(value.get("observed_fields"), "observed_fields", maximum=256)
        field_drift = _field_drift(value.get("field_drift"))
        malicious_fixtures = _fixture_rows(
            value.get("malicious_fixtures", []), "malicious_fixtures"
        )
        benign_fixtures = _fixture_rows(value.get("benign_fixtures", []), "benign_fixtures")
        lifecycle_history = _history_rows(value.get("lifecycle_history", []))

        if state is DetectionState.REJECTED and not rejection_reason:
            raise DetectionError("a rejected candidate requires a rejection reason")
        if state is not DetectionState.REJECTED and rejection_reason is not None:
            raise DetectionError("only a rejected candidate may have a rejection reason")
        if lifecycle_history and lifecycle_history[-1].get("to_state") != state.value:
            raise DetectionError("lifecycle_history does not end at the candidate state")
        if (
            malicious_fixtures
            and tuple(str(row.get("fixture_id")) for row in malicious_fixtures)
            != malicious_fixture_ids
        ):
            raise DetectionError("malicious fixture documents do not match their IDs")
        if benign_fixtures and tuple(str(row.get("fixture_id")) for row in benign_fixtures) != (
            benign_fixture_ids
        ):
            raise DetectionError("benign fixture documents do not match their IDs")

        return cls(
            schema_version="bluefire.detection.v1",
            candidate_id=candidate_id,
            behavior_id=behavior_id,
            title=title,
            target_language=target_language,
            logsource=logsource,
            selection=selection,
            parser_backend=parser_backend,
            public_baselines=public_baselines,
            malicious_fixture_ids=malicious_fixture_ids,
            observed_evidence_ids=observed_evidence_ids,
            benign_fixture_ids=benign_fixture_ids,
            known_misses=known_misses,
            false_positive_notes=false_positive_notes,
            tuning_decisions=tuning_decisions,
            state=state,
            provenance=provenance,
            match_count=match_count,
            benign_match_count=benign_match_count,
            rejection_reason=rejection_reason,
            rule_source=rule_source,
            validation=validation,
            predicted_fields=predicted_fields,
            observed_fields=observed_fields,
            field_drift=field_drift,
            malicious_fixtures=malicious_fixtures,
            benign_fixtures=benign_fixtures,
            lifecycle_history=lifecycle_history,
        )

    def transition(self, state: DetectionState, **changes: Any) -> "DetectionCandidate":
        if state not in _ALLOWED_TRANSITIONS[self.state]:
            raise DetectionError(
                f"invalid detection transition: {self.state.value} -> {state.value}"
            )
        return replace(self, state=state, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "behavior_id": self.behavior_id,
            "title": self.title,
            "target_language": self.target_language,
            "logsource": dict(self.logsource),
            "selection": dict(self.selection),
            "parser_backend": dict(self.parser_backend),
            "public_baselines": [dict(row) for row in self.public_baselines],
            "malicious_fixture_ids": list(self.malicious_fixture_ids),
            "observed_evidence_ids": list(self.observed_evidence_ids),
            "benign_fixture_ids": list(self.benign_fixture_ids),
            "known_misses": list(self.known_misses),
            "false_positive_notes": list(self.false_positive_notes),
            "tuning_decisions": list(self.tuning_decisions),
            "state": self.state.value,
            "provenance": dict(self.provenance),
            "match_count": self.match_count,
            "benign_match_count": self.benign_match_count,
            "rejection_reason": self.rejection_reason,
            "rule_source": self.rule_source,
            "validation": dict(self.validation),
            "predicted_fields": list(self.predicted_fields),
            "observed_fields": list(self.observed_fields),
            "field_drift": {name: list(values) for name, values in self.field_drift.items()},
            "malicious_fixtures": [dict(row) for row in self.malicious_fixtures],
            "benign_fixtures": [dict(row) for row in self.benign_fixtures],
            "lifecycle_history": [dict(row) for row in self.lifecycle_history],
        }


class DetectionPipeline:
    """Validate candidates against explicit fixtures and observed evidence."""

    parser_name = "bluefire-structured-matcher"
    parser_version = "1.0"

    def parse(self, candidate: DetectionCandidate) -> DetectionCandidate:
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be parsed")
        if candidate.target_language != "internal":
            raise DetectionError(
                "external detection languages require their authoritative parser or compiler"
            )
        for field_name in candidate.selection:
            if not isinstance(field_name, str):
                return candidate.transition(
                    DetectionState.REJECTED,
                    rejection_reason=f"invalid selection field: {field_name!r}",
                )
            key, separator, operator = field_name.partition("|")
            if (
                not key
                or " " in field_name
                or any(not part for part in key.split("."))
                or (separator and operator not in {"contains", "startswith", "endswith"})
            ):
                return candidate.transition(
                    DetectionState.REJECTED,
                    rejection_reason=f"invalid selection field: {field_name!r}",
                )
        return candidate.transition(
            DetectionState.PARSED,
            parser_backend={"name": self.parser_name, "version": self.parser_version},
        )

    def exercise_fixtures(
        self,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
    ) -> DetectionCandidate:
        if candidate.state is not DetectionState.PARSED:
            raise DetectionError("candidate must be parsed before fixture exercise")
        ids, matched_ids = self._evaluate(candidate, fixtures)
        if not matched_ids:
            return candidate.transition(
                DetectionState.REJECTED,
                malicious_fixture_ids=tuple(ids),
                rejection_reason="candidate did not match any declared malicious fixture",
            )
        return candidate.transition(
            DetectionState.FIXTURE_EXERCISED,
            malicious_fixture_ids=tuple(ids),
            match_count=len(matched_ids),
        )

    def exercise_observed(
        self,
        candidate: DetectionCandidate,
        records: Sequence[EvidenceRecord],
    ) -> DetectionCandidate:
        if candidate.state not in {DetectionState.PARSED, DetectionState.FIXTURE_EXERCISED}:
            raise DetectionError("candidate must be parsed before observed exercise")
        observed = [
            record for record in records if record.provenance is EvidenceProvenance.OBSERVED
        ]
        fixtures = [dict(record.content, fixture_id=record.evidence_id) for record in observed]
        _ids, matched_ids = self._evaluate(candidate, fixtures)
        if not matched_ids:
            return candidate
        return candidate.transition(
            DetectionState.OBSERVED_EXERCISED,
            observed_evidence_ids=tuple(matched_ids),
            match_count=candidate.match_count + len(matched_ids),
        )

    def evaluate_benign(
        self,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
        *,
        notes: Iterable[str] = (),
    ) -> DetectionCandidate:
        if candidate.state not in {
            DetectionState.FIXTURE_EXERCISED,
            DetectionState.OBSERVED_EXERCISED,
        }:
            raise DetectionError("candidate must be exercised before benign evaluation")
        ids, matched_ids = self._evaluate(candidate, fixtures)
        return candidate.transition(
            DetectionState.BENIGN_EVALUATED,
            benign_fixture_ids=tuple(ids),
            benign_match_count=len(matched_ids),
            false_positive_notes=tuple(notes),
        )

    @classmethod
    def _evaluate(
        cls,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
    ) -> tuple[list[str], list[str]]:
        ids: list[str] = []
        matched_ids: list[str] = []
        for index, fixture in enumerate(fixtures):
            fixture_id = str(fixture.get("fixture_id") or f"fixture-{index + 1}")
            ids.append(fixture_id)
            if cls._matches(candidate.selection, fixture):
                matched_ids.append(fixture_id)
        return ids, matched_ids

    @staticmethod
    def _matches(selection: Mapping[str, Any], fixture: Mapping[str, Any]) -> bool:
        for raw_key, expected in selection.items():
            key, _, operator = raw_key.partition("|")
            actual: Any = fixture
            for part in key.split("."):
                if not isinstance(actual, Mapping) or part not in actual:
                    return False
                actual = actual[part]
            if operator == "contains":
                if str(expected).casefold() not in str(actual).casefold():
                    return False
            elif operator == "startswith":
                if not str(actual).casefold().startswith(str(expected).casefold()):
                    return False
            elif operator == "endswith":
                if not str(actual).casefold().endswith(str(expected).casefold()):
                    return False
            elif operator:
                return False
            elif actual != expected:
                return False
        return True


class ExternalDetectionValidator:
    """Authoritative parser/compiler adapters for the maintained lab languages.

    The imports are intentionally local so Simulate remains usable when the
    optional detection dependencies are not installed.  An unavailable parser
    never advances a candidate's lifecycle state.
    """

    max_source_bytes = 256 * 1024
    max_fixture_bytes = 1024 * 1024

    @staticmethod
    def health() -> Mapping[str, Mapping[str, Any]]:
        result: dict[str, Mapping[str, Any]] = {}
        for package, label in (("pysigma", "pySigma"), ("yara-python", "YARA-Python")):
            try:
                version = metadata.version(package)
            except metadata.PackageNotFoundError:
                result[label] = {"ready": False, "version": None}
            else:
                result[label] = {"ready": True, "version": version}
        result["SPL structural checker"] = {"ready": True, "version": "1"}
        return result

    def parse_sigma(self, candidate: DetectionCandidate, source: str) -> DetectionCandidate:
        self._require_hypothesis(candidate, "sigma")
        source = self._source(source)
        try:
            from sigma.collection import SigmaCollection
        except ImportError as exc:
            raise DetectionError("pySigma is unavailable; candidate remains a hypothesis") from exc
        try:
            collection = SigmaCollection.from_yaml(source, collect_errors=True)
        except Exception as exc:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason=f"pySigma rejected the rule: {type(exc).__name__}",
                validation={"backend": "pySigma", "errors": [str(exc)[:300]]},
            )
        errors = [str(error)[:300] for error in collection.errors]
        for rule in collection.rules:
            errors.extend(str(error)[:300] for error in rule.errors)
        if errors or len(collection.rules) != 1:
            reason = errors[0] if errors else "exactly one Sigma rule is required"
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason="pySigma rejected the rule: " + reason,
                validation={"backend": "pySigma", "errors": errors},
            )
        version = metadata.version("pysigma")
        return candidate.transition(
            DetectionState.PARSED,
            rule_source=source,
            parser_backend={"name": "pySigma", "version": version},
            validation={
                "backend": "pySigma",
                "version": version,
                "rule_count": 1,
                "errors": [],
            },
        )

    def compile_yara(self, candidate: DetectionCandidate, source: str) -> DetectionCandidate:
        if candidate.target_language not in {"yara", "yara-l"}:
            raise DetectionError("candidate language must be yara")
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be compiled")
        source = self._source(source)
        try:
            import yara
        except ImportError as exc:
            raise DetectionError(
                "YARA-Python is unavailable; candidate remains a hypothesis"
            ) from exc
        try:
            yara.compile(source=source, includes=False, error_on_warning=True)
        except yara.Error as exc:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason="YARA rejected the rule",
                validation={"backend": "YARA-Python", "errors": [str(exc)[:300]]},
            )
        version = metadata.version("yara-python")
        return candidate.transition(
            DetectionState.PARSED,
            rule_source=source,
            parser_backend={"name": "YARA-Python", "version": version},
            validation={
                "backend": "YARA-Python",
                "version": version,
                "compiled": True,
                "includes": False,
                "warnings_as_errors": True,
            },
        )

    def exercise_yara_fixtures(
        self,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
    ) -> DetectionCandidate:
        if candidate.state is not DetectionState.PARSED or not candidate.rule_source:
            raise DetectionError("YARA candidate must be compiled before fixture exercise")
        fixture_ids, matched_ids = self._yara_matches(candidate, fixtures)
        if not matched_ids:
            return candidate.transition(
                DetectionState.REJECTED,
                malicious_fixture_ids=tuple(fixture_ids),
                rejection_reason="compiled YARA rule did not match a malicious fixture",
            )
        return candidate.transition(
            DetectionState.FIXTURE_EXERCISED,
            malicious_fixture_ids=tuple(fixture_ids),
            match_count=len(matched_ids),
            validation=dict(candidate.validation, matched_fixture_ids=matched_ids),
        )

    def evaluate_yara_benign(
        self,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
        *,
        notes: Iterable[str] = (),
    ) -> DetectionCandidate:
        if (
            candidate.state
            not in {
                DetectionState.FIXTURE_EXERCISED,
                DetectionState.OBSERVED_EXERCISED,
            }
            or not candidate.rule_source
        ):
            raise DetectionError("YARA candidate must be exercised before benign evaluation")
        fixture_ids, matched_ids = self._yara_matches(candidate, fixtures)
        return candidate.transition(
            DetectionState.BENIGN_EVALUATED,
            benign_fixture_ids=tuple(fixture_ids),
            benign_match_count=len(matched_ids),
            false_positive_notes=tuple(notes),
            validation=dict(candidate.validation, benign_matched_fixture_ids=matched_ids),
        )

    def _yara_matches(
        self,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
    ) -> tuple[list[str], list[str]]:
        try:
            import yara
        except ImportError as exc:
            raise DetectionError("YARA-Python is unavailable") from exc
        if not candidate.rule_source:
            raise DetectionError("YARA candidate has no compiled rule source")
        try:
            rules = yara.compile(
                source=candidate.rule_source, includes=False, error_on_warning=True
            )
        except yara.Error as exc:
            raise DetectionError("YARA-Python fixture compilation failed") from exc
        fixture_ids: list[str] = []
        matched_ids: list[str] = []
        for index, fixture in enumerate(fixtures):
            fixture_id = str(fixture.get("fixture_id") or f"fixture-{index + 1}")
            payload = fixture.get("data", b"")
            if isinstance(payload, str):
                data = payload.encode("utf-8")
            elif isinstance(payload, bytes):
                data = payload
            else:
                raise DetectionError("YARA fixture data must be bytes or text")
            if len(data) > self.max_fixture_bytes:
                raise DetectionError("YARA fixture exceeds the byte limit")
            fixture_ids.append(fixture_id)
            try:
                matches = rules.match(data=data, timeout=2)
            except yara.Error as exc:
                raise DetectionError("YARA-Python fixture evaluation failed") from exc
            if matches:
                matched_ids.append(fixture_id)
        return fixture_ids, matched_ids

    def check_spl(self, candidate: DetectionCandidate, source: str) -> DetectionCandidate:
        self._require_hypothesis(candidate, "spl")
        source = self._source(source)
        problems: list[str] = []
        pairs = {"(": ")", "[": "]", "{": "}"}
        stack: list[str] = []
        in_quote = False
        escaped = False
        for character in source:
            if escaped:
                escaped = False
                continue
            if character == "\\" and in_quote:
                escaped = True
                continue
            if character == '"':
                in_quote = not in_quote
            elif not in_quote and character in pairs:
                stack.append(pairs[character])
            elif not in_quote and character in pairs.values():
                if not stack or stack.pop() != character:
                    problems.append("unbalanced delimiter")
                    break
        if in_quote or stack:
            problems.append("unterminated quote or delimiter")
        if any(ord(character) < 9 for character in source):
            problems.append("control characters are not allowed")
        if problems:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason="SPL structural check failed",
                validation={"backend": "structural-only", "errors": problems},
            )
        # A structural check is useful readiness information, but it is not a
        # backend parser.  The candidate deliberately remains a hypothesis.
        return replace(
            candidate,
            rule_source=source,
            validation={
                "backend": "structural-only",
                "syntax_checked": True,
                "authoritative_backend_validated": False,
                "errors": [],
            },
        )

    @staticmethod
    def field_drift(
        predicted_fields: Iterable[str], observed_fields: Iterable[str]
    ) -> Mapping[str, tuple[str, ...]]:
        predicted = {str(item) for item in predicted_fields if str(item)}
        observed = {str(item) for item in observed_fields if str(item)}
        return {
            "predicted_only": tuple(sorted(predicted - observed)),
            "observed_only": tuple(sorted(observed - predicted)),
            "intersection": tuple(sorted(predicted & observed)),
        }

    @staticmethod
    def compare_public_baseline(
        candidate_matches: Iterable[str], baseline_matches: Iterable[str]
    ) -> Mapping[str, Any]:
        candidate = set(candidate_matches)
        baseline = set(baseline_matches)
        return {
            "candidate_only": sorted(candidate - baseline),
            "baseline_only": sorted(baseline - candidate),
            "overlap": sorted(candidate & baseline),
            "incremental_candidate_matches": len(candidate - baseline),
        }

    def _source(self, source: str) -> str:
        if not isinstance(source, str) or not source.strip():
            raise DetectionError("detection source is required")
        if "\x00" in source or len(source.encode("utf-8")) > self.max_source_bytes:
            raise DetectionError("detection source is invalid or exceeds the byte limit")
        return source

    @staticmethod
    def _require_hypothesis(candidate: DetectionCandidate, language: str) -> None:
        if candidate.target_language != language:
            raise DetectionError(f"candidate language must be {language}")
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be parsed")


__all__ = [
    "DetectionCandidate",
    "DetectionError",
    "ExternalDetectionValidator",
    "DetectionPipeline",
    "DetectionState",
]

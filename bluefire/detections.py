"""Evidence-aware detection hypotheses with honest validation states."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .evidence import EvidenceProvenance, EvidenceRecord
from .util import content_hash


class DetectionError(ValueError):
    pass


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
        if target_language not in {"sigma", "spl", "yara-l", "internal"}:
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
        }


class DetectionPipeline:
    """Validate candidates against explicit fixtures and observed evidence."""

    parser_name = "bluefire-structured-matcher"
    parser_version = "1.0"

    def parse(self, candidate: DetectionCandidate) -> DetectionCandidate:
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be parsed")
        for field_name in candidate.selection:
            if not isinstance(field_name, str) or not field_name or " " in field_name:
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
        ids, matches = self._evaluate(candidate, fixtures)
        if not matches:
            return candidate.transition(
                DetectionState.REJECTED,
                malicious_fixture_ids=tuple(ids),
                rejection_reason="candidate did not match any declared malicious fixture",
            )
        return candidate.transition(
            DetectionState.FIXTURE_EXERCISED,
            malicious_fixture_ids=tuple(ids),
            match_count=matches,
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
        ids, matches = self._evaluate(candidate, fixtures)
        if not matches:
            return candidate
        return candidate.transition(
            DetectionState.OBSERVED_EXERCISED,
            observed_evidence_ids=tuple(ids),
            match_count=candidate.match_count + matches,
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
        ids, matches = self._evaluate(candidate, fixtures)
        return candidate.transition(
            DetectionState.BENIGN_EVALUATED,
            benign_fixture_ids=tuple(ids),
            benign_match_count=matches,
            false_positive_notes=tuple(notes),
        )

    @classmethod
    def _evaluate(
        cls,
        candidate: DetectionCandidate,
        fixtures: Sequence[Mapping[str, Any]],
    ) -> tuple[list[str], int]:
        ids: list[str] = []
        matches = 0
        for index, fixture in enumerate(fixtures):
            fixture_id = str(fixture.get("fixture_id") or f"fixture-{index + 1}")
            ids.append(fixture_id)
            if cls._matches(candidate.selection, fixture):
                matches += 1
        return ids, matches

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
            elif operator:
                return False
            elif actual != expected:
                return False
        return True


__all__ = [
    "DetectionCandidate",
    "DetectionError",
    "DetectionPipeline",
    "DetectionState",
]

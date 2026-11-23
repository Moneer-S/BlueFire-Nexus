"""Parse exact reviewed source into an initial candidate without writing a seed."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, Mapping

from .application_errors import APIError
from .detection_backends import convert_sigma_to_sqlite, inspect_sqlite_query
from .detection_lab import DetectionLabService
from .detections import DetectionCandidate, DetectionError, DetectionState
from .util import content_hash


def parsed(
    lab: DetectionLabService, selected: Mapping[str, Any], title: str, source: str
) -> DetectionCandidate:
    try:
        if (
            not isinstance(title, str)
            or not 1 <= len(title) <= 300
            or not title.strip()
            or title != title.strip()
            or any(ord(c) < 32 for c in title)
        ):
            raise DetectionError("title invalid")
        # The normal parser enforces exact-source size and NUL restrictions before conversion.
        lab.validator._source(source)
        query = (
            str(convert_sigma_to_sqlite(source)["converted_query"])
            if selected["target_language"] == "sigma"
            else str(inspect_sqlite_query(source)["query"])
        )
        definition = {
            "behavior_id": selected["behavior_id"],
            "title": title,
            "target_language": selected["target_language"],
            "logsource": {"product": "bluefire", "service": "normalized_run_observations"},
            "selection": {"query": query},
            "provenance": {
                "origin": "reviewed_initial_source",
                "dataset": "bluefire.normalized_run_observations",
            },
        }
        candidate = DetectionCandidate.hypothesis(**definition)
        candidate = lab._record(
            None,
            candidate,
            action="hypothesis_upsert",
            outcome="created",
            request=definition,
            run_id=selected["run_id"],
        )
        parser = (
            lab.validator.parse_sigma
            if selected["target_language"] == "sigma"
            else lab.validator.parse_sqlite
        )
        result = parser(candidate, source)
        if result.state is not DetectionState.PARSED:
            raise DetectionError("source rejected")
        return lab._record_transition(
            candidate, result, "parse", {"source": source}, run_id=selected["run_id"]
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "detection_creation_source_invalid",
            "The reviewed source could not be parsed by the selected bounded backend. Check its syntax and supported observation fields.",
        ) from exc


def reviewed_digest(
    proposal_digest: str, title: str, source: str, candidate: DetectionCandidate
) -> str:
    return content_hash(
        {
            "proposal_digest": proposal_digest,
            "title": title,
            "source": source,
            "definition_digest": candidate.definition_digest,
            "parser_backend": dict(candidate.parser_backend or {}),
            "validation": dict(candidate.validation),
        }
    )

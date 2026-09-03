"""Independent persisted-evidence validation for GATE-07."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping, cast

from .detection_backends import (
    DetectionBackendError,
    convert_sigma_to_sqlite,
    execute_sqlite_query,
    inspect_sqlite_query,
)
from .detection_gate_management import validate_management_surfaces
from .detection_journey import (
    BROWSER_OPERATION_SEQUENCE,
    BROWSER_REPORT,
    BROWSER_SCHEMA,
    CANDIDATE_REPORT,
    CANDIDATE_SCHEMA,
    CORRUPTION_REPORT,
    CORRUPTION_SCHEMA,
    JOURNEY_REPORT,
    JOURNEY_SCHEMA,
    MANAGEMENT_REPORT,
    MANAGEMENT_SCHEMA,
    SIGMA_SOURCE,
    SQLITE_SOURCE,
    YARA_SOURCE,
)
from .detections import DetectionCandidate, DetectionError
from .evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from .research import ResearchSourceError, load_builtin_research_registry
from .run_store import RunStore, RunStoreError
from .util import content_hash

CHECK_NAMES = frozenset(
    {
        "sigma_backend",
        "yara_execution",
        "query_validation",
        "observed_evaluation",
        "field_mapping",
        "notes_baseline",
        "lifecycle",
        "management_parity",
        "three_executed_candidates",
    }
)
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOOPBACK_ORIGIN = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}$")
_FIXTURE_ID = re.compile(r"^gate07-browser-[0-9a-f]{16}$")
_ALL_ROLES = ("sigma", "yara", "sqlite", "clone", "rejected", "browser")
_SERVICE_OPERATIONS = (
    "upsert",
    "parse",
    "exercise_fixtures",
    "exercise_observed",
    "evaluate_benign",
    "clone",
    "tune",
    "reject",
    "compare",
    "list",
)


class DetectionGateValidationError(ValueError):
    """A persisted GATE-07 artifact did not establish its claimed semantics."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DetectionGateValidationError(message)


def _read_json(path: Path) -> Mapping[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "a GATE-07 report is absent or unsafe")
    _require(path.stat().st_size <= _MAX_REPORT_BYTES, "a GATE-07 report exceeds its byte bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DetectionGateValidationError("a GATE-07 report is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise DetectionGateValidationError("a GATE-07 report must be an object")
    return value


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DetectionGateValidationError(message)
    return value


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate_inventory(
    report: Mapping[str, Any],
) -> tuple[Mapping[str, DetectionCandidate], Mapping[str, Any]]:
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "candidates",
            "comparison",
            "listed_candidate_ids",
            "snapshot_digest",
        }
        and report.get("schema_version") == CANDIDATE_SCHEMA
        and report.get("passed") is True,
        "the GATE-07 candidate report has the wrong schema or status",
    )
    raw_candidates = _mapping(report.get("candidates"), "the GATE-07 candidate inventory is absent")
    _require(
        set(raw_candidates) == set(_ALL_ROLES),
        "the GATE-07 candidate role inventory is not exact",
    )
    candidates: dict[str, DetectionCandidate] = {}
    documents: dict[str, Mapping[str, Any]] = {}
    try:
        for role in _ALL_ROLES:
            document = _mapping(raw_candidates[role], "a GATE-07 candidate document is invalid")
            candidate = DetectionCandidate.from_mapping(document)
            _require(
                candidate.to_dict() == document,
                "a GATE-07 candidate is not canonically rehydratable",
            )
            candidates[role] = candidate
            documents[role] = document
    except (DetectionError, KeyError, TypeError, ValueError) as exc:
        raise DetectionGateValidationError("a GATE-07 candidate failed strict rehydration") from exc
    ids = [candidate.candidate_id for candidate in candidates.values()]
    _require(len(ids) == len(set(ids)), "GATE-07 candidate identifiers are not unique")
    listed = report.get("listed_candidate_ids")
    _require(
        isinstance(listed, list)
        and listed == sorted(ids)
        and all(isinstance(item, str) for item in listed),
        "the persisted GATE-07 candidate list does not match the snapshots",
    )
    comparison = _mapping(report.get("comparison"), "the GATE-07 comparison is absent")
    payload = {"candidates": documents, "comparison": comparison}
    _require(
        report.get("snapshot_digest") == content_hash(payload),
        "the GATE-07 candidate snapshot digest does not match",
    )
    return candidates, comparison


def _run_evidence(
    evidence_dir: Path,
    journey: Mapping[str, Any],
) -> tuple[Mapping[str, str], EvidenceRecord]:
    _require(
        set(journey)
        == {
            "schema_version",
            "core_passed",
            "browser_pending",
            "run_id",
            "run_bundle",
            "observed_evidence_id",
            "roles",
            "states",
            "service_operations",
            "comparison_id",
        }
        and journey.get("schema_version") == JOURNEY_SCHEMA
        and journey.get("core_passed") is True
        and journey.get("browser_pending") is False,
        "the GATE-07 journey report has the wrong schema or status",
    )
    run_id = journey.get("run_id")
    bundle = journey.get("run_bundle")
    _require(
        isinstance(run_id, str)
        and isinstance(bundle, Mapping)
        and set(bundle) == {"run_id", "path"}
        and bundle.get("run_id") == run_id
        and bundle.get("path") == f"runs/{run_id}",
        "the GATE-07 journey has an invalid run-bundle reference",
    )
    run_id = cast(str, run_id)
    bundle = cast(Mapping[str, Any], bundle)
    store = RunStore(evidence_dir / "runs")
    try:
        validation = store.validate_bundle(run_id)
        run = store.get_run(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise DetectionGateValidationError(
            "the GATE-07 observed run bundle failed validation"
        ) from exc
    _require(
        validation.get("valid") is True
        and run.get("run_id") == run_id
        and run.get("status") == "completed"
        and isinstance(run.get("manifest"), Mapping),
        "the GATE-07 observed run is not a finalized valid bundle",
    )
    evidence = _mapping(run.get("evidence"), "the GATE-07 observed evidence is absent")
    rows = evidence.get("records")
    _require(
        isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], Mapping),
        "the GATE-07 observed run must contain exactly one evidence record",
    )
    rows = cast(list[Any], rows)
    try:
        record = EvidenceRecord.from_mapping(rows[0])
    except (EvidenceError, TypeError, ValueError) as exc:
        raise DetectionGateValidationError(
            "the GATE-07 observed evidence failed strict rehydration"
        ) from exc
    _require(
        record.run_id == run_id
        and record.evidence_id == journey.get("observed_evidence_id")
        and record.provenance is EvidenceProvenance.OBSERVED,
        "the GATE-07 observed evidence binding does not match the journey",
    )
    return {"run_id": run_id, "path": str(bundle["path"])}, record


def _query_execution(
    candidate: DetectionCandidate,
    observed: EvidenceRecord,
) -> tuple[
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
]:
    rule_source = candidate.rule_source
    _require(
        candidate.state.value == "benign_evaluated"
        and rule_source is not None
        and candidate.validation.get("source_rule_executed") is True,
        f"the {candidate.target_language} candidate did not reach executed benign evaluation",
    )
    rule_source = cast(str, rule_source)
    if candidate.target_language == "sigma":
        conversion = convert_sigma_to_sqlite(rule_source)
        query = str(conversion["converted_query"])
        digest = conversion["query_sha256"]
        backend_details = conversion
        _require(
            rule_source == SIGMA_SOURCE
            and candidate.parser_backend.get("name") == "pySigma"
            and candidate.parser_backend.get("conversion_backend") == "pySigma SQLite"
            and candidate.parser_backend
            == {
                "name": "pySigma",
                "version": "1.5.0",
                "conversion_backend": "pySigma SQLite",
                "conversion_backend_version": "1.2.2",
            }
            and candidate.validation.get("backend") == "pySigma"
            and candidate.validation.get("version") == "1.5.0"
            and candidate.validation.get("conversion_backend") == "pySigma SQLite"
            and candidate.validation.get("conversion_backend_version") == "1.2.2"
            and candidate.validation.get("source_sha256") == _sha256_text(rule_source)
            and candidate.validation.get("query_sha256") == digest
            and candidate.validation.get("converted_query") == query,
            "the Sigma candidate is not bound to a fresh pySigma backend conversion",
        )
    elif candidate.target_language == "sqlite":
        inspection = inspect_sqlite_query(rule_source)
        query = str(inspection["query"])
        digest = inspection["query_sha256"]
        backend_details = inspection
        _require(
            rule_source == SQLITE_SOURCE
            and candidate.parser_backend
            == {"name": "SQLite bounded executor", "version": sqlite3.sqlite_version}
            and candidate.validation.get("backend") == "SQLite bounded executor"
            and candidate.validation.get("version") == sqlite3.sqlite_version
            and candidate.validation.get("source_sha256") == _sha256_text(rule_source)
            and candidate.validation.get("query_sha256") == digest,
            "the SQLite candidate is not bound to its freshly inspected query",
        )
    else:
        raise DetectionGateValidationError("a non-query candidate entered query validation")
    malicious = execute_sqlite_query(query, candidate.malicious_fixtures)
    benign = execute_sqlite_query(query, candidate.benign_fixtures)
    observed_fixture = {**dict(observed.content), "fixture_id": observed.evidence_id}
    observed_result = execute_sqlite_query(query, (observed_fixture,))
    _require(
        malicious.get("query_sha256") == digest
        and malicious.get("matched_fixture_ids") == list(candidate.malicious_fixture_ids)
        and benign.get("matched_fixture_ids") == []
        and observed_result.get("matched_fixture_ids") == [observed.evidence_id]
        and candidate.benign_match_count == 0,
        f"the {candidate.target_language} persisted execution claims did not reproduce",
    )
    validation = candidate.validation
    last_execution = _mapping(
        validation.get("last_execution"), "the query last-execution record is absent"
    )
    fresh_fields = list(backend_details["mapped_fields"])
    fresh_mapping = dict(backend_details["field_mapping"])
    fresh_unsupported = list(backend_details["unsupported_fields"])
    _require(
        validation.get("source_rule_executed") is True
        and validation.get("mapped_fields") == fresh_fields
        and validation.get("field_mapping") == fresh_mapping
        and validation.get("unsupported_fields") == fresh_unsupported
        and validation.get("executed_query_sha256") == digest
        and validation.get("execution_backend") == "SQLite in-memory bounded executor"
        and validation.get("execution_backend_version") == sqlite3.sqlite_version
        and validation.get("evaluated_fixture_ids") == list(candidate.malicious_fixture_ids)
        and validation.get("matched_fixture_ids") == list(candidate.malicious_fixture_ids)
        and validation.get("evaluated_evidence_ids") == [observed.evidence_id]
        and validation.get("matched_evidence_ids") == [observed.evidence_id]
        and validation.get("benign_evaluated_fixture_ids") == list(candidate.benign_fixture_ids)
        and validation.get("benign_matched_fixture_ids") == []
        and last_execution.get("sqlite_version") == sqlite3.sqlite_version
        and last_execution.get("query_sha256") == digest
        and last_execution.get("query_only") is True
        and last_execution.get("authorizer") is True
        and isinstance(last_execution.get("limits"), Mapping),
        f"the {candidate.target_language} persisted execution metadata is incomplete",
    )
    _require(
        malicious.get("mapped_fields") == fresh_fields
        and observed_result.get("mapped_fields") == fresh_fields
        and benign.get("mapped_fields") == fresh_fields
        and last_execution == benign,
        f"the {candidate.target_language} field mapping did not reproduce exactly",
    )
    return malicious, observed_result, benign, backend_details


def _yara_execution(candidate: DetectionCandidate) -> bool:
    _require(
        candidate.target_language == "yara"
        and candidate.state.value == "benign_evaluated"
        and candidate.rule_source == YARA_SOURCE
        and candidate.parser_backend == {"name": "YARA-Python", "version": "4.5.4"}
        and candidate.validation.get("backend") == "YARA-Python"
        and candidate.validation.get("version") == "4.5.4"
        and candidate.validation.get("compiled") is True
        and candidate.validation.get("includes") is False
        and candidate.validation.get("warnings_as_errors") is True
        and candidate.validation.get("source_sha256") == _sha256_text(candidate.rule_source)
        and candidate.validation.get("source_rule_executed") is True
        and candidate.validation.get("executed_source_sha256")
        == _sha256_text(candidate.rule_source)
        and candidate.validation.get("execution_backend") == "YARA-Python"
        and candidate.validation.get("execution_backend_version") == "4.5.4"
        and candidate.malicious_fixture_ids == ("yara-malicious",)
        and candidate.benign_fixture_ids == ("yara-benign",)
        and candidate.malicious_fixtures
        == (
            {
                "fixture_id": "yara-malicious",
                "data": "prefix BLUEFIRE_GATE07_MALICIOUS_MARKER suffix",
            },
        )
        and candidate.benign_fixtures
        == ({"fixture_id": "yara-benign", "data": "ordinary benign document"},),
        "the YARA candidate is not a compiled benign-evaluated rule",
    )
    try:
        installed_version = metadata.version("yara-python")
    except metadata.PackageNotFoundError as exc:
        raise DetectionGateValidationError(
            "the pinned YARA-Python distribution is unavailable"
        ) from exc
    _require(
        installed_version == "4.5.4",
        "the installed YARA-Python distribution does not match the reviewed pin",
    )
    try:
        import yara
    except ImportError as exc:
        raise DetectionGateValidationError(
            "the persisted YARA source could not be independently imported"
        ) from exc
    try:
        rules = yara.compile(
            source=candidate.rule_source,
            includes=False,
            error_on_warning=True,
        )
        malicious_matches = [
            fixture["fixture_id"]
            for fixture in candidate.malicious_fixtures
            if rules.match(data=str(fixture["data"]).encode("utf-8"), timeout=2)
        ]
        benign_matches = [
            fixture["fixture_id"]
            for fixture in candidate.benign_fixtures
            if rules.match(data=str(fixture["data"]).encode("utf-8"), timeout=2)
        ]
    except (KeyError, TypeError, yara.Error) as exc:
        raise DetectionGateValidationError(
            "the persisted YARA source could not be independently compiled and executed"
        ) from exc
    return (
        malicious_matches == list(candidate.malicious_fixture_ids)
        and not benign_matches
        and candidate.benign_match_count == 0
        and candidate.validation.get("evaluated_fixture_ids")
        == list(candidate.malicious_fixture_ids)
        and candidate.validation.get("matched_fixture_ids") == list(candidate.malicious_fixture_ids)
        and candidate.validation.get("benign_evaluated_fixture_ids")
        == list(candidate.benign_fixture_ids)
        and candidate.validation.get("benign_matched_fixture_ids") == []
    )


def _notes_and_baseline(candidate: DetectionCandidate) -> bool:
    if not candidate.false_positive_notes or len(candidate.public_baselines) != 1:
        return False
    reference = candidate.public_baselines[0]
    try:
        source = load_builtin_research_registry().get(reference["research_source_id"])
    except (KeyError, ResearchSourceError, TypeError, ValueError):
        return False
    return reference == {
        "schema_version": "bluefire.public-baseline.v2",
        "research_source_id": source.id,
        "source_digest": content_hash(source.to_dict()),
        "pin": source.pin,
        "version": source.version,
        "exact_ref": source.exact_ref,
        "retrieved_at": source.retrieved_at,
        "license": source.license,
        "file_level_license_review": source.file_level_license_review,
        "trademark_considerations": source.trademark_considerations,
        "license_review": source.license_review.value,
        "relationship": source.relationship.value,
        "use_classification": source.use_classification.value,
        "use": "comparison",
        "attribution": source.attribution,
        "security_review": source.security_review,
        "last_verified_at": source.last_verified_at,
        "update_status": source.update_status,
    }


def _lifecycle_check(
    candidates: Mapping[str, DetectionCandidate],
    comparison: Mapping[str, Any],
) -> bool:
    sigma = candidates["sigma"]
    clone = candidates["clone"]
    rejected = candidates["rejected"]
    snapshot = {key: value for key, value in comparison.items() if key != "comparison_id"}
    comparison_id = "detection-comparison-" + content_hash(snapshot).removeprefix("sha256:")[:20]
    sigma_actions = [row.get("action") for row in sigma.lifecycle_history]
    clone_actions = [row.get("action") for row in clone.lifecycle_history]
    rejected_actions = [row.get("action") for row in rejected.lifecycle_history]
    deltas = comparison.get("deltas")
    return (
        clone.revision == 2
        and clone.revision_kind == "clone"
        and clone.parent_candidate_id == sigma.candidate_id
        and rejected.revision == 3
        and rejected.revision_kind == "tune"
        and rejected.parent_candidate_id == clone.candidate_id
        and rejected.state.value == "rejected"
        and sigma.revision_root_id == clone.revision_root_id == rejected.revision_root_id
        and clone_actions == ["revision_clone"]
        and rejected_actions == ["revision_tune", "reject"]
        and sigma_actions
        == [
            "hypothesis_upsert",
            "parse",
            "exercise_fixtures",
            "exercise_observed",
            "evaluate_benign",
        ]
        and comparison.get("comparison_id") == comparison_id
        and comparison.get("revision_root_id") == sigma.candidate_id
        and isinstance(deltas, Mapping)
        and _mapping(deltas.get("rule"), "the comparison rule delta is absent").get("changed")
        is True
        and _mapping(deltas.get("lifecycle"), "the comparison lifecycle delta is absent").get(
            "changed"
        )
        is True
    )


def _browser_check(
    browser: Mapping[str, Any],
    candidate: DetectionCandidate,
) -> bool:
    _require(
        set(browser)
        == {
            "schema_version",
            "production_browser_interaction",
            "demo_mode",
            "origin",
            "candidate_id",
            "visible_state",
            "query_digest",
            "backend",
            "evaluated_fixture_ids",
            "matched_fixture_ids",
            "operation_sequence",
            "observed_at",
        }
        and browser.get("schema_version") == BROWSER_SCHEMA
        and browser.get("production_browser_interaction") is True
        and browser.get("demo_mode") is False,
        "the GATE-07 browser report fields or production status are invalid",
    )
    backend = _mapping(browser.get("backend"), "the browser backend evidence is absent")
    _require(
        set(backend) == {"parser", "parser_version", "execution", "execution_version"},
        "the browser backend evidence fields are not exact",
    )
    _require(
        len(candidate.lifecycle_history) == 3
        and all(isinstance(row, Mapping) for row in candidate.lifecycle_history),
        "the browser-created candidate lifecycle is incomplete",
    )
    final_lifecycle = candidate.lifecycle_history[-1]
    _require(
        isinstance(final_lifecycle.get("recorded_at"), str),
        "the browser-created candidate lifecycle timestamp is absent",
    )
    observed_at = browser.get("observed_at")
    try:
        timestamp = datetime.fromisoformat(str(observed_at).removesuffix("Z") + "+00:00")
        lifecycle_timestamp = datetime.fromisoformat(
            str(final_lifecycle["recorded_at"]).removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise DetectionGateValidationError("the browser observation timestamp is invalid") from exc
    evaluated = browser.get("evaluated_fixture_ids")
    matched = browser.get("matched_fixture_ids")
    validation = candidate.validation
    try:
        inspection = inspect_sqlite_query(str(candidate.rule_source))
        reproduced = execute_sqlite_query(str(inspection["query"]), candidate.malicious_fixtures)
    except DetectionBackendError as exc:
        raise DetectionGateValidationError(
            "the browser-created SQLite candidate did not independently re-execute"
        ) from exc
    return bool(
        isinstance(browser.get("origin"), str)
        and _LOOPBACK_ORIGIN.fullmatch(str(browser["origin"])) is not None
        and timestamp.tzinfo == timezone.utc
        and lifecycle_timestamp.tzinfo == timezone.utc
        and lifecycle_timestamp <= timestamp <= datetime.now(timezone.utc)
        and candidate.target_language == "sqlite"
        and candidate.rule_source == SQLITE_SOURCE
        and candidate.state.value == "fixture_exercised"
        and browser.get("candidate_id") == candidate.candidate_id
        and browser.get("visible_state") == candidate.state.value
        and isinstance(browser.get("query_digest"), str)
        and _SHA256.fullmatch(str(browser["query_digest"])) is not None
        and browser.get("query_digest") == validation.get("query_sha256")
        and browser.get("query_digest") == validation.get("executed_query_sha256")
        and browser.get("query_digest") == inspection.get("query_sha256")
        and backend.get("parser") == candidate.parser_backend.get("name")
        and backend.get("parser") == "SQLite bounded executor"
        and backend.get("parser_version") == candidate.parser_backend.get("version")
        and isinstance(backend.get("parser_version"), str)
        and bool(backend.get("parser_version"))
        and backend.get("execution") == validation.get("execution_backend")
        and backend.get("execution") == "SQLite in-memory bounded executor"
        and backend.get("execution_version") == validation.get("execution_backend_version")
        and isinstance(backend.get("execution_version"), str)
        and bool(backend.get("execution_version"))
        and isinstance(evaluated, list)
        and len(evaluated) == 1
        and isinstance(evaluated[0], str)
        and _FIXTURE_ID.fullmatch(evaluated[0]) is not None
        and matched == evaluated
        and validation.get("evaluated_fixture_ids") == evaluated
        and validation.get("matched_fixture_ids") == matched
        and list(candidate.malicious_fixture_ids) == matched
        and reproduced.get("matched_fixture_ids") == matched
        and validation.get("source_rule_executed") is True
        and browser.get("operation_sequence") == list(BROWSER_OPERATION_SEQUENCE)
        and [row.get("action") for row in candidate.lifecycle_history]
        == ["hypothesis_upsert", "parse", "exercise_fixtures"]
    )


def _management_check(
    repository: Path,
    evidence_dir: Path,
    report: Mapping[str, Any],
    browser: Mapping[str, Any],
    candidates: Mapping[str, DetectionCandidate],
    comparison: Mapping[str, Any],
) -> bool:
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "shared_product_store",
            "service",
            "api",
            "cli",
            "ui",
            "browser_report",
        }
        and report.get("schema_version") == MANAGEMENT_SCHEMA
        and report.get("browser_report") == BROWSER_REPORT,
        "the GATE-07 management report has the wrong schema",
    )
    browser_candidate = candidates["browser"]
    store = _mapping(report.get("shared_product_store"), "shared product-store proof is absent")
    service = _mapping(report.get("service"), "service management proof is absent")
    api = _mapping(report.get("api"), "API management proof is absent")
    cli = _mapping(report.get("cli"), "CLI management proof is absent")
    ui = _mapping(report.get("ui"), "UI management proof is absent")
    _require(
        set(service) == {"operations", "candidate_ids"}
        and set(api)
        == {
            "session_authenticated",
            "loopback_origin",
            "candidate_status",
            "candidate_id",
            "candidate_definition_digest",
            "browser_candidate_status",
            "browser_candidate_id",
            "browser_candidate_definition_digest",
            "comparison_status",
            "comparison_id",
        }
        and set(cli)
        == {
            "exit_code",
            "command",
            "candidate_id",
            "candidate_definition_digest",
            "stderr_empty",
        }
        and set(ui)
        == {
            "production_assets_served",
            "root_status",
            "shell_sha256",
            "browser_interaction_claimed",
        },
        "the GATE-07 nested management report fields are not exact",
    )
    expected_ids = sorted(candidate.candidate_id for candidate in candidates.values())
    derived_api, derived_cli = validate_management_surfaces(
        repository,
        evidence_dir,
        store,
        candidates,
        comparison,
    )
    packaged_index = repository / "bluefire" / "ui" / "index.html"
    _require(
        packaged_index.is_file()
        and not packaged_index.is_symlink()
        and 0 < packaged_index.stat().st_size <= 1024 * 1024,
        "the committed packaged UI shell is absent, unsafe, or unbounded",
    )
    packaged_shell_digest = "sha256:" + hashlib.sha256(packaged_index.read_bytes()).hexdigest()
    core = (
        service.get("operations") == list(_SERVICE_OPERATIONS)
        and service.get("candidate_ids") == expected_ids
        and api == derived_api
        and cli == derived_cli
        and ui.get("production_assets_served") is True
        and ui.get("root_status") == 200
        and ui.get("shell_sha256") == packaged_shell_digest
        and ui.get("browser_interaction_claimed") is False
    )
    browser_complete = _browser_check(browser, browser_candidate)
    _require(
        report.get("passed") is (core and browser_complete),
        "the GATE-07 management status does not match its independently checked evidence",
    )
    return core and browser_complete


def _corruption_check(report: Mapping[str, Any]) -> bool:
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "invalid_queries",
            "refused",
            "sigma_conversion_deterministic",
            "sigma_query_sha256",
        }
        and report.get("schema_version") == CORRUPTION_SCHEMA,
        "the GATE-07 corruption report has the wrong schema",
    )
    queries = _mapping(report.get("invalid_queries"), "invalid-query cases are absent")
    refused = _mapping(report.get("refused"), "invalid-query outcomes are absent")
    _require(
        set(queries) == {"multi_statement", "write_attempt", "foreign_table"}
        and set(refused) == set(queries),
        "the invalid-query inventory is not exact",
    )
    reproduced: dict[str, bool] = {}
    for name, source in queries.items():
        _require(isinstance(source, str), "an invalid-query fixture is not text")
        try:
            inspect_sqlite_query(source)
        except DetectionBackendError:
            reproduced[name] = True
        else:
            reproduced[name] = False
    first = convert_sigma_to_sqlite(SIGMA_SOURCE)
    second = convert_sigma_to_sqlite(SIGMA_SOURCE)
    passed = (
        all(reproduced.values())
        and refused == reproduced
        and first == second
        and report.get("sigma_conversion_deterministic") is True
        and report.get("sigma_query_sha256") == first.get("query_sha256")
    )
    _require(report.get("passed") is passed, "the corruption status is inconsistent")
    return passed


def validate_persisted_detection_gate(
    repository: Path,
    evidence_dir: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    """Rehydrate reports and rerun backend semantics without trusting producer booleans."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(root.is_dir() and destination.is_dir(), "GATE-07 roots must be directories")
    journey = _read_json(destination / JOURNEY_REPORT)
    candidate_report = _read_json(destination / CANDIDATE_REPORT)
    management = _read_json(destination / MANAGEMENT_REPORT)
    corruption = _read_json(destination / CORRUPTION_REPORT)
    browser = _read_json(destination / BROWSER_REPORT)
    candidates, comparison = _candidate_inventory(candidate_report)
    bundle, observed = _run_evidence(destination, journey)
    roles = journey.get("roles")
    states = journey.get("states")
    _require(
        isinstance(roles, Mapping)
        and roles == {role: candidates[role].candidate_id for role in _ALL_ROLES}
        and isinstance(states, Mapping)
        and states == {role: candidates[role].state.value for role in _ALL_ROLES}
        and journey.get("comparison_id") == comparison.get("comparison_id")
        and journey.get("service_operations") == list(_SERVICE_OPERATIONS),
        "the GATE-07 journey bindings do not match the candidate snapshots",
    )
    sigma_malicious, sigma_observed, sigma_benign, sigma_backend = _query_execution(
        candidates["sigma"], observed
    )
    sqlite_malicious, sqlite_observed, sqlite_benign, sqlite_backend = _query_execution(
        candidates["sqlite"], observed
    )
    yara_ok = _yara_execution(candidates["yara"])
    _require(yara_ok, "the YARA execution claims did not reproduce")
    sigma_fields = set(sigma_backend.get("mapped_fields", ()))
    sqlite_fields = set(sqlite_backend.get("mapped_fields", ()))
    field_mapping = (
        {"artifact_type", "path"} <= sigma_fields
        and {"artifact_type", "path"} <= sqlite_fields
        and sigma_backend.get("field_mapping") == {field: field for field in sorted(sigma_fields)}
        and sqlite_backend.get("field_mapping") == {field: field for field in sorted(sqlite_fields)}
        and sigma_backend.get("unsupported_fields") == []
        and sqlite_backend.get("unsupported_fields") == []
        and sigma_malicious.get("mapped_fixture_fields") == ["artifact_type", "path"]
        and sqlite_malicious.get("mapped_fixture_fields") == ["artifact_type", "path"]
        and sigma_observed.get("mapped_fixture_fields") == ["artifact_type", "host.name", "path"]
        and sqlite_observed.get("mapped_fixture_fields") == ["artifact_type", "host.name", "path"]
        and sigma_malicious.get("unsupported_fixture_fields") == []
        and sqlite_malicious.get("unsupported_fixture_fields") == []
        and sigma_observed.get("unsupported_fixture_fields") == []
        and sqlite_observed.get("unsupported_fixture_fields") == []
        and sigma_benign.get("unsupported_fixture_fields") == ["unmodeled_signal"]
        and sqlite_benign.get("unsupported_fixture_fields") == ["unmodeled_signal"]
        and candidates["sigma"].field_drift
        == {
            "intersection": ("artifact_type", "path"),
            "observed_only": ("host.name",),
            "predicted_only": ("user.name",),
        }
    )
    sigma_history = candidates["sigma"].lifecycle_history
    sqlite_history = candidates["sqlite"].lifecycle_history
    observed_lifecycle_bound = (
        len(sigma_history) > 3
        and len(sqlite_history) > 3
        and isinstance(sigma_history[3], Mapping)
        and isinstance(sqlite_history[3], Mapping)
        and sigma_history[3].get("run_id") == observed.run_id
        and sqlite_history[3].get("run_id") == observed.run_id
    )
    corruption_ok = _corruption_check(corruption)
    checks = {
        "sigma_backend": bool(
            sigma_malicious.get("matched_fixture_ids")
            and sigma_observed.get("matched_fixture_ids") == [observed.evidence_id]
            and sigma_benign.get("matched_fixture_ids") == []
        ),
        "yara_execution": yara_ok,
        "query_validation": bool(
            sqlite_malicious.get("matched_fixture_ids")
            and sqlite_observed.get("matched_fixture_ids") == [observed.evidence_id]
            and sqlite_benign.get("matched_fixture_ids") == []
            and corruption_ok
        ),
        "observed_evaluation": bool(
            candidates["sigma"].observed_evidence_ids == (observed.evidence_id,)
            and candidates["sqlite"].observed_evidence_ids == (observed.evidence_id,)
            and observed_lifecycle_bound
        ),
        "field_mapping": field_mapping,
        "notes_baseline": _notes_and_baseline(candidates["sigma"]),
        "lifecycle": _lifecycle_check(candidates, comparison),
        "management_parity": _management_check(
            root, destination, management, browser, candidates, comparison
        ),
        "three_executed_candidates": bool(
            candidates["sigma"].state.value == "benign_evaluated"
            and candidates["yara"].state.value == "benign_evaluated"
            and candidates["sqlite"].state.value == "benign_evaluated"
            and candidates["sigma"].validation.get("source_rule_executed") is True
            and candidates["sqlite"].validation.get("source_rule_executed") is True
            and yara_ok
        ),
    }
    _require(set(checks) == CHECK_NAMES, "the GATE-07 semantic check inventory is incomplete")
    return checks, (bundle,)


__all__ = [
    "CHECK_NAMES",
    "DetectionGateValidationError",
    "validate_persisted_detection_gate",
]

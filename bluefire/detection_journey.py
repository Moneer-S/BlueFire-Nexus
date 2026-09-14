"""Production-service evidence journey for the authoritative Detection Lab gate."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .api import (
    BROWSER_BOOTSTRAP_HEADER,
    browser_console_url,
    create_server,
    generate_browser_bootstrap_capability,
)
from .detection_backends import (
    DetectionBackendError,
    convert_sigma_to_sqlite,
    inspect_sqlite_query,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .runner_lifecycle import ManagedRunnerLifecycle
from .service import BlueFireService
from .util import canonical_json_bytes, content_hash

JOURNEY_REPORT = "gate07-journey-report.json"
CANDIDATE_REPORT = "gate07-candidate-report.json"
MANAGEMENT_REPORT = "gate07-management-report.json"
CORRUPTION_REPORT = "gate07-corruption-report.json"
BROWSER_REPORT = "gate07-browser-report.json"
PRODUCT_DB_ARTIFACT = "runs/bluefire-product.sqlite3"
REPORT_PATHS = (
    JOURNEY_REPORT,
    CANDIDATE_REPORT,
    MANAGEMENT_REPORT,
    CORRUPTION_REPORT,
    BROWSER_REPORT,
)
HELPER_SCHEMA = "bluefire.gate-07-helper.v1"
JOURNEY_SCHEMA = "bluefire.detection-gate-journey.v1"
CANDIDATE_SCHEMA = "bluefire.detection-gate-candidates.v1"
MANAGEMENT_SCHEMA = "bluefire.detection-gate-management.v1"
CORRUPTION_SCHEMA = "bluefire.detection-gate-corruption.v1"
BROWSER_SCHEMA = "bluefire.detection-production-browser.v1"

BROWSER_OPERATION_SEQUENCE = (
    "bootstrap_production_session",
    "open_detection_lab",
    "verify_sqlite_backend",
    "create_sqlite_hypothesis",
    "parse_sqlite_query",
    "execute_malicious_fixture",
    "reload_and_verify_persisted_state",
)

SIGMA_SOURCE = """title: Gate 07 staged artifact
id: 0cd9b580-272b-4c48-a463-3c2032a29a11
status: test
description: Detect the bounded staged-file acceptance fixture.
logsource:
  category: file_event
  product: linux
detection:
  selection:
    artifact_type: file_observation
    path|contains: staged/
  condition: selection
"""
SQLITE_SOURCE = (
    "SELECT * FROM logs WHERE artifact_type = 'file_observation' AND path LIKE '%staged/%'"
)
YARA_SOURCE = """rule bluefire_gate07_staged_marker {
  strings:
    $marker = "BLUEFIRE_GATE07_MALICIOUS_MARKER" ascii
  condition:
    $marker
}
"""

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_DETECTION_ID = re.compile(r"^detection-[0-9a-f]{20}$")


class DetectionJourneyError(ValueError):
    """Raised when production Detection Lab evidence cannot be established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DetectionJourneyError(message)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    _require(
        path.parent.is_dir() and not path.exists() and len(payload) <= _MAX_REPORT_BYTES,
        "a GATE-07 report path is stale or exceeds its byte bound",
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-07 report write made no progress")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _candidate(response: Mapping[str, Any]) -> Mapping[str, Any]:
    resource = response.get("candidate")
    document = resource.get("document") if isinstance(resource, Mapping) else None
    if not isinstance(document, Mapping):
        raise DetectionJourneyError("a Detection Lab response omitted its candidate")
    candidate_id = document.get("candidate_id")
    _require(
        isinstance(candidate_id, str) and _DETECTION_ID.fullmatch(candidate_id) is not None,
        "a Detection Lab response returned an invalid candidate identifier",
    )
    return dict(document)


def _baseline(service: BlueFireService) -> Mapping[str, str]:
    resource = service.resource("research_source", "research.atomic-red-team.v1")["resource"]
    _require(isinstance(resource, Mapping), "the pinned comparison source is absent")
    document = resource.get("document")
    _require(isinstance(document, Mapping), "the pinned comparison source is invalid")
    return {
        "schema_version": "bluefire.public-baseline.v2",
        "research_source_id": str(resource["id"]),
        "source_digest": str(resource["digest"]),
        "pin": str(document["pin"]),
        "version": str(document["version"]),
        "exact_ref": str(document["exact_ref"]),
        "retrieved_at": str(document["retrieved_at"]),
        "license": str(document["license"]),
        "file_level_license_review": str(document["file_level_license_review"]),
        "trademark_considerations": str(document["trademark_considerations"]),
        "license_review": str(document["license_review"]),
        "relationship": str(document["relationship"]),
        "use_classification": str(document["use_classification"]),
        "use": "comparison",
        "attribution": str(document["attribution"]),
        "security_review": str(document["security_review"]),
        "last_verified_at": str(document["last_verified_at"]),
        "update_status": str(document["update_status"]),
    }


def _hypothesis(
    language: str,
    title: str,
    *,
    baseline: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    request: dict[str, Any] = {
        "behavior_id": "sandbox.collection.stage.v1",
        "title": title,
        "target_language": language,
        "logsource": {"category": "file_event", "product": "linux"},
        "selection": {
            "artifact_type": "file_observation",
            "path|contains": "staged/",
        },
        "provenance": {
            "source": "gate-07-reviewed-local-fixture",
            "license": "Apache-2.0",
        },
        "known_misses": ["Requires a normalized file-observation path."],
        "predicted_fields": ["artifact_type", "path", "user.name"],
    }
    if baseline is not None:
        request["public_baselines"] = [dict(baseline)]
    return request


def _create_observed_run(service: BlueFireService) -> tuple[str, EvidenceRecord]:
    handle = service.store.create_run(
        scenario={
            "schema_version": "bluefire.detection-observed-fixture.v1",
            "id": "scenario.gate-07.observed-evidence.v1",
        },
        plan={"schema_version": "bluefire.detection-observed-plan.v1", "steps": ["stage"]},
        policy={
            "schema_version": "bluefire.detection-observed-policy.v1",
            "scope_refs": ["sandbox.workspace"],
        },
        profile={"id": "profile.gate-07.observer.v1", "environment": "disposable"},
    )
    record = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="gate-07-observer.v1",
        runner_profile_id="profile.gate-07.observer.v1",
        environment={"environment_type": "disposable", "platform": "acceptance"},
        content={
            "artifact_type": "file_observation",
            "path": "staged/observed-gate07.txt",
            "host.name": "gate07-observed-host",
        },
        target_scope_ref="runner-profile:profile.gate-07.observer.v1",
    )
    service.store.finalize(
        handle.run_id,
        result={
            "schema_version": "bluefire.detection-observed-result.v1",
            "status": "completed",
            "objective_reached": True,
        },
        evidence=[record.to_dict()],
        detections=[],
    )
    _require(
        service.store.validate_bundle(handle.run_id).get("valid") is True,
        "the observed-evidence run bundle failed final validation",
    )
    return handle.run_id, record


def _query_lifecycle(
    service: BlueFireService,
    *,
    language: str,
    title: str,
    source: str,
    run_id: str,
    evidence_id: str,
    baseline: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    created = _candidate(
        service.upsert_detection_hypothesis(_hypothesis(language, title, baseline=baseline))
    )
    candidate_id = str(created["candidate_id"])
    parsed = _candidate(service.parse_detection_candidate(candidate_id, {"source": source}))
    _require(parsed.get("state") == "parsed", f"the {language} source was not parsed")
    exercised = _candidate(
        service.exercise_detection_fixtures(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": f"{language}-malicious",
                        "artifact_type": "file_observation",
                        "path": f"staged/{language}-malicious.txt",
                    }
                ]
            },
        )
    )
    _require(
        exercised.get("state") == "fixture_exercised",
        f"the {language} query did not execute against its malicious fixture",
    )
    observed = _candidate(
        service.exercise_detection_observed(
            candidate_id,
            {"run_id": run_id, "evidence_ids": [evidence_id]},
        )
    )
    _require(
        observed.get("state") == "observed_exercised",
        f"the {language} query did not match immutable observed evidence",
    )
    evaluated = _candidate(
        service.evaluate_detection_benign(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": f"{language}-benign",
                        "artifact_type": "file_observation",
                        "path": f"documents/{language}-benign.txt",
                        "unmodeled_signal": "reported-not-promoted",
                    }
                ],
                "notes": [f"Reviewed {language} benign fixture did not match."],
            },
        )
    )
    _require(
        evaluated.get("state") == "benign_evaluated",
        f"the {language} query did not complete benign evaluation",
    )
    return evaluated


def _yara_lifecycle(service: BlueFireService) -> Mapping[str, Any]:
    created = _candidate(
        service.upsert_detection_hypothesis(_hypothesis("yara", "Gate 07 YARA marker"))
    )
    candidate_id = str(created["candidate_id"])
    parsed = _candidate(service.parse_detection_candidate(candidate_id, {"source": YARA_SOURCE}))
    _require(parsed.get("state") == "parsed", "the YARA rule did not compile")
    exercised = _candidate(
        service.exercise_detection_fixtures(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "yara-malicious",
                        "data": "prefix BLUEFIRE_GATE07_MALICIOUS_MARKER suffix",
                    }
                ]
            },
        )
    )
    _require(
        exercised.get("state") == "fixture_exercised",
        "the compiled YARA rule did not match its malicious fixture",
    )
    evaluated = _candidate(
        service.evaluate_detection_benign(
            candidate_id,
            {
                "fixtures": [{"fixture_id": "yara-benign", "data": "ordinary benign document"}],
                "notes": ["Reviewed YARA benign fixture did not match."],
            },
        )
    )
    _require(
        evaluated.get("state") == "benign_evaluated",
        "the compiled YARA rule did not complete benign evaluation",
    )
    return evaluated


def _lifecycle_revisions(
    service: BlueFireService,
    root: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    root_id = str(root["candidate_id"])
    clone = _candidate(
        service.clone_detection_candidate(
            root_id,
            {"reason": "Create a reviewed Gate 07 revision."},
        )
    )
    tuned = _candidate(
        service.tune_detection_candidate(
            str(clone["candidate_id"]),
            {
                "reason": "Narrow the reviewed revision to the archive path.",
                "selection": {
                    "artifact_type": "file_observation",
                    "path|contains": "archive/",
                },
                "predicted_fields": ["artifact_type", "path", "host.name"],
            },
        )
    )
    rejected = _candidate(
        service.reject_detection_candidate(
            str(tuned["candidate_id"]),
            {
                "reason": "The narrowed revision misses the maintained staged fixture.",
                "notes": ["Retain the root candidate as the reviewed baseline."],
            },
        )
    )
    comparison = service.compare_detection_candidates(
        root_id,
        {"candidate_id": str(rejected["candidate_id"])},
    )
    _require(
        rejected.get("state") == "rejected"
        and isinstance(comparison, Mapping)
        and comparison.get("revision_root_id") == root_id,
        "the clone/tune/reject comparison lifecycle is incomplete",
    )
    return clone, rejected, dict(comparison)


def _http_request(
    port: int,
    method: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, Mapping[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    payload = None if body is None else canonical_json_bytes(body)
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if method == "POST":
        request_headers["Origin"] = f"http://127.0.0.1:{port}"
    connection.request(method, path, body=payload, headers=request_headers)
    response = connection.getresponse()
    data = response.read(1024 * 1024 + 1)
    response_headers = {name: value for name, value in response.getheaders()}
    status = response.status
    connection.close()
    _require(len(data) <= 1024 * 1024, "a management API response exceeded its byte bound")
    return status, response_headers, data


def _json_response(payload: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DetectionJourneyError("a management response was not JSON") from exc
    if not isinstance(value, Mapping):
        raise DetectionJourneyError("a management response was not an object")
    return value


def _api_evidence(
    service: BlueFireService,
    sigma: Mapping[str, Any],
    rejected: Mapping[str, Any],
    browser_candidate: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service,
        browser_bootstrap_capability=capability,
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cookie = ""
    try:
        port = int(server.server_address[1])
        status, headers, payload = _http_request(
            port,
            "POST",
            "/api/v1/session",
            headers={BROWSER_BOOTSTRAP_HEADER: capability},
        )
        _require(status == 204 and payload == b"", "the API session exchange failed")
        cookie = headers.get("Set-Cookie", "").split(";", 1)[0]
        _require(cookie.startswith("bluefire_session="), "the API session cookie is absent")
        auth = {"Cookie": cookie}
        sigma_id = str(sigma["candidate_id"])
        status, _headers, payload = _http_request(
            port,
            "GET",
            f"/api/v1/detections/{sigma_id}",
            headers=auth,
        )
        api_candidate = _candidate(_json_response(payload))
        _require(
            status == 200 and api_candidate == sigma,
            "the API did not rehydrate the persisted Sigma candidate",
        )
        browser_id = str(browser_candidate["candidate_id"])
        browser_status, _headers, payload = _http_request(
            port,
            "GET",
            f"/api/v1/detections/{browser_id}",
            headers=auth,
        )
        api_browser_candidate = _candidate(_json_response(payload))
        _require(
            browser_status == 200 and api_browser_candidate == browser_candidate,
            "the API did not rehydrate the browser-created SQLite candidate",
        )
        status, _headers, payload = _http_request(
            port,
            "POST",
            f"/api/v1/detections/{sigma_id}/compare",
            body={"candidate_id": str(rejected["candidate_id"])},
            headers=auth,
        )
        api_comparison = _json_response(payload)
        _require(
            status == 200 and api_comparison.get("revision_root_id") == sigma_id,
            "the API comparison route did not use the persisted lineage",
        )
        ui_status, _headers, ui_payload = _http_request(port, "GET", "/")
        _require(
            ui_status == 200 and b"<!doctype html" in ui_payload.lower(),
            "the production UI shell was not served",
        )
        api = {
            "session_authenticated": True,
            "loopback_origin": True,
            "candidate_status": status if status != 200 else 200,
            "candidate_id": sigma_id,
            "candidate_definition_digest": sigma["definition_digest"],
            "browser_candidate_status": browser_status,
            "browser_candidate_id": browser_id,
            "browser_candidate_definition_digest": browser_candidate["definition_digest"],
            "comparison_status": status,
            "comparison_id": api_comparison["comparison_id"],
        }
        ui = {
            "production_assets_served": True,
            "root_status": ui_status,
            "shell_sha256": "sha256:" + hashlib.sha256(ui_payload).hexdigest(),
            "browser_interaction_claimed": False,
        }
        return api, ui
    finally:
        capability = ""
        cookie = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _cli_evidence(
    repository: Path,
    run_root: Path,
    sigma: Mapping[str, Any],
) -> Mapping[str, Any]:
    cli_home = run_root / ".gate07-cli-home"
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": os.fspath(cli_home),
            "USERPROFILE": os.fspath(cli_home),
            "LOCALAPPDATA": os.fspath(cli_home),
            "XDG_STATE_HOME": os.fspath(cli_home),
        }
    )
    command = [
        sys.executable,
        "-B",
        "-m",
        "bluefire.cli",
        "--runs-dir",
        os.fspath(run_root),
        "detections",
        "detail",
        str(sigma["candidate_id"]),
    ]
    completed = subprocess.run(
        command,
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    _require(
        len(completed.stdout) <= 1024 * 1024 and len(completed.stderr) <= 64 * 1024,
        "the CLI response exceeded its byte bound",
    )
    _require(not cli_home.exists(), "the CLI created unexpected unmanaged state")
    response = _json_response(completed.stdout)
    cli_candidate = _candidate(response)
    _require(
        completed.returncode == 0 and cli_candidate == sigma,
        "the CLI did not rehydrate the shared persisted Sigma candidate",
    )
    return {
        "exit_code": completed.returncode,
        "command": [
            "{python}",
            "-B",
            "-m",
            "bluefire.cli",
            "--runs-dir",
            "{gate-runs}",
            "detections",
            "detail",
            "{candidate-id}",
        ],
        "candidate_id": sigma["candidate_id"],
        "candidate_definition_digest": sigma["definition_digest"],
        "stderr_empty": completed.stderr == b"",
    }


def _node_binary() -> Path:
    raw = os.environ.get("BLUEFIRE_GATE_NODE") or shutil.which("node")
    if not isinstance(raw, str) or not raw:
        raise DetectionJourneyError("the pinned Gate 07 Node runtime is unavailable")
    node = Path(raw).resolve(strict=True)
    _require(node.is_file(), "the pinned Gate 07 Node runtime is invalid")
    return node


def _run_node(
    node: Path,
    arguments: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> None:
    completed = subprocess.run(
        [os.fspath(node), *arguments],
        cwd=repository,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )
    _require(
        len(completed.stdout) <= 256 * 1024 and len(completed.stderr) <= 256 * 1024,
        "a Gate 07 Node process exceeded its output bound",
    )
    _require(completed.returncode == 0, "a Gate 07 production browser process failed")


def _browser_evidence(
    repository: Path,
    destination: Path,
    service: BlueFireService,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Exercise the committed packaged UI with the fixed Playwright wrapper once."""

    node = _node_binary()
    wrapper = repository / "tools" / "run_detection_browser_journey.mjs"
    ui_root = repository / "bluefire" / "ui"
    expected_assets = {
        "index.html": 1024 * 1024,
        "app.js": 8 * 1024 * 1024,
        "styles.css": 2 * 1024 * 1024,
    }
    _require(
        ui_root.is_dir()
        and not ui_root.is_symlink()
        and wrapper.is_file()
        and not wrapper.is_symlink(),
        "the packaged production UI or browser harness is absent",
    )
    try:
        entries = {entry.name: entry for entry in ui_root.iterdir()}
    except OSError as exc:
        raise DetectionJourneyError("the packaged production UI is unreadable") from exc
    _require(
        set(entries) == set(expected_assets),
        "the packaged production UI asset inventory is not exact",
    )
    for name, maximum in expected_assets.items():
        asset = entries[name]
        _require(
            asset.is_file()
            and not asset.is_symlink()
            and asset.resolve(strict=True).parent == ui_root.resolve(strict=True)
            and 0 < asset.stat().st_size <= maximum,
            "a packaged production UI asset is absent, unsafe, or unbounded",
        )
    index_payload = entries["index.html"].read_bytes()
    _require(
        b"/ui/app.js" in index_payload and b"/ui/styles.css" in index_payload,
        "the packaged production UI shell does not bind its committed assets",
    )
    report_path = destination / BROWSER_REPORT
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service,
        browser_bootstrap_capability=capability,
        host="127.0.0.1",
        port=0,
        ui_root=ui_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(server.server_address[1])
        launch_url = browser_console_url("127.0.0.1", port, capability)
        browser_environment = dict(os.environ)
        browser_environment.update(
            {
                "BLUEFIRE_PRODUCTION_URL": launch_url,
                "VITE_DEMO_MODE": "false",
            }
        )
        _run_node(
            node,
            [os.fspath(wrapper), "--report", os.fspath(report_path)],
            repository=repository,
            environment=browser_environment,
            timeout_seconds=150,
        )
    finally:
        capability = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    _require(report_path.is_file() and not report_path.is_symlink(), "browser report is absent")
    browser = _json_response(report_path.read_bytes())
    candidate_id = browser.get("candidate_id")
    _require(
        browser.get("schema_version") == BROWSER_SCHEMA
        and browser.get("production_browser_interaction") is True
        and isinstance(candidate_id, str)
        and _DETECTION_ID.fullmatch(candidate_id) is not None,
        "the production browser report did not identify a completed candidate",
    )
    candidate_id = cast(str, candidate_id)
    candidate = _candidate(service.detection_candidate(candidate_id))
    _require(
        candidate.get("state") == "fixture_exercised"
        and candidate.get("target_language") == "sqlite",
        "the browser-created candidate was not rehydrated from the shared ProductStore",
    )
    return browser, candidate


def _corruption_evidence() -> Mapping[str, Any]:
    cases = {
        "multi_statement": "SELECT * FROM logs; SELECT * FROM logs",
        "write_attempt": "DELETE FROM logs",
        "foreign_table": "SELECT * FROM sqlite_master",
    }
    refused: dict[str, bool] = {}
    for name, source in cases.items():
        try:
            inspect_sqlite_query(source)
        except DetectionBackendError:
            refused[name] = True
        else:
            refused[name] = False
    first = convert_sigma_to_sqlite(SIGMA_SOURCE)
    second = convert_sigma_to_sqlite(SIGMA_SOURCE)
    return {
        "schema_version": CORRUPTION_SCHEMA,
        "passed": all(refused.values()) and first == second,
        "invalid_queries": cases,
        "refused": refused,
        "sigma_conversion_deterministic": first == second,
        "sigma_query_sha256": first.get("query_sha256"),
    }


def _product_database_artifact(run_root: Path) -> Mapping[str, Any]:
    database = run_root / "bluefire-product.sqlite3"
    for suffix in ("-shm", "-wal"):
        sidecar = run_root / (database.name + suffix)
        _require(not sidecar.exists(), "the persisted ProductStore has an unsafe sidecar")
    _require(
        database.is_file() and not database.is_symlink(),
        "the persisted shared ProductStore is absent or unsafe",
    )
    payload = database.read_bytes()
    _require(0 < len(payload) <= 64 * 1024 * 1024, "the shared ProductStore exceeds its bound")
    return {
        "path": PRODUCT_DB_ARTIFACT,
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def produce_detection_gate_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    """Exercise the real production UI, service, API, CLI, and shared store."""

    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(root.is_dir() and destination.is_dir(), "GATE-07 roots must be directories")
    _require(
        all(not (destination / name).exists() for name in REPORT_PATHS),
        "GATE-07 evidence contains stale owned artifacts",
    )
    run_root = destination / "runs"
    run_root.mkdir(mode=0o700, exist_ok=False)
    service = BlueFireService(
        project_root=root,
        runs_dir=run_root,
        runner_lifecycle=ManagedRunnerLifecycle(destination / ".gate07-managed-runner"),
    )
    reports: tuple[Mapping[str, Any], ...] | None = None
    management_report: dict[str, Any] | None = None
    try:
        run_id, observed = _create_observed_run(service)
        baseline = _baseline(service)
        sigma = _query_lifecycle(
            service,
            language="sigma",
            title="Gate 07 Sigma staged artifact",
            source=SIGMA_SOURCE,
            run_id=run_id,
            evidence_id=observed.evidence_id,
            baseline=baseline,
        )
        sqlite = _query_lifecycle(
            service,
            language="sqlite",
            title="Gate 07 bounded SQLite staged artifact",
            source=SQLITE_SOURCE,
            run_id=run_id,
            evidence_id=observed.evidence_id,
        )
        yara = _yara_lifecycle(service)
        clone, rejected, comparison = _lifecycle_revisions(service, sigma)
        _browser, browser_candidate = _browser_evidence(root, destination, service)
        candidates = {
            "sigma": sigma,
            "yara": yara,
            "sqlite": sqlite,
            "clone": clone,
            "rejected": rejected,
            "browser": browser_candidate,
        }
        listed = service.detection_candidates().get("candidates")
        if not isinstance(listed, list):
            raise DetectionJourneyError("the persisted Detection Lab list is invalid")
        listed_ids = sorted(
            str(resource.get("id")) for resource in listed if isinstance(resource, Mapping)
        )
        expected_ids = sorted(str(row["candidate_id"]) for row in candidates.values())
        _require(listed_ids == expected_ids, "the persisted candidate inventory is incomplete")
        api, ui = _api_evidence(service, sigma, rejected, browser_candidate)
        cli = _cli_evidence(root, run_root, sigma)
        service_operations = [
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
        ]
        candidate_payload = {"candidates": candidates, "comparison": comparison}
        candidate_report = {
            "schema_version": CANDIDATE_SCHEMA,
            "passed": True,
            **candidate_payload,
            "listed_candidate_ids": listed_ids,
            "snapshot_digest": content_hash(candidate_payload),
        }
        journey_report = {
            "schema_version": JOURNEY_SCHEMA,
            "core_passed": True,
            "browser_pending": False,
            "run_id": run_id,
            "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
            "observed_evidence_id": observed.evidence_id,
            "roles": {role: row["candidate_id"] for role, row in candidates.items()},
            "states": {role: row["state"] for role, row in candidates.items()},
            "service_operations": service_operations,
            "comparison_id": comparison["comparison_id"],
        }
        management_report = {
            "schema_version": MANAGEMENT_SCHEMA,
            "passed": True,
            "shared_product_store": {
                "path": PRODUCT_DB_ARTIFACT,
                "candidate_id": sigma["candidate_id"],
                "candidate_definition_digest": sigma["definition_digest"],
                "browser_candidate_id": browser_candidate["candidate_id"],
                "browser_candidate_definition_digest": browser_candidate["definition_digest"],
                "candidate_count": len(candidates),
            },
            "service": {
                "operations": service_operations,
                "candidate_ids": expected_ids,
            },
            "api": api,
            "cli": cli,
            "ui": ui,
            "browser_report": BROWSER_REPORT,
        }
        corruption_report = _corruption_evidence()
        reports = (
            journey_report,
            candidate_report,
            management_report,
            corruption_report,
        )
    finally:
        service.close()
    _require(
        reports is not None and management_report is not None,
        "GATE-07 evidence production did not complete",
    )
    management_report["shared_product_store"].update(_product_database_artifact(run_root))
    for name, report in zip(REPORT_PATHS[:-1], reports, strict=True):
        _write_json(destination / name, report)
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "passed",
        "reports": list(REPORT_PATHS),
        "run_count": 1,
        "blocking_check": None,
    }


__all__ = [
    "BROWSER_REPORT",
    "BROWSER_SCHEMA",
    "CANDIDATE_REPORT",
    "CANDIDATE_SCHEMA",
    "CORRUPTION_REPORT",
    "CORRUPTION_SCHEMA",
    "DetectionJourneyError",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT",
    "JOURNEY_SCHEMA",
    "MANAGEMENT_REPORT",
    "MANAGEMENT_SCHEMA",
    "PRODUCT_DB_ARTIFACT",
    "REPORT_PATHS",
    "BROWSER_OPERATION_SEQUENCE",
    "SIGMA_SOURCE",
    "SQLITE_SOURCE",
    "YARA_SOURCE",
    "produce_detection_gate_evidence",
]

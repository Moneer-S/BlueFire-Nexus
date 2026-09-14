"""Independent shared-store, API, and CLI revalidation for Detection Gate 07."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping

from .api import BROWSER_BOOTSTRAP_HEADER, create_server, generate_browser_bootstrap_capability
from .detection_journey import PRODUCT_DB_ARTIFACT
from .detections import DetectionCandidate, DetectionError
from .service import BlueFireService
from .util import canonical_json_bytes, content_hash

_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class DetectionManagementValidationError(ValueError):
    """A retained management surface failed independent replay."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DetectionManagementValidationError(message)


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DetectionManagementValidationError(message)
    return value


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_nlink,
    )


def _database_snapshot(
    evidence_dir: Path,
    store: Mapping[str, Any],
    candidates: Mapping[str, DetectionCandidate],
) -> bytes:
    sigma = candidates["sigma"]
    browser = candidates["browser"]
    _require(
        set(store)
        == {
            "path",
            "sha256",
            "size_bytes",
            "candidate_id",
            "candidate_definition_digest",
            "browser_candidate_id",
            "browser_candidate_definition_digest",
            "candidate_count",
        },
        "the shared ProductStore artifact fields are not exact",
    )
    database = evidence_dir / PRODUCT_DB_ARTIFACT
    sidecars = tuple(Path(str(database) + suffix) for suffix in ("-wal", "-shm"))
    _require(
        store.get("path") == PRODUCT_DB_ARTIFACT
        and database.is_file()
        and not database.is_symlink()
        and all(not path.exists() for path in sidecars)
        and isinstance(store.get("size_bytes"), int)
        and not isinstance(store.get("size_bytes"), bool)
        and 0 < int(store["size_bytes"]) <= _MAX_DATABASE_BYTES
        and isinstance(store.get("sha256"), str)
        and _SHA256.fullmatch(str(store["sha256"])) is not None,
        "the shared ProductStore artifact is absent, unsafe, or unbounded",
    )
    path_before = database.stat(follow_symlinks=False)
    _require(
        stat.S_ISREG(path_before.st_mode)
        and path_before.st_nlink == 1
        and path_before.st_size == store["size_bytes"],
        "the shared ProductStore artifact identity is unsafe",
    )
    try:
        with database.open("rb") as stream:
            handle_before = os.fstat(stream.fileno())
            payload = stream.read(_MAX_DATABASE_BYTES + 1)
            handle_after = os.fstat(stream.fileno())
    except OSError as exc:
        raise DetectionManagementValidationError(
            "the ProductStore snapshot could not be read"
        ) from exc
    path_after = database.stat(follow_symlinks=False)
    _require(
        _identity(path_before)
        == _identity(path_after)
        == _identity(handle_before)
        == _identity(handle_after)
        and all(not path.exists() for path in sidecars)
        and len(payload) == store["size_bytes"],
        "the shared ProductStore artifact changed while it was snapshotted",
    )
    digest = hashlib.sha256(payload).hexdigest()
    _require(store.get("sha256") == "sha256:" + digest, "the ProductStore hash does not match")
    temporary_root: Path
    try:
        with tempfile.TemporaryDirectory(prefix=".gate07-db-snapshot-", dir=evidence_dir) as temp:
            temporary_root = Path(temp)
            snapshot = temporary_root / "product.sqlite3"
            snapshot.write_bytes(payload)
            snapshot.chmod(0o600)
            snapshot_before = snapshot.stat(follow_symlinks=False)
            connection = sqlite3.connect(
                snapshot.resolve(strict=True).as_uri() + "?mode=ro&immutable=1",
                uri=True,
            )
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT resource_id, document_json, digest, status "
                    "FROM resources WHERE kind = ? ORDER BY resource_id",
                    ("detection",),
                ).fetchall()
            finally:
                connection.close()
            snapshot_after = snapshot.stat(follow_symlinks=False)
            _require(
                _identity(snapshot_before) == _identity(snapshot_after)
                and hashlib.sha256(snapshot.read_bytes()).hexdigest() == digest,
                "the immutable ProductStore validation snapshot changed",
            )
        _require(not temporary_root.exists(), "the private ProductStore snapshot was retained")
    except (OSError, sqlite3.Error) as exc:
        raise DetectionManagementValidationError(
            "the shared ProductStore snapshot could not be opened immutable"
        ) from exc

    persisted: dict[str, Mapping[str, Any]] = {}
    for resource_id, document_json, resource_digest, status in rows:
        try:
            document = json.loads(document_json)
            candidate = DetectionCandidate.from_mapping(document)
        except (json.JSONDecodeError, DetectionError, TypeError, ValueError) as exc:
            raise DetectionManagementValidationError(
                "a shared ProductStore candidate failed strict rehydration"
            ) from exc
        _require(
            isinstance(document, Mapping)
            and resource_id == candidate.candidate_id
            and resource_digest == content_hash(document)
            and status == candidate.state.value
            and candidate.to_dict() == document,
            "a shared ProductStore candidate binding is invalid",
        )
        persisted[candidate.candidate_id] = document
    expected_documents = {
        candidate.candidate_id: candidate.to_dict() for candidate in candidates.values()
    }
    _require(
        persisted == expected_documents
        and store.get("candidate_count") == len(candidates)
        and store.get("candidate_id") == sigma.candidate_id
        and store.get("candidate_definition_digest") == sigma.definition_digest
        and store.get("browser_candidate_id") == browser.candidate_id
        and store.get("browser_candidate_definition_digest") == browser.definition_digest,
        "the immutable ProductStore snapshot does not match the candidate inventory",
    )
    return payload


def _candidate_document(response: Mapping[str, Any], context: str) -> Mapping[str, Any]:
    _require(
        set(response) == {"schema_version", "candidate"}
        and response.get("schema_version") == "bluefire.detection-resource.v1",
        f"the {context} candidate envelope is invalid",
    )
    resource = _mapping(response.get("candidate"), f"the {context} candidate resource is absent")
    _require(
        set(resource) == {"kind", "id", "status", "digest", "created_at", "updated_at", "document"},
        f"the {context} candidate resource fields are invalid",
    )
    document = _mapping(resource.get("document"), f"the {context} candidate document is absent")
    try:
        candidate = DetectionCandidate.from_mapping(document)
    except (DetectionError, TypeError, ValueError) as exc:
        raise DetectionManagementValidationError(
            f"the {context} candidate failed strict rehydration"
        ) from exc
    _require(
        candidate.to_dict() == document
        and resource.get("kind") == "detection"
        and resource.get("id") == candidate.candidate_id
        and resource.get("status") == candidate.state.value
        and resource.get("digest") == content_hash(document),
        f"the {context} candidate resource binding is invalid",
    )
    return document


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
    try:
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        response_payload = response.read(1024 * 1024 + 1)
        response_headers = {name.casefold(): value for name, value in response.getheaders()}
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise DetectionManagementValidationError(
            "the independent management API replay failed"
        ) from exc
    finally:
        connection.close()
    _require(
        len(response_payload) <= 1024 * 1024,
        "an independent management API response exceeded its byte bound",
    )
    return status, response_headers, response_payload


def _json_response(payload: bytes, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DetectionManagementValidationError(
            f"the {context} replay response is not JSON"
        ) from exc
    return _mapping(value, f"the {context} replay response is not an object")


def _replay(
    repository: Path,
    evidence_dir: Path,
    database_payload: bytes,
    candidates: Mapping[str, DetectionCandidate],
    comparison: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    sigma = candidates["sigma"]
    browser = candidates["browser"]
    rejected = candidates["rejected"]
    temporary_root: Path
    with tempfile.TemporaryDirectory(prefix=".gate07-management-replay-", dir=evidence_dir) as temp:
        temporary_root = Path(temp)
        run_root = temporary_root / "runs"
        run_root.mkdir(mode=0o700)
        database = run_root / "bluefire-product.sqlite3"
        database.write_bytes(database_payload)
        database.chmod(0o600)
        _require(
            hashlib.sha256(database.read_bytes()).digest()
            == hashlib.sha256(database_payload).digest(),
            "the private management replay database copy is invalid",
        )
        service: BlueFireService | None = None
        server = None
        thread: threading.Thread | None = None
        capability = generate_browser_bootstrap_capability()
        try:
            service = BlueFireService(project_root=repository, runs_dir=run_root)
            server = create_server(
                service,
                browser_bootstrap_capability=capability,
                host="127.0.0.1",
                port=0,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = int(server.server_address[1])
            status, headers, payload = _http_request(
                port,
                "POST",
                "/api/v1/session",
                headers={BROWSER_BOOTSTRAP_HEADER: capability},
            )
            _require(status == 204 and payload == b"", "the replay API session exchange failed")
            cookie = headers.get("set-cookie", "").split(";", 1)[0]
            _require(cookie.startswith("bluefire_session="), "the replay API session is absent")
            replay_status, _headers, _payload = _http_request(
                port,
                "POST",
                "/api/v1/session",
                headers={BROWSER_BOOTSTRAP_HEADER: capability},
            )
            _require(replay_status == 401, "the replay API capability was not exactly one-use")
            auth = {"Cookie": cookie}
            sigma_status, _headers, payload = _http_request(
                port,
                "GET",
                f"/api/v1/detections/{sigma.candidate_id}",
                headers=auth,
            )
            api_sigma = _candidate_document(
                _json_response(payload, "management API Sigma"), "management API Sigma"
            )
            browser_status, _headers, payload = _http_request(
                port,
                "GET",
                f"/api/v1/detections/{browser.candidate_id}",
                headers=auth,
            )
            api_browser = _candidate_document(
                _json_response(payload, "management API browser"), "management API browser"
            )
            comparison_status, _headers, payload = _http_request(
                port,
                "POST",
                f"/api/v1/detections/{sigma.candidate_id}/compare",
                body={"candidate_id": rejected.candidate_id},
                headers=auth,
            )
            api_comparison = _json_response(payload, "management API comparison")
            _require(
                sigma_status == browser_status == comparison_status == 200
                and api_sigma == sigma.to_dict()
                and api_browser == browser.to_dict()
                and api_comparison == comparison,
                "the independent management API replay did not return exact persisted semantics",
            )
        finally:
            capability = ""
            if server is not None and thread is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            if service is not None:
                service.close()

        command = [
            sys.executable,
            "-B",
            "-m",
            "bluefire.cli",
            "--runs-dir",
            os.fspath(run_root),
            "detections",
            "detail",
            sigma.candidate_id,
        ]
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "TEMP": os.fspath(temporary_root),
                "TMP": os.fspath(temporary_root),
                "TMPDIR": os.fspath(temporary_root),
            }
        )
        try:
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
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DetectionManagementValidationError(
                "the independent management CLI replay failed"
            ) from exc
        _require(
            len(completed.stdout) <= 1024 * 1024 and len(completed.stderr) <= 64 * 1024,
            "the independent management CLI response exceeded its byte bound",
        )
        cli_document = _candidate_document(
            _json_response(completed.stdout, "management CLI Sigma"), "management CLI Sigma"
        )
        _require(
            completed.returncode == 0
            and completed.stderr == b""
            and cli_document == sigma.to_dict(),
            "the independent management CLI replay did not return the persisted Sigma candidate",
        )
        derived_api = {
            "session_authenticated": True,
            "loopback_origin": True,
            "candidate_status": sigma_status,
            "candidate_id": sigma.candidate_id,
            "candidate_definition_digest": sigma.definition_digest,
            "browser_candidate_status": browser_status,
            "browser_candidate_id": browser.candidate_id,
            "browser_candidate_definition_digest": browser.definition_digest,
            "comparison_status": comparison_status,
            "comparison_id": api_comparison["comparison_id"],
        }
        derived_cli = {
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
            "candidate_id": sigma.candidate_id,
            "candidate_definition_digest": sigma.definition_digest,
            "stderr_empty": completed.stderr == b"",
        }
    _require(not temporary_root.exists(), "the private management replay state was retained")
    return derived_api, derived_cli


def validate_management_surfaces(
    repository: Path,
    evidence_dir: Path,
    store: Mapping[str, Any],
    candidates: Mapping[str, DetectionCandidate],
    comparison: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Validate the retained DB snapshot, then independently replay API and CLI reads."""

    payload = _database_snapshot(evidence_dir, store, candidates)
    return _replay(repository, evidence_dir, payload, candidates, comparison)


__all__ = ["DetectionManagementValidationError", "validate_management_surfaces"]

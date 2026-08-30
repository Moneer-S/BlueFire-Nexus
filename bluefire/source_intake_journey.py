"""Real source-intake, package activation, native execution, and UI journey."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .api import (
    browser_console_url,
    create_server,
    generate_browser_bootstrap_capability,
)
from .config import RunnerProfile
from .defense_frontier import (
    _close_runtime_and_remove,
    _remove_runner_journal,
    _runtime_temp_parent,
)
from .runner_bootstrap import RunnerBootstrapError, bootstrap_runner, current_platform
from .runner_client import SubprocessRustRunner
from .runner_lifecycle import ManagedRunnerLifecycle
from .service import BlueFireService
from .source_intake import SourceIntakeError, perform_source_intake
from .source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    INTAKE_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    LICENSE_SHA256,
    LICENSE_SIZE_BYTES,
    PACKAGE_ID,
    PACKAGE_VERSION,
    REQUIRED_NOTICE,
    REVIEWED_OPCODE,
    SOURCE_ASSET,
    SOURCE_BLOB,
    SOURCE_COMMIT,
    SOURCE_ID,
    SOURCE_SHA256,
    SOURCE_SIZE_BYTES,
    SOURCE_TAG_OBJECT,
    SOURCE_VERSION,
    gate09_intake_request,
    validate_gate09_intake_envelope,
)
from .util import canonical_json_bytes, content_hash

INTAKE_REPORT = "gate09-intake-report.json"
EXECUTION_REPORT = "gate09-execution-report.json"
SAFETY_REPORT = "gate09-safety-report.json"
BROWSER_REPORT = "gate09-browser-report.json"
PRODUCT_DB_ARTIFACT = "runs/bluefire-product.sqlite3"
PRIMARY_INTAKE_DESTINATION_ID = "gate09-reviewed-t1082"
BROWSER_INTAKE_DESTINATION_ID = "gate09-browser-reviewed-t1082"
OPERATION_RECEIPT_FILENAME = f"{INTAKE_ID}.operation-receipt.json"
BROWSER_INTAKE_ARTIFACT = f"runs/source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"
BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT = (
    f"runs/source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{OPERATION_RECEIPT_FILENAME}"
)
INTAKE_ARTIFACT = f"runs/source-intakes/{PRIMARY_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"
PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT = (
    f"runs/source-intakes/{PRIMARY_INTAKE_DESTINATION_ID}/{OPERATION_RECEIPT_FILENAME}"
)
REPORT_PATHS = (INTAKE_REPORT, EXECUTION_REPORT, SAFETY_REPORT, BROWSER_REPORT)

HELPER_SCHEMA = "bluefire.gate-09-helper.v1"
INTAKE_SCHEMA = "bluefire.source-intake-gate-journey.v1"
EXECUTION_SCHEMA = "bluefire.source-intake-native-execution.v1"
SAFETY_SCHEMA = "bluefire.source-intake-safety.v1"
BROWSER_SCHEMA = "bluefire.source-intake-production-browser.v1"
BROWSER_OPERATION_SEQUENCE = (
    "bootstrap_production_session",
    "open_research_sources",
    "verify_pinned_source",
    "expand_intake_review",
    "configure_reviewed_intake",
    "activate_reviewed_intake",
    "open_behaviors",
    "verify_imported_behavior",
    "verify_behavior_provenance",
    "reload_and_verify_persisted_state",
)

_MAX_REPORT_BYTES = 2 * 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 256 * 1024
_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class SourceIntakeJourneyError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceIntakeJourneyError(message)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        0 < len(payload) <= _MAX_REPORT_BYTES and path.parent.is_dir() and not path.exists(),
        "a GATE-09 report path is stale, missing its parent, or unbounded",
    )
    descriptor: int | None = None
    owned_identity: tuple[int, int, int] | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        owned_identity = _identity(opened)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise OSError("report output is unsafe")
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("report write made no progress")
            written += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            _identity(after) != owned_identity
            or _identity(current) != owned_identity
            or _is_link_or_reparse(current)
            or after.st_nlink != 1
            or current.st_nlink != 1
        ):
            raise OSError("report output changed during publication")
    except OSError as exc:
        if owned_identity is not None:
            try:
                current = path.lstat()
                if _identity(current) == owned_identity and not _is_link_or_reparse(current):
                    path.unlink()
            except OSError:
                pass
        raise SourceIntakeJourneyError("a GATE-09 report could not be written") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _is_link_or_reparse(details: Any) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _identity(details: Any) -> tuple[int, int, int]:
    return (int(details.st_dev), int(details.st_ino), int(details.st_mode))


def _bounded_file_artifact(
    path: Path,
    *,
    maximum_size: int,
    unavailable_message: str,
    capture_payload: bool = False,
) -> tuple[Mapping[str, Any], bytes | None]:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            _is_link_or_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_size
        ):
            raise SourceIntakeJourneyError(unavailable_message)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != before.st_size
            or _identity(opened) != _identity(before)
        ):
            raise SourceIntakeJourneyError(unavailable_message)
        digest = hashlib.sha256()
        captured = bytearray() if capture_payload else None
        observed_size = 0
        while observed_size <= maximum_size:
            block = os.read(descriptor, min(64 * 1024, maximum_size + 1 - observed_size))
            if not block:
                break
            observed_size += len(block)
            digest.update(block)
            if captured is not None:
                captured.extend(block)
        after = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise SourceIntakeJourneyError(unavailable_message) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _require(
        observed_size == before.st_size
        and observed_size <= maximum_size
        and _identity(after) == _identity(opened) == _identity(current)
        and after.st_size == current.st_size == before.st_size
        and after.st_nlink == current.st_nlink == 1
        and not _is_link_or_reparse(current),
        unavailable_message,
    )
    return (
        {
            "path": path.name,
            "size_bytes": observed_size,
            "sha256": "sha256:" + digest.hexdigest(),
        },
        bytes(captured) if captured is not None else None,
    )


def _verified_file_payload(
    path: Path,
    expected_size: int,
    expected_hash: str,
) -> tuple[Mapping[str, Any], bytes]:
    _require(
        isinstance(expected_size, int)
        and not isinstance(expected_size, bool)
        and 0 < expected_size <= _MAX_DATABASE_BYTES,
        "a reviewed GATE-09 source asset failed exact integrity validation",
    )
    artifact, payload = _bounded_file_artifact(
        path,
        maximum_size=expected_size,
        unavailable_message="a reviewed GATE-09 source asset is unavailable",
        capture_payload=True,
    )
    _require(
        artifact["size_bytes"] == expected_size and artifact["sha256"] == expected_hash,
        "a reviewed GATE-09 source asset failed exact integrity validation",
    )
    _require(payload is not None, "a reviewed GATE-09 source asset is unavailable")
    return artifact, cast(bytes, payload)


def _verified_file(path: Path, expected_size: int, expected_hash: str) -> Mapping[str, Any]:
    return _verified_file_payload(path, expected_size, expected_hash)[0]


def _node_binary() -> Path:
    raw = os.environ.get("BLUEFIRE_GATE_NODE") or shutil.which("node")
    if not isinstance(raw, str) or not raw:
        raise SourceIntakeJourneyError("the pinned Gate 09 Node runtime is unavailable")
    node = Path(raw).resolve(strict=True)
    _require(node.is_file(), "the pinned Gate 09 Node runtime is invalid")
    return node


def _run_node(
    node: Path,
    arguments: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
) -> None:
    try:
        completed = subprocess.run(
            [os.fspath(node), *arguments],
            cwd=repository,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=150,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceIntakeJourneyError("the Gate 09 production browser process failed") from exc
    _require(
        len(completed.stdout) <= _MAX_PROCESS_OUTPUT_BYTES
        and len(completed.stderr) <= _MAX_PROCESS_OUTPUT_BYTES,
        "the Gate 09 browser process exceeded its output bound",
    )
    _require(completed.returncode == 0, "the Gate 09 production browser process failed")


def _browser_evidence(
    repository: Path,
    destination: Path,
    service: BlueFireService,
    *,
    profile_id: str,
    expected_record_sha256: str,
) -> Mapping[str, Any]:
    node = _node_binary()
    wrapper = repository / "tools" / "run_source_intake_browser_journey.mjs"
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
        "the packaged production UI or Gate 09 browser harness is absent",
    )
    entries = {entry.name: entry for entry in ui_root.iterdir()}
    _require(set(entries) == set(expected_assets), "the packaged UI asset inventory is not exact")
    for name, maximum in expected_assets.items():
        entry = entries[name]
        _require(
            entry.is_file() and not entry.is_symlink() and 0 < entry.stat().st_size <= maximum,
            "a packaged UI asset is unsafe or unbounded",
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
    thread = threading.Thread(
        target=server.serve_forever,
        name="bluefire-gate09-ui",
        daemon=True,
    )
    thread.start()
    try:
        launch_url = browser_console_url("127.0.0.1", int(server.server_address[1]), capability)
        environment = dict(os.environ)
        environment.update(
            {
                "BLUEFIRE_PRODUCTION_URL": launch_url,
                "BLUEFIRE_GATE09_PROFILE_ID": profile_id,
                "BLUEFIRE_GATE09_EXPECTED_RECORD_SHA256": expected_record_sha256,
                "VITE_DEMO_MODE": "false",
            }
        )
        _run_node(
            node,
            [os.fspath(wrapper), "--report", os.fspath(report_path)],
            repository=repository,
            environment=environment,
        )
    finally:
        capability = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
    _require(not thread.is_alive(), "the Gate 09 UI server did not stop")
    _require(report_path.is_file() and not report_path.is_symlink(), "browser report is absent")
    try:
        _report_artifact, report_payload = _bounded_file_artifact(
            report_path,
            maximum_size=_MAX_REPORT_BYTES,
            unavailable_message="the Gate 09 browser report is invalid",
            capture_payload=True,
        )
        _require(report_payload is not None, "the Gate 09 browser report is invalid")
        browser = json.loads(cast(bytes, report_payload))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise SourceIntakeJourneyError("the Gate 09 browser report is invalid") from exc
    _require(
        isinstance(browser, Mapping)
        and browser.get("schema_version") == BROWSER_SCHEMA
        and browser.get("production_browser_interaction") is True
        and browser.get("source_id") == SOURCE_ID
        and browser.get("behavior_id") == BEHAVIOR_ID
        and browser.get("action_id") == ACTION_ID
        and browser.get("activation_operation") == "already_active_revalidated"
        and browser.get("behavior_provenance_visible") is True
        and browser.get("behavior_provenance_reference")
        == (
            f"urn:bluefire:source-intake:{INTAKE_ID}:"
            f"sha256:{expected_record_sha256.removeprefix('sha256:')}"
        )
        and browser.get("intake_destination_id") == BROWSER_INTAKE_DESTINATION_ID
        and browser.get("intake_record_sha256") == expected_record_sha256
        and browser.get("intake_state_ref")
        == f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"
        and browser.get("operation_receipt_visible") is True
        and isinstance(browser.get("operation_receipt_sha256"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", browser["operation_receipt_sha256"]) is not None
        and browser.get("operation_receipt_state_ref")
        == (f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{OPERATION_RECEIPT_FILENAME}")
        and browser.get("runner_profile_id") == profile_id
        and browser.get("operation_sequence") == list(BROWSER_OPERATION_SEQUENCE),
        "the production browser report did not prove source and behavior provenance",
    )
    return cast(Mapping[str, Any], browser)


def _refused_without_output(
    source_root: Path,
    parent: Path,
    name: str,
    request: Mapping[str, Any],
) -> bool:
    destination = parent / name
    destination.mkdir(mode=0o700)
    try:
        perform_source_intake(source_root, destination, request)
    except SourceIntakeError:
        return list(destination.iterdir()) == []
    return False


def _safety_evidence(
    source_root: Path,
    source_document: Mapping[str, Any],
    runtime: Path,
) -> Mapping[str, Any]:
    request = gate09_intake_request()
    digest_request = copy.deepcopy(request)
    digest_request["source"]["sha256"] = "sha256:" + "0" * 64
    unknown_request = copy.deepcopy(request)
    unknown_request["transformer"] = {"name": "unreviewed-runtime-plugin", "version": "1.0.0"}

    unsafe_root = runtime / "unsafe-source"
    unsafe_root.mkdir(mode=0o700)
    unsafe_document = copy.deepcopy(source_document)
    unsafe_document["objects"][0]["command"] = "unreviewed executable material"
    unsafe_payload = canonical_json_bytes(unsafe_document)
    (unsafe_root / SOURCE_ASSET).write_bytes(unsafe_payload)
    unsafe_request = copy.deepcopy(request)
    unsafe_request["source"].update(
        {
            "sha256": "sha256:" + hashlib.sha256(unsafe_payload).hexdigest(),
            "size_bytes": len(unsafe_payload),
        }
    )

    multi_root = runtime / "multi-source"
    multi_root.mkdir(mode=0o700)
    multi_document = copy.deepcopy(source_document)
    multi_document["objects"].append(copy.deepcopy(multi_document["objects"][0]))
    multi_payload = canonical_json_bytes(multi_document)
    (multi_root / SOURCE_ASSET).write_bytes(multi_payload)
    multi_request = copy.deepcopy(request)
    multi_request["source"].update(
        {
            "sha256": "sha256:" + hashlib.sha256(multi_payload).hexdigest(),
            "size_bytes": len(multi_payload),
        }
    )

    destinations = runtime / "refusals"
    destinations.mkdir(mode=0o700)
    refused = {
        "source_digest_mismatch": _refused_without_output(
            source_root, destinations, "digest", digest_request
        ),
        "unknown_transformer": _refused_without_output(
            source_root, destinations, "transformer", unknown_request
        ),
        "executable_materialization_field": _refused_without_output(
            unsafe_root, destinations, "executable", unsafe_request
        ),
        "multi_object_bundle": _refused_without_output(
            multi_root, destinations, "multi", multi_request
        ),
    }
    return {
        "schema_version": SAFETY_SCHEMA,
        "passed": all(refused.values()),
        "refused_without_output": refused,
        "trusted_transformer": {
            "name": request["transformer"]["name"],
            "version": request["transformer"]["version"],
            "runtime_discovery": False,
        },
        "external_content_executed": False,
        "network_intake": False,
    }


def _research_source(service: BlueFireService) -> Mapping[str, Any]:
    rows = service.resources("research_source").get("resources")
    matches = (
        [row for row in rows if isinstance(row, Mapping) and row.get("id") == SOURCE_ID]
        if isinstance(rows, list)
        else []
    )
    _require(len(matches) == 1, "the pinned source was not seeded into the ProductStore")
    resource = matches[0]
    document = resource.get("document")
    if resource.get("status") != "pinned" or not isinstance(document, Mapping):
        raise SourceIntakeJourneyError("the ProductStore source record is not pinned")
    return document


def _database_artifact(run_root: Path) -> Mapping[str, Any]:
    database = run_root / "bluefire-product.sqlite3"
    for suffix in ("-shm", "-wal"):
        sidecar = run_root / (database.name + suffix)
        try:
            sidecar.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SourceIntakeJourneyError("ProductStore sidecar status is unavailable") from exc
        else:
            raise SourceIntakeJourneyError("ProductStore sidecar remains")
    artifact = dict(
        _bounded_file_artifact(
            database,
            maximum_size=_MAX_DATABASE_BYTES,
            unavailable_message="the GATE-09 ProductStore artifact is unsafe or unbounded",
        )[0]
    )
    artifact["path"] = PRODUCT_DB_ARTIFACT
    return artifact


def _scenario(record_sha256: str) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.scenario.v1",
        "id": "scenario.source-intake.system-information.v1",
        "title": "Reviewed source-intake system information",
        "purpose": "Execute the independently compiled action associated with reviewed T1082 metadata.",
        "start": "observe_system",
        "steps": [{"id": "observe_system", "behavior_id": BEHAVIOR_ID}],
        "edges": [],
        "provenance": {
            "source": "BlueFire Gate 09 reviewed source-intake journey",
            "reference": f"urn:bluefire:source-intake:{INTAKE_ID}:{record_sha256}",
            "license": LICENSE_ID,
            "derived": True,
            "notes": "No upstream executable content is dispatched. " + REQUIRED_NOTICE,
        },
        "limitations": ["Reads bounded platform identity only."],
    }


def produce_source_intake_gate_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    """Produce one acceptance-bound run plus independently checkable intake evidence."""

    try:
        root_details = repository.lstat()
        destination_details = evidence_dir.lstat()
    except OSError as exc:
        raise SourceIntakeJourneyError("GATE-09 journey roots are absent") from exc
    _require(
        stat.S_ISDIR(root_details.st_mode)
        and not _is_link_or_reparse(root_details)
        and stat.S_ISDIR(destination_details.st_mode)
        and not _is_link_or_reparse(destination_details),
        "GATE-09 journey roots are invalid",
    )
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        (root / "pyproject.toml").is_file(),
        "GATE-09 repository root is invalid",
    )
    _require(
        destination.is_dir()
        and not destination.is_symlink()
        and not any((destination / name).exists() for name in REPORT_PATHS)
        and not (destination / "runs").exists()
        and not (destination / "intake").exists(),
        "GATE-09 evidence directory contains stale owned artifacts",
    )
    data_root = root / "bluefire" / "data"
    source_asset, source_payload = _verified_file_payload(
        data_root / SOURCE_ASSET,
        SOURCE_SIZE_BYTES,
        SOURCE_SHA256,
    )
    license_asset = _verified_file(data_root / LICENSE_ASSET, LICENSE_SIZE_BYTES, LICENSE_SHA256)
    try:
        source_document = json.loads(source_payload)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise SourceIntakeJourneyError("the reviewed source asset is not valid JSON") from exc
    _require(isinstance(source_document, Mapping), "the reviewed source asset is not an object")
    run_root = destination / "runs"
    run_root.mkdir(mode=0o700)

    service: BlueFireService | None = None
    runtime: Path | None = None
    cleanup_attempted = False

    def close_service() -> None:
        nonlocal service
        if service is not None:
            service.close()
            service = None

    try:
        runtime = Path(tempfile.mkdtemp(prefix=".g9-", dir=_runtime_temp_parent()))
        safety = _safety_evidence(data_root, source_document, runtime)
        _require(safety["passed"] is True, "the source-intake refusal matrix is incomplete")
        try:
            bootstrapped = bootstrap_runner(
                environ={},
                resource_root=root / "bluefire" / "native",
                managed_root=runtime / "managed",
            )
        except RunnerBootstrapError as exc:
            raise SourceIntakeJourneyError("the packaged native runner is unavailable") from exc
        _require(
            current_platform() == "windows"
            and bootstrapped.source == "packaged"
            and bootstrapped.manifest.platform == "windows",
            "GATE-09 requires the packaged Windows runner on this host",
        )
        runner = SubprocessRustRunner(
            bootstrapped.binary_path,
            runtime / "transport",
            timeout_seconds=35.0,
            output_limit_bytes=4 * 1024 * 1024,
        )
        service = BlueFireService(
            project_root=root,
            runs_dir=run_root,
            product_db_path=run_root / "bluefire-product.sqlite3",
            runner_factory=lambda _profile: (runner, bootstrapped.sandbox_path),
            runner_lifecycle=ManagedRunnerLifecycle(runtime / "managed-lifecycle"),
        )
        initial_catalog = service.catalog()
        initial_behaviors = initial_catalog.get("behaviors")
        initial_actions = initial_catalog.get("actions")
        initial_authority = initial_catalog.get("action_package_catalog")
        _require(
            isinstance(initial_behaviors, list)
            and isinstance(initial_actions, list)
            and isinstance(initial_authority, Mapping)
            and all(
                not isinstance(row, Mapping) or row.get("id") != BEHAVIOR_ID
                for row in initial_behaviors
            )
            and all(
                not isinstance(row, Mapping) or row.get("id") != ACTION_ID
                for row in initial_actions
            ),
            "the source-intake package IDs unexpectedly existed before activation",
        )
        initial_authority = cast(Mapping[str, Any], initial_authority)
        source = _research_source(service)
        profile = next(
            (
                item
                for item in service.config.runner_profiles
                if item.mode.value == "execute"
                and REVIEWED_OPCODE in item.enabled_actions
                and "windows" in item.platforms
            ),
            None,
        )
        _require(profile is not None, "no reviewed Execute profile can dispatch the source action")
        profile = cast(RunnerProfile, profile)
        product_intake = service.intake_reviewed_t1082(
            {
                "destination_id": PRIMARY_INTAKE_DESTINATION_ID,
                "runner_profile_id": profile.id,
                "operator_id": "gate-09-source-reviewer",
            }
        )
        intake_envelope = validate_gate09_intake_envelope(product_intake.get("envelope"))
        intake_summary = product_intake.get("intake")
        artifact_summary = product_intake.get("artifact")
        activation_summary = product_intake.get("package_activation")
        receipt_summary = product_intake.get("operation_receipt")
        receipt_record = (
            receipt_summary.get("record") if isinstance(receipt_summary, Mapping) else None
        )
        package_summary = (
            activation_summary.get("package") if isinstance(activation_summary, Mapping) else None
        )
        activation_delta = (
            activation_summary.get("catalog_delta")
            if isinstance(activation_summary, Mapping)
            else None
        )
        _require(
            product_intake.get("schema_version") == "bluefire.reviewed-source-intake-result.v1"
            and product_intake.get("destination_id") == PRIMARY_INTAKE_DESTINATION_ID
            and isinstance(intake_summary, Mapping)
            and intake_summary.get("intake_id") == INTAKE_ID
            and intake_summary.get("record_sha256") == intake_envelope["record_sha256"]
            and intake_summary.get("output_sha256")
            == intake_envelope["record"]["transformation_history"][0]["output_sha256"]
            and intake_summary.get("execution_material_imported") is False
            and isinstance(artifact_summary, Mapping)
            and artifact_summary.get("state_ref")
            == f"source-intakes/{PRIMARY_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"
            and isinstance(activation_summary, Mapping)
            and activation_summary.get("operation") == "installed_and_activated"
            and isinstance(package_summary, Mapping)
            and package_summary.get("package_id") == PACKAGE_ID
            and package_summary.get("version") == PACKAGE_VERSION
            and isinstance(activation_delta, Mapping)
            and activation_delta.get("behavior_ids_added") == [BEHAVIOR_ID]
            and activation_delta.get("action_ids_added") == [ACTION_ID]
            and isinstance(receipt_summary, Mapping)
            and set(receipt_summary)
            == {"media_type", "sha256", "size_bytes", "state_ref", "record"}
            and receipt_summary.get("media_type")
            == "application/vnd.bluefire.reviewed-source-intake-operation-receipt+json"
            and receipt_summary.get("state_ref")
            == (f"source-intakes/{PRIMARY_INTAKE_DESTINATION_ID}/{OPERATION_RECEIPT_FILENAME}")
            and isinstance(receipt_record, Mapping)
            and receipt_summary.get("sha256") == content_hash(receipt_record)
            and receipt_summary.get("size_bytes") == len(canonical_json_bytes(receipt_record))
            and set(receipt_record)
            == {
                "schema_version",
                "destination_id",
                "operator_id",
                "runner_profile_id",
                "intake",
                "artifact",
                "package",
                "activation",
                "completed_at",
            }
            and receipt_record.get("schema_version")
            == "bluefire.reviewed-source-intake-operation-receipt.v1"
            and receipt_record.get("destination_id") == PRIMARY_INTAKE_DESTINATION_ID
            and receipt_record.get("operator_id") == "gate-09-source-reviewer"
            and receipt_record.get("runner_profile_id") == profile.id
            and receipt_record.get("intake")
            == {
                "intake_id": INTAKE_ID,
                "record_sha256": intake_summary["record_sha256"],
                "output_sha256": intake_summary["output_sha256"],
            }
            and receipt_record.get("artifact")
            == {
                "state_ref": artifact_summary["state_ref"],
                "sha256": artifact_summary["sha256"],
                "size_bytes": artifact_summary["size_bytes"],
            }
            and receipt_record.get("package")
            == {
                "package_id": package_summary["package_id"],
                "version": package_summary["version"],
                "package_digest": package_summary["package_digest"],
                "content_digest": package_summary["content_digest"],
            }
            and receipt_record.get("activation")
            == {
                "operation": activation_summary["operation"],
                "catalog_generation": activation_delta["generation_after"],
                "catalog_digest": activation_delta["catalog_digest_after"],
            }
            and isinstance(receipt_record.get("completed_at"), str)
            and str(receipt_record["completed_at"]).endswith("Z"),
            "the public reviewed-source intake operation returned a detached result",
        )
        intake_summary = cast(Mapping[str, Any], intake_summary)
        artifact_summary = cast(Mapping[str, Any], artifact_summary)
        activation_summary = cast(Mapping[str, Any], activation_summary)
        receipt_summary = cast(Mapping[str, Any], receipt_summary)
        package_summary = cast(Mapping[str, Any], package_summary)
        activation_delta = cast(Mapping[str, Any], activation_delta)
        run = service.run(
            {
                "scenario": _scenario(str(intake_envelope["record_sha256"])),
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
                "approval": {"confirmed": True, "approved_by": "gate-09-run-reviewer"},
            }
        )
        run_id = str(run.get("run_id"))
        steps = run.get("steps")
        step = steps[0] if isinstance(steps, list) and len(steps) == 1 else None
        _require(
            run.get("status") == "completed"
            and run.get("objective_reached") is True
            and isinstance(step, Mapping)
            and step.get("behavior_id") == BEHAVIOR_ID
            and step.get("action_id") == ACTION_ID
            and step.get("status") == "success"
            and service.store.validate_bundle(run_id).get("valid") is True,
            "the imported behavior did not execute through its reviewed native binding",
        )
        catalog = service.catalog()
        behaviors = catalog.get("behaviors")
        behavior_matches = (
            [row for row in behaviors if isinstance(row, Mapping) and row.get("id") == BEHAVIOR_ID]
            if isinstance(behaviors, list)
            else []
        )
        actions = catalog.get("actions")
        action_matches = (
            [row for row in actions if isinstance(row, Mapping) and row.get("id") == ACTION_ID]
            if isinstance(actions, list)
            else []
        )
        active_authority = catalog.get("action_package_catalog")
        _require(
            len(behavior_matches) == 1
            and len(action_matches) == 1
            and isinstance(active_authority, Mapping),
            "the imported behavior or action is absent from the active catalog",
        )
        active_authority = cast(Mapping[str, Any], active_authority)
        browser = _browser_evidence(
            root,
            destination,
            service,
            profile_id=profile.id,
            expected_record_sha256=str(intake_envelope["record_sha256"]),
        )
        execution = {
            "schema_version": EXECUTION_SCHEMA,
            "passed": True,
            "package": {
                "package_id": PACKAGE_ID,
                "version": PACKAGE_VERSION,
                "package_digest": package_summary["package_digest"],
                "content_digest": package_summary["content_digest"],
                "publisher_id": package_summary["publisher_id"],
                "key_id": package_summary["key_id"],
                "trust_state": "trusted",
                "catalog_generation": activation_delta["generation_after"],
            },
            "binding": {
                "behavior_id": BEHAVIOR_ID,
                "action_id": ACTION_ID,
                "reviewed_opcode": REVIEWED_OPCODE,
                "technique_id": "T1082",
                "implementation": "independent_bluefire_compiled_action",
            },
            "runner": {
                "source": bootstrapped.source,
                "platform": bootstrapped.manifest.platform,
                "binary_sha256": "sha256:" + bootstrapped.binary_sha256,
            },
            "run_id": run_id,
            "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
            "profile_id": profile.id,
            "cleanup": run.get("cleanup"),
            "browser_report": BROWSER_REPORT,
            "catalog_delta": {
                "package_id": PACKAGE_ID,
                "package_version": PACKAGE_VERSION,
                "behavior_id": BEHAVIOR_ID,
                "action_id": ACTION_ID,
                "behavior_absent_before": True,
                "action_absent_before": True,
                "behavior_present_after": True,
                "action_present_after": True,
                "generation_before": initial_authority.get("generation"),
                "generation_after": active_authority.get("generation"),
                "catalog_digest_before": initial_authority.get("catalog_digest"),
                "catalog_digest_after": active_authority.get("catalog_digest"),
            },
        }
        intake_report = {
            "schema_version": INTAKE_SCHEMA,
            "passed": True,
            "source": {
                **source_asset,
                "research_source_id": SOURCE_ID,
                "version": SOURCE_VERSION,
                "commit": SOURCE_COMMIT,
                "tag_object": SOURCE_TAG_OBJECT,
                "blob_sha1": SOURCE_BLOB,
            },
            "license": {
                **license_asset,
                "identifier": LICENSE_ID,
                "notice": REQUIRED_NOTICE,
            },
            "intake_artifact": {
                "path": INTAKE_ARTIFACT,
                "record_sha256": intake_envelope["record_sha256"],
                "output_sha256": intake_summary["output_sha256"],
            },
            "operation_receipt": {
                "path": PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
                "media_type": receipt_summary["media_type"],
                "sha256": receipt_summary["sha256"],
                "size_bytes": receipt_summary["size_bytes"],
                "state_ref": receipt_summary["state_ref"],
            },
            "output": intake_envelope["record"]["output"],
            "transformation_history": intake_envelope["record"]["transformation_history"],
            "research_source": source,
        }
        try:
            _close_runtime_and_remove(runtime, close_service)
        finally:
            cleanup_attempted = True

        _remove_runner_journal(run_root)
        database = _database_artifact(run_root)
        execution["product_store"] = database
        for path, report in (
            (destination / INTAKE_REPORT, intake_report),
            (destination / EXECUTION_REPORT, execution),
            (destination / SAFETY_REPORT, safety),
        ):
            _write_json(path, report)
        _require(browser.get("demo_mode") is False, "the UI evidence used demo mode")
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 1,
            "blocking_check": None,
        }
    finally:
        if runtime is not None and not cleanup_attempted:
            _close_runtime_and_remove(runtime, close_service)


__all__ = [
    "BROWSER_OPERATION_SEQUENCE",
    "BROWSER_INTAKE_DESTINATION_ID",
    "BROWSER_INTAKE_ARTIFACT",
    "BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT",
    "BROWSER_REPORT",
    "BROWSER_SCHEMA",
    "EXECUTION_REPORT",
    "EXECUTION_SCHEMA",
    "HELPER_SCHEMA",
    "INTAKE_ARTIFACT",
    "INTAKE_REPORT",
    "INTAKE_SCHEMA",
    "OPERATION_RECEIPT_FILENAME",
    "PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT",
    "PRODUCT_DB_ARTIFACT",
    "REPORT_PATHS",
    "SAFETY_REPORT",
    "SAFETY_SCHEMA",
    "SourceIntakeJourneyError",
    "produce_source_intake_gate_evidence",
]

"""No-argument Linux-side worker for the fixed Gate 11 WSL boundary."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import multiprocessing
import os
import queue
import re
import secrets
import shutil
import signal
import stat
import sys
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

REQUEST_SCHEMA = "bluefire.cross-platform-linux-request.v2"
SUMMARY_SCHEMA = "bluefire.cross-platform-linux-worker.v3"
SOURCE_DISTRO = "BlueFire-Gate11-Base-v1"
_EXECUTION_DISTRO = re.compile(r"^BlueFire-Gate11-Run-[0-9a-f]{16}$")
SCENARIO = "linux_container_validation.yaml"
PROFILE = "sandbox-execute.v1"
SCENARIO_VARIANTS = ("primary", "registered-alternate")
_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_ACCEPTANCE_ENV = {
    "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
    "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
}


class WorkerError(ValueError):
    pass


class DependencyError(WorkerError):
    def __init__(self, facts: Mapping[str, Any]) -> None:
        super().__init__("Linux product dependencies are incompatible")
        self.facts = facts


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkerError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _load_request(root: Path) -> Mapping[str, Any]:
    path = root / "request.json"
    details = path.lstat()
    _require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1, "unsafe request")
    payload = path.read_bytes()
    _require(0 < len(payload) <= 64 * 1024, "unbounded request")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerError("invalid request") from exc
    _require(
        isinstance(value, Mapping)
        and set(value)
        == {
            "schema_version",
            "source_distribution_id",
            "execution_distribution_id",
            "workspace_name",
            "scenario_variant",
            "acceptance_binding",
            "release_artifact",
            "wheelhouse",
        }
        and value.get("schema_version") == REQUEST_SCHEMA
        and value.get("source_distribution_id") == SOURCE_DISTRO
        and isinstance(value.get("execution_distribution_id"), str)
        and _EXECUTION_DISTRO.fullmatch(str(value["execution_distribution_id"])) is not None
        and isinstance(value.get("workspace_name"), str)
        and _WORKSPACE.fullmatch(str(value["workspace_name"])) is not None,
        "invalid request envelope",
    )
    _require(value.get("scenario_variant") in SCENARIO_VARIANTS, "invalid scenario variant")
    acceptance = value.get("acceptance_binding")
    artifact = value.get("release_artifact")
    wheelhouse = value.get("wheelhouse")
    _require(
        isinstance(acceptance, Mapping)
        and set(acceptance) == set(_ACCEPTANCE_ENV)
        and all(isinstance(item, str) and 1 <= len(item) <= 512 for item in acceptance.values())
        and isinstance(artifact, Mapping)
        and set(artifact)
        == {
            "runner_id",
            "runner_version",
            "platform",
            "architecture",
            "repository_commit",
            "repository_tree",
            "binary_git_blob",
            "manifest_git_blob",
            "binary_sha256",
            "binary_size",
            "manifest_sha256",
            "manifest_size",
        }
        and artifact.get("runner_id") == "bluefire-rust-runner.v1"
        and artifact.get("platform") == "linux"
        and artifact.get("architecture") == "x86_64"
        and artifact.get("repository_commit") == acceptance.get("repository_commit")
        and artifact.get("repository_tree") == acceptance.get("repository_tree")
        and _GIT_OBJECT.fullmatch(str(artifact.get("binary_git_blob"))) is not None
        and _GIT_OBJECT.fullmatch(str(artifact.get("manifest_git_blob"))) is not None
        and isinstance(artifact.get("binary_sha256"), str)
        and _SHA256.fullmatch(str(artifact["binary_sha256"])) is not None
        and type(artifact.get("binary_size")) is int
        and 1 <= int(artifact["binary_size"]) <= 128 * 1024 * 1024
        and isinstance(artifact.get("manifest_sha256"), str)
        and _SHA256.fullmatch(str(artifact["manifest_sha256"])) is not None
        and type(artifact.get("manifest_size")) is int
        and 1 <= int(artifact["manifest_size"]) <= 64 * 1024
        and isinstance(wheelhouse, Mapping)
        and set(wheelhouse) == {"manifest_sha256", "manifest_size", "wheel_count"}
        and isinstance(wheelhouse.get("manifest_sha256"), str)
        and _SHA256.fullmatch(str(wheelhouse["manifest_sha256"])) is not None
        and type(wheelhouse.get("manifest_size")) is int
        and 1 <= int(wheelhouse["manifest_size"]) <= 64 * 1024
        and wheelhouse.get("wheel_count") == 5,
        "invalid request authorities",
    )
    return value


def _file_payload(path: Path, maximum: int) -> tuple[bytes, tuple[int, str]]:
    details = path.lstat()
    _require(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and details.st_nlink == 1
        and 1 <= details.st_size <= maximum,
        "unsafe staged file",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (details.st_dev, details.st_ino, details.st_size),
            "staged file identity changed",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum + 1)
        final = os.fstat(descriptor)
        current = path.lstat()
        _require(
            len(payload) == opened.st_size
            and len(payload) <= maximum
            and (final.st_dev, final.st_ino, final.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size)
            and (current.st_dev, current.st_ino, current.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size)
            and not stat.S_ISLNK(current.st_mode),
            "staged file changed during its pinned read",
        )
        return payload, (len(payload), "sha256:" + hashlib.sha256(payload).hexdigest())
    finally:
        os.close(descriptor)


def _file_identity(path: Path, maximum: int) -> tuple[int, str]:
    return _file_payload(path, maximum)[1]


def _dependency_facts(product_root: Path) -> Mapping[str, Any]:
    requirements = {
        "PyYAML": ("PyYAML>=6.0.1,<7", (6, 0, 1), (7, 0, 0)),
        "cryptography": ("cryptography>=50,<51", (50, 0, 0), (51, 0, 0)),
        "PyNaCl": ("PyNaCl>=1.5,<2", (1, 5, 0), (2, 0, 0)),
    }
    pyproject = product_root / "pyproject.toml"
    payload = pyproject.read_bytes()
    _require(0 < len(payload) <= 256 * 1024, "project dependency contract is unavailable")
    try:
        project_text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise WorkerError("project dependency contract is invalid") from exc
    facts: dict[str, Any] = {}
    ready = True
    for name, (requirement, minimum, maximum) in requirements.items():
        declared = f'"{requirement}"' in project_text
        try:
            observed = importlib.metadata.version(name)
            match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", observed)
            version = tuple(int(item or 0) for item in match.groups()) if match else ()
        except importlib.metadata.PackageNotFoundError:
            observed = None
            version = ()
        compatible = bool(declared and version and minimum <= version < maximum)
        facts[name] = {
            "requirement": requirement,
            "declared": declared,
            "version": observed,
            "compatible": compatible,
        }
        ready = ready and compatible
    return {"ready": ready, "packages": facts}


def _safe_member_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name or name.endswith("/"):
        return False
    path = PurePosixPath(name)
    return bool(
        not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not any(part.endswith(".data") for part in path.parts)
    )


def _record_rows(payload: bytes) -> Mapping[str, tuple[str, str]]:
    _require(0 < len(payload) <= 4 * 1024 * 1024, "wheel RECORD is unbounded")
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise WorkerError("wheel RECORD is invalid") from exc
    result: dict[str, tuple[str, str]] = {}
    for row in rows:
        _require(
            len(row) == 3 and _safe_member_name(row[0]) and row[0] not in result,
            "wheel RECORD row is invalid",
        )
        result[row[0]] = (row[1], row[2])
    return result


def _verify_record(name: str, payload: bytes, row: tuple[str, str]) -> None:
    digest, size = row
    _require(size == str(len(payload)), "wheel RECORD size mismatch")
    _require(digest.startswith("sha256="), "wheel RECORD digest is unsupported")
    encoded = digest.removeprefix("sha256=")
    _require(re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is not None, "invalid wheel hash")
    try:
        expected = base64.urlsafe_b64decode(encoded + "=")
    except ValueError as exc:
        raise WorkerError("invalid wheel hash") from exc
    _require(
        len(expected) == 32 and expected == hashlib.sha256(payload).digest(),
        f"wheel RECORD digest mismatch for {name}",
    )


def _write_site_member(site: Path, name: str, payload: bytes) -> None:
    target = site.joinpath(*PurePosixPath(name).parts)
    _require(target.is_relative_to(site), "wheel member escaped task-private site")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = target.parent
    while current != site:
        details = current.lstat()
        _require(stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode), "unsafe site")
        current = current.parent
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "wheel extraction made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _install_locked_wheel(path: Path, row: Mapping[str, Any], site: Path) -> None:
    expected_identity = (int(row["size"]), "sha256:" + str(row["sha256"]))
    wheel_payload, observed_identity = _file_payload(path, 32 * 1024 * 1024)
    _require(observed_identity == expected_identity, "wheel identity mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_payload), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            _require(
                0 < len(infos) <= 4096
                and len(names) == len(set(names))
                and all(_safe_member_name(name) for name in names),
                "wheel member inventory is unsafe",
            )
            total = 0
            for info in infos:
                mode = int(info.external_attr) >> 16
                _require(
                    not (info.flag_bits & 0x1)
                    and not stat.S_ISLNK(mode)
                    and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    and 0 <= info.file_size <= 32 * 1024 * 1024,
                    "wheel member is unsafe",
                )
                total += info.file_size
            _require(total <= 64 * 1024 * 1024, "wheel expansion exceeds its bound")
            records = [name for name in names if name.endswith(".dist-info/RECORD")]
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
            _require(
                len(records) == len(metadata_names) == len(wheel_names) == 1,
                "wheel metadata inventory is invalid",
            )
            payloads = {name: archive.read(name) for name in names}
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WorkerError("locked wheel is unreadable") from exc
    record_name = records[0]
    records_by_name = _record_rows(payloads[record_name])
    _require(set(records_by_name) == set(names), "wheel RECORD inventory is incomplete")
    for name, payload in payloads.items():
        if name == record_name:
            _require(records_by_name[name] == ("", ""), "wheel RECORD self-row is invalid")
        else:
            _verify_record(name, payload, records_by_name[name])
    metadata = BytesParser(policy=email_policy).parsebytes(payloads[metadata_names[0]])
    _require(
        _canonical_distribution(str(metadata.get("Name", "")))
        == _canonical_distribution(str(row["distribution"]))
        and metadata.get("Version") == row["version"],
        "wheel distribution metadata does not match its lock",
    )
    try:
        wheel_lines = payloads[wheel_names[0]].decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise WorkerError("wheel compatibility metadata is invalid") from exc
    tags = [line.removeprefix("Tag: ") for line in wheel_lines if line.startswith("Tag: ")]
    allowed = re.compile(
        r"^(?:py3-none-any|cp312-cp312-manylinux(?:2014|_2_(?:17|28))_x86_64|"
        r"cp(?:311|38)-abi3-manylinux(?:2014|_2_17)_x86_64)$"
    )
    _require(tags and all(allowed.fullmatch(tag) for tag in tags), "wheel tag is incompatible")
    for name, payload in payloads.items():
        _write_site_member(site, name, payload)


def _prepare_task_site(staging: Path, workspace: Path, request: Mapping[str, Any]) -> Path:
    if not (
        sys.implementation.name == "cpython"
        and sys.version_info[:2] == (3, 12)
        and sys.platform == "linux"
        and os.uname().machine == "x86_64"
    ):
        raise DependencyError(
            {
                "ready": False,
                "runtime": {
                    "implementation": sys.implementation.name,
                    "major": sys.version_info.major,
                    "minor": sys.version_info.minor,
                    "platform": sys.platform,
                    "architecture": os.uname().machine,
                },
            }
        )
    manifest_path = staging / "wheelhouse.json"
    manifest_payload, (manifest_size, manifest_digest) = _file_payload(manifest_path, 64 * 1024)
    authority = request["wheelhouse"]
    _require(
        manifest_size == authority["manifest_size"]
        and manifest_digest == authority["manifest_sha256"],
        "wheelhouse manifest identity changed",
    )
    try:
        manifest = json.loads(manifest_payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerError("wheelhouse manifest is invalid") from exc
    wheels = manifest.get("wheels") if isinstance(manifest, Mapping) else None
    _require(
        isinstance(manifest, Mapping)
        and set(manifest) == {"schema_version", "platform", "architecture", "python", "wheels"}
        and manifest.get("schema_version") == "bluefire.linux-wheelhouse.v1"
        and manifest.get("platform") == "linux"
        and manifest.get("architecture") == "x86_64"
        and manifest.get("python") == {"implementation": "cpython", "major": 3, "minor": 12}
        and isinstance(wheels, list)
        and len(wheels) == authority["wheel_count"] == 5,
        "wheelhouse manifest contract is invalid",
    )
    wheelhouse = staging / "wheelhouse"
    _require(
        wheelhouse.is_dir()
        and not wheelhouse.is_symlink()
        and {path.name for path in wheelhouse.iterdir()}
        == {str(row.get("filename")) for row in wheels if isinstance(row, Mapping)},
        "wheelhouse file inventory changed",
    )
    site = workspace / "site"
    site.mkdir(mode=0o700)
    for row in wheels:
        _require(
            isinstance(row, Mapping)
            and set(row) == {"distribution", "version", "filename", "size", "sha256"},
            "wheelhouse row is invalid",
        )
        _install_locked_wheel(wheelhouse / str(row["filename"]), row, site)
    shutil.copytree(staging / "product" / "bluefire", site / "bluefire")
    shutil.copyfile(staging / "product" / "pyproject.toml", site / "pyproject.toml")
    native = site / "bluefire" / "native" / "linux-x86_64"
    artifact = request["release_artifact"]
    _require(
        _file_payload(native / "runner-manifest.json", 64 * 1024)[1]
        == (artifact["manifest_size"], artifact["manifest_sha256"])
        and _file_payload(native / "bluefire-runner", 128 * 1024 * 1024)[1]
        == (artifact["binary_size"], artifact["binary_sha256"]),
        "commit-bound product runner resources changed",
    )
    return site


def _publish_supervisor(staging: Path, workspace_name: str) -> None:
    process_id = os.getpid()
    process_group_id = os.getpgrp()
    raw_stat = (Path("/proc") / "self" / "stat").read_text(encoding="ascii")
    close = raw_stat.rfind(")")
    fields = raw_stat[close + 2 :].split() if close >= 0 else []
    session_id = os.getsid(0)
    _require(
        process_id == process_group_id == session_id and len(fields) >= 20,
        "worker is not an isolated process-group supervisor",
    )
    record = {
        "schema_version": "bluefire.cross-platform-linux-supervisor.v1",
        "workspace_name": workspace_name,
        "process_id": process_id,
        "process_group_id": process_group_id,
        "session_id": session_id,
        "start_time_ticks": int(fields[19]),
    }
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    path = staging / "supervisor.json"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _receiver_child(authentication_key: bytes, messages: Any) -> None:
    from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig

    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=authentication_key,
            host="127.0.0.1",
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=60.0,
        )
    )
    messages.put(
        {
            "kind": "ready",
            "process_id": receiver.process_id,
            "host": receiver.host,
            "port": receiver.port,
        }
    )
    summary = receiver.serve()
    messages.put(
        {
            "kind": "complete",
            "summary": dict(summary),
            "bindings": [dict(item) for item in receiver.accepted_artifact_bindings],
        }
    )


def _secret_encodings(secret: bytes) -> tuple[bytes, ...]:
    return tuple(
        item
        for item in {
            secret,
            secret.hex().encode("ascii"),
            secret.hex().upper().encode("ascii"),
            base64.b64encode(secret),
            base64.b64encode(secret).rstrip(b"="),
            base64.urlsafe_b64encode(secret),
            base64.urlsafe_b64encode(secret).rstrip(b"="),
        }
        if item
    )


def _retained_receiver_key_factory(
    enrollment_key: bytes,
    derivation: Callable[[bytes, object], bytes],
) -> tuple[Callable[[object], bytes], list[bytes]]:
    retained: list[bytes] = []

    def factory(task_id: object) -> bytes:
        key = derivation(enrollment_key, task_id)
        _require(type(key) is bytes and len(key) == 32, "derived receiver key is invalid")
        retained.append(key)
        return key

    return factory, retained


def _scan_secrets(root: Path, secrets: Sequence[bytes]) -> None:
    _require(
        secrets and all(type(secret) is bytes and len(secret) == 32 for secret in secrets),
        "receiver secret inventory is invalid",
    )
    needles = tuple(
        dict.fromkeys(needle for secret in secrets for needle in _secret_encodings(secret))
    )
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        payload = path.read_bytes()
        total += len(payload)
        _require(total <= 64 * 1024 * 1024, "run scan exceeded bound")
        _require(not any(needle in payload for needle in needles), "receiver secret leaked")


def _network_binding(result: Mapping[str, Any]) -> Mapping[str, Any]:
    steps = result.get("steps")
    _require(isinstance(steps, list), "missing Execute steps")
    step = next(
        (
            item
            for item in steps
            if isinstance(item, Mapping)
            and item.get("behavior_id") == "sandbox.network.loopback.v1"
        ),
        None,
    )
    artifacts = step.get("artifacts") if isinstance(step, Mapping) else None
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    details = receipt.get("details") if isinstance(receipt, Mapping) else None
    _require(
        isinstance(step, Mapping)
        and step.get("status") == "success"
        and isinstance(step.get("runner_task_id"), str)
        and isinstance(receipt, Mapping)
        and isinstance(details, Mapping)
        and isinstance(details.get("sha256"), str)
        and isinstance(details.get("bytes_sent"), int),
        "network step lacks a bound runner receipt",
    )
    return {
        "run_id": result["run_id"],
        "step_id": step["step_id"],
        "runner_task_id": step["runner_task_id"],
        "authenticated": True,
        "sha256": details["sha256"],
        "bytes": details["bytes_sent"],
    }


def _scenario_document(
    product_root: Path, scenario_variant: object, port: object
) -> Mapping[str, Any]:
    from bluefire.contracts import load_scenario

    _require(scenario_variant in SCENARIO_VARIANTS, "invalid scenario variant")
    _require(type(port) is int and 1024 <= port <= 65535, "invalid receiver port")
    document = load_scenario(product_root / "bluefire" / "data" / SCENARIO).to_dict()
    if scenario_variant == "registered-alternate":
        alternate_step = next(
            item for item in document["steps"] if item.get("id") == "enumerate_fixture"
        )
        _require(
            alternate_step.get("behavior_id") == "sandbox.discovery.list.v1"
            and alternate_step.get("alternates") == ["sandbox.discovery.metadata.v1"],
            "registered Linux alternate changed",
        )
        alternate_step["behavior_id"] = "sandbox.discovery.metadata.v1"
        alternate_step["alternates"] = ["sandbox.discovery.list.v1"]
    transport_step = next(
        item for item in document["steps"] if item.get("id") == "internal_transport"
    )
    transport_step["parameters"]["port"] = port
    return document


def _run_product(
    staging: Path,
    workspace: Path,
    request: Mapping[str, Any],
    product_root: Path,
) -> Mapping[str, Any]:
    dependency_facts = _dependency_facts(product_root)
    if dependency_facts["ready"] is not True:
        raise DependencyError(dependency_facts)
    source_runner = staging / "runner"
    runner_path = workspace / "bluefire-runner"
    shutil.copyfile(source_runner, runner_path)
    os.chmod(runner_path, 0o700)
    artifact = request["release_artifact"]
    size, digest = _file_identity(runner_path, 128 * 1024 * 1024)
    _require(
        size == artifact["binary_size"] and digest == artifact["binary_sha256"],
        "staged runner identity changed",
    )
    acceptance = request["acceptance_binding"]
    for field, name in _ACCEPTANCE_ENV.items():
        os.environ[name] = str(acceptance[field])

    from bluefire.cross_platform_process_proof import posix_watchdog_crash_containment
    from bluefire.receiver_auth import derive_receiver_task_key
    from bluefire.runner_client import SubprocessRustRunner
    from bluefire.service import BlueFireService

    watchdog_containment = posix_watchdog_crash_containment(workspace / "watchdog-containment")
    sandbox = workspace / "sandbox"
    sandbox.mkdir(mode=0o700)
    receiver_key = secrets.token_bytes(32)
    task_key_factory, derived_receiver_keys = _retained_receiver_key_factory(
        receiver_key, derive_receiver_task_key
    )
    context = multiprocessing.get_context("fork")
    messages = context.Queue(maxsize=2)
    receiver = context.Process(target=_receiver_child, args=(receiver_key, messages))
    receiver.start()
    try:
        try:
            ready = messages.get(timeout=15)
        except queue.Empty as exc:
            raise WorkerError("receiver readiness timed out") from exc
        _require(
            isinstance(ready, Mapping)
            and set(ready) == {"kind", "process_id", "host", "port"}
            and ready.get("kind") == "ready"
            and ready.get("process_id") == receiver.pid
            and ready.get("host") == "127.0.0.1"
            and type(ready.get("port")) is int
            and 1024 <= int(ready["port"]) <= 65535
            and receiver.pid != os.getpid(),
            "receiver readiness is invalid",
        )
        runner = SubprocessRustRunner(
            runner_path,
            workspace / "transport",
            timeout_seconds=35.0,
            output_limit_bytes=4 * 1024 * 1024,
            receiver_task_key_factory=task_key_factory,
        )
        inventory = runner.inventory()
        _require(
            inventory.get("runner_id") == artifact["runner_id"]
            and inventory.get("runner_version") == artifact["runner_version"]
            and inventory.get("platform") == "linux",
            "runner inventory does not match the release artifact",
        )
        service = BlueFireService(
            project_root=product_root,
            runs_dir=workspace / "runs",
            product_db_path=workspace / "product.sqlite3",
            runner_factory=lambda _profile: (runner, sandbox),
        )
        try:
            scenario_document = _scenario_document(
                product_root,
                request["scenario_variant"],
                ready["port"],
            )
            result = service.run(
                {
                    "scenario": scenario_document,
                    "mode": "execute",
                    "runner_profile_id": PROFILE,
                    "target_scope": {
                        "scope_refs": [
                            "sandbox.workspace",
                            "network.loopback",
                            "export.local",
                        ]
                    },
                    "autonomy": "off",
                    "approval": {
                        "confirmed": True,
                        "approved_by": "cross-platform-linux-runtime-reviewer",
                    },
                }
            )
            run_id = result.get("run_id")
            cleanup = result.get("cleanup")
            _require(
                isinstance(run_id, str)
                and _RUN_ID.fullmatch(run_id) is not None
                and result.get("status") == "completed"
                and result.get("objective_reached") is True
                and isinstance(cleanup, Mapping)
                and cleanup.get("success") is True
                and cleanup.get("outstanding_receipt_count") == 0
                and service.store.validate_bundle(run_id).get("valid") is True,
                "production Linux Execute did not reconcile",
            )
            network = _network_binding(result)
        finally:
            service.close()
        try:
            complete = messages.get(timeout=20)
        except queue.Empty as exc:
            raise WorkerError("receiver completion timed out") from exc
        receiver.join(timeout=5)
        _require(receiver.exitcode == 0 and not receiver.is_alive(), "receiver did not exit")
        expected_summary = {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
        _require(
            isinstance(complete, Mapping)
            and complete.get("kind") == "complete"
            and complete.get("summary") == expected_summary
            and complete.get("bindings")
            == [
                {
                    "task_id": network["runner_task_id"],
                    "sha256": network["sha256"],
                    "bytes_received": network["bytes"],
                }
            ],
            "receiver and Execute evidence do not bind",
        )
        remaining = [path for path in sandbox.rglob("*") if path.is_file()]
        _require(not remaining, "Linux sandbox retained receipt-owned files")
        run_path = workspace / "runs" / str(run_id)
        _require(derived_receiver_keys, "Execute did not derive a receiver task key")
        _scan_secrets(run_path, (receiver_key, *derived_receiver_keys))
        output_runs = staging / "runs"
        output_runs.mkdir(exist_ok=False)
        shutil.copytree(run_path, output_runs / str(run_id))
        return {
            "schema_version": SUMMARY_SCHEMA,
            "passed": True,
            "run_id": run_id,
            "scenario_variant": request["scenario_variant"],
            "workspace_name": request["workspace_name"],
            "runner": dict(artifact),
            "watchdog_containment": watchdog_containment,
            "receiver": {
                "process_id": ready["process_id"],
                "process_distinct": True,
                "process_exited": True,
                "summary": expected_summary,
                "transfer": {
                    **network,
                    "destination_process_id": ready["process_id"],
                },
            },
            "workspace_removed": True,
        }
    finally:
        if receiver.is_alive():
            receiver.terminate()
            receiver.join(timeout=5)
        if receiver.is_alive():
            receiver.kill()
            receiver.join(timeout=5)
        _require(not receiver.is_alive(), "receiver process survived cleanup")
        receiver.close()
        receiver_key = b""
        for index in range(len(derived_receiver_keys)):
            derived_receiver_keys[index] = b""


def run() -> Mapping[str, Any]:
    staging = Path.cwd().resolve(strict=True)
    request = _load_request(staging)
    workspace = Path("/tmp") / str(request["workspace_name"])
    signal.signal(signal.SIGTERM, lambda _signal, _frame: (_ for _ in ()).throw(InterruptedError()))
    _require(not workspace.exists(), "Linux workspace identity is stale")
    _publish_supervisor(staging, str(request["workspace_name"]))
    workspace.mkdir(mode=0o700)
    details = workspace.stat()
    _require(
        details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) == 0o700,
        "Linux workspace ownership is unsafe",
    )
    result: Mapping[str, Any] | None = None
    try:
        product_root = _prepare_task_site(staging, workspace, request)
        sys.path.insert(0, os.fspath(product_root))
        result = _run_product(staging, workspace, request, product_root)
    finally:
        if workspace.exists():
            shutil.rmtree(workspace)
        _require(not workspace.exists(), "Linux workspace survived removal")
    _require(result is not None, "Linux product did not return evidence")
    return result


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    try:
        summary = run()
    except DependencyError as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "schema_version": "bluefire.cross-platform-linux-worker-error.v1",
                    "code": "linux_dependencies_unavailable",
                    "dependencies": exc.facts,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 1
    except BaseException:
        return 1
    sys.stdout.write(json.dumps(summary, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Opt-in official-SDK compatibility tests; subprocess cannot open network sockets."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tests_platform.test_s3_access_native_binding import planned_sends
from tests_platform.test_s3_access_policy import fixture
from tests_platform.test_s3_access_sdk import DATA, worker_request
from tests_platform.test_s3_access_wire import NOW, credential_row


@pytest.fixture(scope="module")
def offline_runtime():
    binary = os.environ.get("BLUEFIRE_S3_OFFLINE_PYTHON")
    manifest_path = os.environ.get("BLUEFIRE_S3_OFFLINE_MANIFEST")
    manifest_pin = os.environ.get("BLUEFIRE_S3_OFFLINE_MANIFEST_SHA256")
    if not binary or not manifest_path or not manifest_pin:
        pytest.skip("explicit reviewed offline-only SDK runtime is not configured")
    executable = Path(binary)
    raw = Path(manifest_path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest_pin
    manifest = json.loads(raw)
    assert manifest["status"] == "PINNED_OFFLINE_ONLY_NOT_ADMITTED_FOR_LIVE_USE"
    runtime = executable.parent.parent
    assert executable.is_absolute() and executable.is_file()
    assert str(runtime).lower() == manifest["runtime"].lower()

    def verify():
        expected = set()
        for row in manifest["files"]:
            relative = Path(row["path"])
            assert not relative.is_absolute() and ".." not in relative.parts
            path = runtime / relative
            assert not path.is_symlink()
            payload = path.read_bytes()
            assert len(payload) == row["bytes"]
            assert hashlib.sha256(payload).hexdigest() == row["sha256"]
            expected.add(relative.as_posix())
        observed = set()
        for path in runtime.rglob("*"):
            assert not path.is_symlink()
            if path.is_file():
                observed.add(path.relative_to(runtime).as_posix())
        assert observed == expected

    verify()
    try:
        yield executable
    finally:
        verify()


@pytest.mark.parametrize(
    "operation,scenario,expected,calls",
    [
        ("inspect_policy", "normal", "observed", 2),
        ("apply_policy", "normal", "observed", 4),
        ("rollback_policy", "normal", "observed", 4),
        ("probe_read", "normal", "observed", 4),
        ("legitimate_read", "normal", "observed", 5),
        ("probe_read", "denied", "observed", 4),
        ("probe_read", "redirect", "failed", 4),
        ("probe_read", "object_drift", "failed", 4),
        ("probe_read", "oversized", "failed", 4),
        ("probe_read", "missing_read_id", "failed", 4),
        ("apply_policy", "missing_put_id", "reconcile_required", 3),
        ("inspect_policy", "hostile_profile", "failed", 0),
        ("inspect_policy", "fixed_session", "observed", 2),
        ("legitimate_read", "fixed_session", "observed", 5),
        ("apply_policy", "fixed_session", "observed", 4),
    ],
)
def test_official_sdk_serialization_with_inert_transport(
    operation, scenario, expected, calls, offline_runtime
):
    executable = offline_runtime
    request = worker_request(operation)
    policy = fixture()[1]
    if operation == "rollback_policy":
        policy = request.to_dict()["policy_change"]["after"]
    repository = Path(__file__).absolute().parents[1]
    payload = {
        "repository": str(repository),
        "request": request.to_dict(),
        "now": NOW.isoformat(),
        "credentials": credential_row(),
        "policy": policy,
        "objects": [data.decode() for data in DATA],
        "scenario": scenario,
    }
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    environment.update(
        HOME=str(executable.parent),
        USERPROFILE=str(executable.parent),
        AWS_EC2_METADATA_DISABLED="true",
        BLUEFIRE_TEST_ORIGINAL_HOME=os.environ.get("USERPROFILE", ""),
    )
    completed = subprocess.run(
        [
            str(executable),
            "-I",
            "-B",
            str(Path(__file__).with_name("test_s3_access_sdk_offline_worker.py")),
        ],
        input=json.dumps(payload).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        env=environment,
    )
    assert completed.returncode == 0, "offline SDK compatibility probe failed"
    assert len(completed.stdout) < 16 * 1024 and not completed.stderr
    result = json.loads(completed.stdout)
    assert result["sdk_version"] == "1.43.110"
    assert result["result"]["outcome"] == expected
    assert result["http_calls"] == calls
    assert result["send_projections"] == planned_sends(request)[: result["permits"]]
    # urllib3's import-time IPv6 availability probe attempts one socket
    # construction; the audit hook denies it before any socket is created.
    assert result["counters"] == {
        "socket_construction_denied": 1,
        "network_connection_denied": 0,
        "ambient_reads_denied": 0,
        "credential_resolver_denied": 0,
    }
    assert result["production_runtime_admitted"] is False
    assert result["transport_mode"] == "official-sdk-with-inert-connection"
    assert result["session_configuration"] == (
        "fixed-runtime" if scenario == "fixed_session" else "injected-test-session"
    )
    if scenario == "denied":
        assert result["result"]["data"]["objects"][0]["result"] == "service_denied"

from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.cross_platform_artifact_validation import validate_transport_recovery_report
from bluefire.cross_platform_journey import (
    CrossPlatformJourneyError,
    _assert_secrets_absent,
    _execution_summary,
    _private_trust_material,
    _start_receiver,
    _stop_receiver_process,
)
from bluefire.cross_platform_recovery import transport_recovery
from bluefire.cross_platform_recovery_witness import (
    WITNESS_SCHEMA,
    RecoveryWitnessError,
    inspect_live_recovery,
    validate_witness_validation,
)
from bluefire.receiver_auth import derive_receiver_task_key
from bluefire.runner_bootstrap import RUNNER_ID
from bluefire.runner_lifecycle import (
    CLIENT_ID,
    ManagedRunnerLifecycle,
    _windows_process_id,
    _windows_process_in_job,
)
from bluefire.runner_trust import create_local_enrollment
from bluefire.service import BlueFireService


class _TrustMaterialEnrollment:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.server_private_key = root / "server-key.pem"
        self.client_private_key = root / "client-key.pem"
        self.server_private_key.write_bytes(b"server-private-material")
        self.client_private_key.write_bytes(b"client-private-material")

    @staticmethod
    def hmac_key() -> bytes:
        return b"h" * 32

    @staticmethod
    def server_key_password() -> bytes:
        return b"server-password-material"

    @staticmethod
    def client_key_password() -> bytes:
        return b"client-password-material"


def test_windows_execution_summary_binds_actual_step_count() -> None:
    result = {
        "run_id": "run-20260829T120000Z-abcdef0123456789",
        "status": "completed",
        "objective_reached": True,
        "cleanup": {"success": True, "outstanding_receipt_count": 0},
        "steps": [{"step_id": "one"}, {"step_id": "two"}],
    }

    assert _execution_summary(result)["step_count"] == 2
    with pytest.raises(CrossPlatformJourneyError, match="did not reconcile"):
        _execution_summary({**result, "steps": []})


def test_windows_evidence_scan_includes_derived_receiver_task_key(tmp_path: Path) -> None:
    enrollment_root = tmp_path / "enrollment"
    enrollment_root.mkdir()
    enrollment = _TrustMaterialEnrollment(enrollment_root)
    task_id = "execute-" + "a" * 64
    derived = derive_receiver_task_key(enrollment.hmac_key(), task_id)

    materials = _private_trust_material(enrollment, (task_id,))
    assert derived in materials
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "report.json").write_bytes(base64.urlsafe_b64encode(derived))
    with pytest.raises(CrossPlatformJourneyError, match="trust material leaked"):
        _assert_secrets_absent(evidence, materials)


@pytest.mark.skipif(os.name != "nt", reason="the packaged receiver journey is Windows-only")
def test_disposable_receiver_retains_the_exact_process_handle_and_job(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    managed_root = tmp_path / "BlueFire Nexus"
    managed_root.mkdir()
    create_local_enrollment(
        managed_root / "enrollment",
        runner_id=RUNNER_ID,
        client_id=CLIENT_ID,
        allowed_profile_ids=("sandbox-endpoint-deep-lab.v1",),
    )
    receiver, ready = _start_receiver(repository, tmp_path)
    try:
        assert receiver.process_handle is not None
        assert receiver.job_handle is not None
        assert receiver.process_id == ready["process_id"]
        assert _windows_process_id(receiver.process_handle) == ready["process_id"]
        assert _windows_process_in_job(receiver.process_handle, receiver.job_handle)
    finally:
        _stop_receiver_process(receiver)
    assert receiver.launcher.poll() is not None


@pytest.mark.skipif(os.name != "nt", reason="the packaged recovery journey is Windows-only")
def test_authenticated_transport_recovery_is_full_and_independently_validated(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    lifecycle = ManagedRunnerLifecycle(tmp_path / "managed")
    service: BlueFireService | None = None

    def require(condition: bool, message: str) -> None:
        assert condition, message

    try:
        lifecycle.bootstrap(
            allowed_profile_ids=("sandbox-endpoint-deep-lab.v1",),
            environ={},
            resource_root=repository / "bluefire" / "native",
        )
        assert lifecycle.start(profile_id="sandbox-endpoint-deep-lab.v1")["state"] == "ready"
        service = BlueFireService(
            project_root=repository,
            runs_dir=tmp_path / "runs",
            product_db_path=tmp_path / "product.sqlite3",
            runner_lifecycle=lifecycle,
        )
        report = transport_recovery(service, lifecycle, require=require)
        witness = report["witness_validation"]
        validate_witness_validation(witness)
        stages = witness["stages"]
        assert witness["schema_version"] == WITNESS_SCHEMA
        assert stages["before_interruption"]["receipt_count"] == 1
        assert stages["after_recovery"]["receipt_count"] == 1
        assert stages["after_cleanup"]["receipt_count"] == 0
        assert stages["after_cleanup"]["effect_exists"] is False
        assert stages["after_recovered_host_stop"]["host_before_absent"] is True
        assert stages["after_recovered_host_stop"]["host_after_absent"] is True
        assert stages["continuation"]["host_running"] is True
        assert str(tmp_path) not in str(witness)
        tampered = copy.deepcopy(witness)
        tampered["stages"]["after_cleanup"]["receipt_count"] = 1
        with pytest.raises(RecoveryWitnessError, match="stage digest"):
            validate_witness_validation(tampered)
        validate_transport_recovery_report(report)
    finally:
        if service is not None:
            service.close()
        if lifecycle.root.exists():
            status = lifecycle.status(profile_id="sandbox-endpoint-deep-lab.v1")
            if status["state"] == "ready" or status["process"] not in {"absent", "stopped"}:
                lifecycle.stop(profile_id="sandbox-endpoint-deep-lab.v1")
            status = lifecycle.status(profile_id="sandbox-endpoint-deep-lab.v1")
            if status["enrollment"] == "active":
                lifecycle.revoke()
            if lifecycle.status()["enrollment"] == "revoked":
                lifecycle.remove(confirm_runner_id=RUNNER_ID)


class _ReportOnlyRecoveryClient:
    def health(self) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.runner-health.v1",
            "status": "ready",
            "transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
            "ledger": {
                "generation": "sha256:" + "1" * 64,
                "rows": 1,
                "execute_rows": 1,
                "accepting_execute": True,
            },
        }

    def recover(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        return {
            "original_task_id": task_id,
            "original_request_hash": request_hash,
            "state": "completed",
            "result": {},
            "error_code": None,
            "cancellation_requested": False,
            "receipt_ids": [],
            "cleanup_required": False,
        }


def test_report_only_recovery_claim_cannot_substitute_for_live_witness(
    tmp_path: Path,
) -> None:
    with pytest.raises(RecoveryWitnessError, match="live receipt root is unavailable"):
        inspect_live_recovery(
            client=_ReportOnlyRecoveryClient(),
            sandbox=tmp_path,
            task_id="execute-" + "2" * 64,
            request_hash="sha256:" + "2" * 64,
            receipt_id="3" * 64,
            expected_result={},
            expected_generation="sha256:" + "1" * 64,
            client_process_id=os.getpid(),
            host_process_id=os.getpid(),
            stage="before_interruption",
        )

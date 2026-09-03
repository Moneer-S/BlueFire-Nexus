from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_linux_cleanup_validation as cleanup_module
from bluefire.cross_platform_linux_cleanup_validation import (
    LINUX_CLEANUP_VERIFIER,
    LinuxCleanupValidationError,
    validate_linux_cleanup_boundary,
)
from bluefire.cross_platform_readiness import WSL_DISTRIBUTION_ID
from bluefire.util import content_hash


@pytest.fixture(autouse=True)
def _fixed_live_absence_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    def verified(distribution_name: str) -> list[Mapping[str, Any]]:
        assert distribution_name == "BlueFire-Gate11-Run-0123456789abcdef"
        return [{"delay_ms": delay, "registered": False} for delay in (0, 100, 250)]

    monkeypatch.setattr(cleanup_module, "probe_distribution_absence", verified)


def _repository() -> Path:
    return Path(__file__).resolve().parents[1]


def _facts() -> Mapping[str, Any]:
    return {
        "provider": "wsl2",
        "probe_state": "ready",
        "configured": True,
        "distribution_id": WSL_DISTRIBUTION_ID,
        "version": "2",
        "facts_digest": "sha256:" + "1" * 64,
    }


def _verifier_digest(repository: Path) -> str:
    path = repository / Path(*LINUX_CLEANUP_VERIFIER.split("/"))
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _boundary(repository: Path) -> dict[str, Any]:
    workspace_name = "bluefire-gate11-0123456789abcdef"
    identities = [
        {
            "process_id": 101,
            "process_group_id": 101,
            "session_id": 101,
            "start_time_ticks": 202,
        },
        {
            "process_id": 303,
            "process_group_id": 101,
            "session_id": 101,
            "start_time_ticks": 304,
        },
    ]
    identity_material = {
        "schema_version": "bluefire.cross-platform-linux-cleanup-identities.v1",
        "workspace_name": workspace_name,
        "process_identities": identities,
    }
    return {
        **_facts(),
        "source_distribution_persistent": True,
        "execution_distribution_id": "BlueFire-Gate11-Run-0123456789abcdef",
        "execution_distribution_disposable": True,
        "execution_distribution_removed": True,
        "distribution_storage_removed": True,
        "distribution_absence_probes": [
            {"delay_ms": delay, "registered": False} for delay in (0, 100, 250)
        ],
        "workspace_disposable": True,
        "workspace_removed": True,
        "workspace_name": workspace_name,
        "worker_process_exited": True,
        "worker_process_id": 101,
        "process_group_id": 101,
        "session_id": 101,
        "worker_start_time_ticks": 202,
        "survivor_probes": [
            {"delay_ms": 0, "running": False},
            {"delay_ms": 100, "running": False},
            {"delay_ms": 250, "running": False},
        ],
        "cleanup_verification": {
            "schema_version": "bluefire.cross-platform-linux-cleanup-verification.v1",
            "workspace_name": workspace_name,
            "workspace_absent": True,
            "process_identities_absent": True,
            "process_identity_count": len(identities),
            "identity_material": identity_material,
            "identity_material_sha256": content_hash(identity_material),
            "verifier_sha256": _verifier_digest(repository),
            "probe_delays_ms": [0, 100, 250],
        },
    }


def _rehash_identity_material(boundary: dict[str, Any]) -> None:
    verification = boundary["cleanup_verification"]
    verification["identity_material_sha256"] = content_hash(verification["identity_material"])


def test_linux_cleanup_boundary_binds_exact_persisted_identities() -> None:
    repository = _repository()
    boundary = _boundary(repository)

    assert validate_linux_cleanup_boundary(repository, boundary, fresh_wsl=_facts()) == boundary


def test_linux_cleanup_absence_reprobe_targets_disposable_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked: list[str] = []

    def absent(distribution_name: str) -> list[Mapping[str, Any]]:
        invoked.append(distribution_name)
        return [{"delay_ms": delay, "registered": False} for delay in (0, 100, 250)]

    monkeypatch.setattr(cleanup_module, "probe_distribution_absence", absent)

    boundary = _boundary(_repository())
    validate_linux_cleanup_boundary(_repository(), boundary, fresh_wsl=_facts())

    assert invoked == [boundary["execution_distribution_id"]]


@pytest.mark.parametrize(
    "tamper",
    [
        "identity_digest",
        "verifier_digest",
        "outer_workspace",
        "identity_workspace",
        "identity_count",
        "worker_identity",
        "identity_fields",
        "duplicate_identity",
    ],
)
def test_linux_cleanup_boundary_rejects_unbound_or_tampered_claims(tamper: str) -> None:
    repository = _repository()
    boundary = copy.deepcopy(_boundary(repository))
    verification = boundary["cleanup_verification"]
    identity_material = verification["identity_material"]
    if tamper == "identity_digest":
        verification["identity_material_sha256"] = "sha256:" + "0" * 64
    elif tamper == "verifier_digest":
        verification["verifier_sha256"] = "sha256:" + "0" * 64
    elif tamper == "outer_workspace":
        boundary["workspace_name"] = "bluefire-gate11-fedcba9876543210"
    elif tamper == "identity_workspace":
        identity_material["workspace_name"] = "bluefire-gate11-fedcba9876543210"
        _rehash_identity_material(boundary)
    elif tamper == "identity_count":
        verification["process_identity_count"] += 1
    elif tamper == "worker_identity":
        boundary["worker_start_time_ticks"] += 1
    elif tamper == "identity_fields":
        del identity_material["process_identities"][0]["session_id"]
        _rehash_identity_material(boundary)
    elif tamper == "duplicate_identity":
        identity_material["process_identities"].append(
            copy.deepcopy(identity_material["process_identities"][0])
        )
        verification["process_identity_count"] += 1
        _rehash_identity_material(boundary)

    with pytest.raises(LinuxCleanupValidationError):
        validate_linux_cleanup_boundary(repository, boundary, fresh_wsl=_facts())


def test_linux_cleanup_boundary_rehashes_repository_verifier(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    verifier = repository / Path(*LINUX_CLEANUP_VERIFIER.split("/"))
    verifier.parent.mkdir(parents=True)
    verifier.write_bytes((_repository() / Path(*LINUX_CLEANUP_VERIFIER.split("/"))).read_bytes())
    boundary = _boundary(repository)
    verifier.write_bytes(verifier.read_bytes() + b"\n")

    with pytest.raises(LinuxCleanupValidationError):
        validate_linux_cleanup_boundary(repository, boundary, fresh_wsl=_facts())


def test_linux_cleanup_boundary_rejects_live_absence_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository()
    boundary = _boundary(repository)
    monkeypatch.setattr(cleanup_module, "probe_distribution_absence", lambda _name: [])

    with pytest.raises(LinuxCleanupValidationError, match="live WSL distribution absence"):
        validate_linux_cleanup_boundary(repository, boundary, fresh_wsl=_facts())

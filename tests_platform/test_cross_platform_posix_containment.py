from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import bluefire.cross_platform_process_proof as process_proof_module
from bluefire.cross_platform_linux_bundle_validation import validate_linux_bundle
from bluefire.cross_platform_process_proof import (
    POSIX_CONTAINMENT_IDENTITIES_SCHEMA,
    POSIX_CONTAINMENT_SCHEMA,
    ProcessProofError,
    validate_posix_watchdog_containment_proof,
)
from bluefire.util import content_hash


def _containment_proof() -> dict[str, Any]:
    identity_material = {
        "schema_version": POSIX_CONTAINMENT_IDENTITIES_SCHEMA,
        "child_program": "system-sleep",
        "child_executable_sha256": "sha256:" + "a" * 64,
        "parent_death_helper_sha256": "sha256:" + "b" * 64,
        "supervisor": {
            "process_id": 701,
            "process_group_id": 701,
            "session_id": 701,
            "start_time_ticks": 7001,
        },
        "child": {
            "process_id": 702,
            "process_group_id": 701,
            "session_id": 701,
            "start_time_ticks": 7002,
        },
    }
    return {
        "schema_version": POSIX_CONTAINMENT_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "platform": "linux",
        "containment": "linux-parent-death-signal-private-session",
        "forced_signal": "SIGKILL",
        "termination_scope": "supervisor-pidfd-only",
        "parent_death_contract": "PR_SET_PDEATHSIG",
        "identity_material": identity_material,
        "identity_material_sha256": content_hash(identity_material),
        "supervisor_reaped": True,
        "child_reaped": True,
        "supervisor_exit_signal": "SIGKILL",
        "child_exit_signal": "SIGKILL",
        "pidfd_exit_observed": True,
        "absence_probes": [
            {
                "delay_ms": delay,
                "supervisor_identity_present": False,
                "child_identity_present": False,
            }
            for delay in (0, 100, 250)
        ],
    }


def _raise_requirement(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_linux_watchdog_containment_proof_is_exact_and_hash_bound() -> None:
    proof = _containment_proof()
    assert validate_posix_watchdog_containment_proof(proof) == proof

    proof["termination_scope"] = "process-group"
    with pytest.raises(ProcessProofError, match="containment proof is invalid"):
        validate_posix_watchdog_containment_proof(proof)

    proof = _containment_proof()
    proof["identity_material"]["child"]["start_time_ticks"] += 1
    with pytest.raises(ProcessProofError, match="containment proof is invalid"):
        validate_posix_watchdog_containment_proof(proof)


@pytest.mark.parametrize(
    "substitution",
    [True, {"passed": True}, {"report": "posix-watchdog-containment.json"}],
    ids=("boolean-only", "claim-only", "report-only"),
)
def test_linux_bundle_rejects_watchdog_containment_substitution(
    tmp_path: Path,
    substitution: object,
) -> None:
    with pytest.raises(AssertionError, match="watchdog containment proof"):
        validate_linux_bundle(
            tmp_path,
            {
                "run_id": "run-20260830T120000Z-0123456789abcdef",
                "watchdog_containment": substitution,
            },
            scenario_variant="primary",
            require=_raise_requirement,
        )


def test_linux_bundle_requires_watchdog_containment_field(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="watchdog containment proof"):
        validate_linux_bundle(
            tmp_path,
            {"run_id": "run-20260830T120000Z-0123456789abcdef"},
            scenario_variant="primary",
            require=_raise_requirement,
        )


def test_parent_death_helper_is_execution_layer_and_bounded() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = json.loads(
        (root / "bluefire" / "data" / "architecture_policy.json").read_text(encoding="utf-8")
    )
    execution = next(rule for rule in policy["python_layer_rules"] if rule["layer"] == "execution")

    assert "bluefire.runner_parent_death" in execution["patterns"]
    assert (
        len((root / "bluefire" / "runner_parent_death.py").read_text(encoding="utf-8").splitlines())
        <= 1_000
    )


def test_pidfd_identity_change_is_closed_without_signal_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = {
        "process_id": 701,
        "process_group_id": 701,
        "session_id": 701,
        "start_time_ticks": 7001,
    }
    changed = {**identity, "start_time_ticks": 8001}
    observations = iter((identity, changed))
    closed: list[int] = []
    monkeypatch.setattr(
        process_proof_module,
        "_linux_process_identity",
        lambda _process_id: next(observations),
    )
    monkeypatch.setattr(process_proof_module, "_PIDFD_OPEN", lambda _pid, _flags: 91)
    monkeypatch.setattr(process_proof_module.os, "close", closed.append)

    with pytest.raises(ProcessProofError, match="pidfd is not identity-bound"):
        process_proof_module._open_identity_bound_pidfd(identity)

    assert closed == [91]


def test_failure_cleanup_stops_verified_session_members_before_reaping_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leader = {
        "process_id": 701,
        "process_group_id": 701,
        "session_id": 701,
        "start_time_ticks": 7001,
    }
    child = {
        "process_id": 702,
        "process_group_id": 701,
        "session_id": 701,
        "start_time_ticks": 7002,
    }
    events: list[tuple[str, int]] = []

    def open_pidfd(identity: dict[str, int]) -> int:
        events.append(("open", identity["process_id"]))
        return 92

    def reap(process_id: int, _deadline: float) -> int:
        events.append(("reap", process_id))
        return 9

    monkeypatch.setattr(
        process_proof_module,
        "_linux_private_session_identities",
        lambda _leader: (leader, child),
    )
    monkeypatch.setattr(
        process_proof_module,
        "_open_identity_bound_pidfd",
        open_pidfd,
    )
    monkeypatch.setattr(process_proof_module, "_linux_identity_present", lambda _identity: True)
    monkeypatch.setattr(
        process_proof_module,
        "_PIDFD_SEND_SIGNAL",
        lambda descriptor, _signal, _info, _flags: events.append(("signal", descriptor)),
    )
    monkeypatch.setattr(
        process_proof_module,
        "_wait_for_reaped_process",
        reap,
    )
    pidfds = {701: 91}

    reaped = process_proof_module._cleanup_failed_posix_private_session(leader, pidfds)

    assert events == [
        ("open", 702),
        ("signal", 92),
        ("signal", 91),
        ("reap", 701),
        ("reap", 702),
    ]
    assert pidfds == {701: 91, 702: 92}
    assert reaped == {701, 702}

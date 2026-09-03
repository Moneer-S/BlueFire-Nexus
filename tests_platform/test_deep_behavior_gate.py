from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import bluefire.deep_behavior_gate as gate_module
import bluefire.product_gates as product_gates
from bluefire.deep_behavior_gate_validation import (
    ASSERTION_REPORTS,
    CHECK_NAMES,
    JOURNEY_REPORT_PATHS,
)
from bluefire.product_acceptance import load_release_contract


def _gate() -> Any:
    return next(item for item in load_release_contract().gates if item.gate_id == "GATE-03")


def _helper(*, blocking_check: str | None = None) -> Mapping[str, Any]:
    passed = blocking_check is None
    return {
        "schema_version": "bluefire.deep-behavior-helper.v1",
        "status": "passed" if passed else "failed",
        "blocking_check": blocking_check,
        "reports": list(JOURNEY_REPORT_PATHS),
        "run_count": 5 if passed else 0,
        "exit_code": 0 if passed else 1,
        "command": ["{python}", "tools/run_deep_behavior_gate_journey.py", "{fixed-arguments}"],
        "protocol_valid": True,
        "passed": passed,
    }


def _suite() -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": "deep-behavior-contracts",
        "command": [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *gate_module._CONTRACT_TESTS,
            "--junitxml={temporary}",
        ],
        "exit_code": 0,
        "passed": True,
        "tests": 0,
        "passed_tests": [],
        "failed_tests": [],
        "skipped_tests": [],
    }


def _bundles() -> tuple[Mapping[str, str], ...]:
    return tuple(
        {
            "run_id": f"run-20260830T12000{index}Z-{index:016x}",
            "path": f"runs/run-20260830T12000{index}Z-{index:016x}",
        }
        for index in range(5)
    )


def test_gate03_locked_contract_and_dispatcher_match_validator() -> None:
    gate = _gate()

    assert [(item.assertion_id, item.proof) for item in gate.assertions] == [
        (assertion_id, proof) for assertion_id, proof, _report in ASSERTION_REPORTS
    ]
    assert product_gates._WORKFLOWS["GATE-03"] is product_gates._gate_03_workflow
    assert set(gate_module._ASSERTION_CHECKS.values()) == CHECK_NAMES


def test_gate03_returns_only_the_validated_typed_linux_blocker(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        gate_module, "_run_helper", lambda *_args: _helper(blocking_check="linux_primary")
    )
    monkeypatch.setattr(
        gate_module,
        "validate_linux_unavailable_report",
        lambda *_args: "GATE-03 Linux runtime is unavailable",
    )

    outcome = gate_module.run_gate_03(_gate(), tmp_path, repository_root=Path.cwd())

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason == "GATE-03 Linux runtime is unavailable"


def test_gate03_success_requires_all_checks_five_bundles_and_unique_proofs(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    checks = {name: True for name in CHECK_NAMES}
    bundles = _bundles()
    validations: list[tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]] = []
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_ID", "gate03-test")
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_GATE_ID", "GATE-03")
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256", "sha256:" + "3" * 64)
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT", "4" * 40)
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE", "5" * 40)
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_RELEASE", "true")
    monkeypatch.setattr(gate_module, "_run_helper", lambda *_args: _helper())
    monkeypatch.setattr(gate_module, "_run_pytest_suite", lambda *_args, **_kwargs: _suite())
    monkeypatch.setattr(gate_module, "_suite_is_exact", lambda _value: True)

    def validate(
        *_args: Any, **_kwargs: Any
    ) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
        validations.append((checks, bundles))
        return checks, bundles

    monkeypatch.setattr(gate_module, "validate_deep_behavior_reports", validate)
    monkeypatch.setattr(
        gate_module, "validate_deep_behavior_verification", lambda *_args, **_kwargs: None
    )

    outcome = gate_module.run_gate_03(_gate(), tmp_path, repository_root=Path.cwd())

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(validations) == 2
    assert len(outcome.proofs) == 15
    assert len({proof["test_id"] for proof in outcome.proofs}) == 15
    assert {item for proof in outcome.proofs for item in proof["run_ids"]} == {
        bundle["run_id"] for bundle in bundles
    }


def test_gate03_suite_inventory_is_exact_and_rejects_skips(monkeypatch: Any) -> None:
    report = dict(_suite())
    report["tests"] = 1
    report["passed_tests"] = ["tests_platform.test_gate03::test_locked"]
    monkeypatch.setattr(gate_module, "_EXPECTED_SUITE_TEST_COUNT", 1)
    monkeypatch.setattr(
        gate_module,
        "_EXPECTED_SUITE_TESTS_SHA256",
        gate_module.content_hash(report["passed_tests"]),
    )
    assert gate_module._suite_is_exact(report)

    report["skipped_tests"] = ["not-allowed"]
    assert not gate_module._suite_is_exact(report)


def test_gate03_production_modules_stay_within_architecture_budget() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *sorted((root / "bluefire").glob("deep_behavior*.py")),
        root / "tools" / "run_deep_behavior_gate_journey.py",
    ]

    assert paths
    assert all(len(path.read_text(encoding="utf-8").splitlines()) <= 1_000 for path in paths)

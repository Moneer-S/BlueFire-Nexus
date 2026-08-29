"""Focused contract tests for the executable GATE-10 workflow."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

import bluefire.architecture_gate as architecture_gate
import bluefire.product_gates as product_gates
from bluefire.product_acceptance import load_release_contract

REPOSITORY = Path(__file__).resolve().parents[1]

_STRUCTURAL_CHECKS = (
    "python_decomposition",
    "rust_decomposition",
    "file_size_budget",
    "dependency_direction",
    "import_cycles",
    "crypto_primitives",
    "responsibility_separation",
)

_PROOF_EXPECTATIONS = {
    "GATE-10-PYTHON-DECOMPOSITION": (
        "structural",
        "architecture-report.json",
        "GATE-10.python-decomposition.v1",
    ),
    "GATE-10-DEPENDENCY-DIRECTION": (
        "structural",
        "architecture-report.json",
        "GATE-10.dependency-direction.v1",
    ),
    "GATE-10-IMPORT-CYCLES": (
        "structural",
        "architecture-report.json",
        "GATE-10.import-cycles.v1",
    ),
    "GATE-10-PROPERTY-FUZZ": (
        "dynamic",
        "property-fuzz-report.json",
        "GATE-10.property-fuzz.v1",
    ),
    "GATE-10-BEHAVIOR-PRESERVATION": (
        "dynamic",
        "behavior-preservation-report.json",
        "GATE-10.behavior-preservation.v1",
    ),
}


def _passing_dynamic_report(suite_id: str, tests: Sequence[str]) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": suite_id,
        "command": ["{python}", "-m", "pytest"],
        "exit_code": 0,
        "passed": True,
        "tests": len(tests),
        "passed_tests": list(tests),
        "failed_tests": [],
        "skipped_tests": [],
    }


def _controlled_architecture_report(_repository: Path) -> dict[str, Any]:
    passed = {
        "python_decomposition",
        "dependency_direction",
        "import_cycles",
    }
    return {
        "schema_version": architecture_gate.REPORT_SCHEMA_VERSION,
        "policy_sha256": "sha256:" + "0" * 64,
        "checks": {
            name: {
                "passed": name in passed,
                "findings": (
                    [] if name in passed else [{"code": "controlled_blocker", "check": name}]
                ),
            }
            for name in _STRUCTURAL_CHECKS
        },
        "size_budget": {"files": [], "findings": []},
        "dependencies": {"python": {"cycles": []}, "rust": {"cycles": []}},
        "responsibilities": {"assignments": [], "findings": []},
        "crypto": {"findings": [], "maintained_primitive_uses": []},
    }


def test_repository_audit_emits_machine_readable_concrete_blockers() -> None:
    report = architecture_gate.audit_repository(REPOSITORY)

    assert report["schema_version"] == "bluefire.architecture-audit.v1"
    assert set(report["checks"]) == set(_STRUCTURAL_CHECKS)
    assert report["policy_sha256"].startswith("sha256:")
    size = report["size_budget"]
    assert size["files"]
    assert {row["language"] for row in size["files"]} == {"python", "rust"}
    assert all(
        set(row)
        == {
            "path",
            "language",
            "classification",
            "lines",
            "limit",
            "exception_applied",
        }
        for row in size["files"]
    )
    assert isinstance(size["findings"], list)
    assert all(
        isinstance(check["passed"], bool) and isinstance(check["findings"], list)
        for check in report["checks"].values()
    )

    dependencies = report["dependencies"]
    assert isinstance(dependencies["python"]["edges"], list)
    assert isinstance(dependencies["rust"]["edges"], list)
    assert isinstance(dependencies["python"]["cycles"], list)
    assert isinstance(dependencies["rust"]["cycles"], list)
    assert isinstance(dependencies["findings"], list)
    assert isinstance(report["responsibilities"]["assignments"], list)
    assert isinstance(report["responsibilities"]["findings"], list)
    assert isinstance(report["crypto"]["findings"], list)
    assert isinstance(report["crypto"]["maintained_primitive_uses"], list)


def test_policy_is_fail_closed_and_synthetic_violations_remain_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bluefire").mkdir()
    (tmp_path / "runner" / "src").mkdir(parents=True)
    (tmp_path / "bluefire" / "adapter.py").write_text("ERROR = 1\n", encoding="utf-8")
    (tmp_path / "bluefire" / "service.py").write_text(
        "from .adapter import ERROR\n"
        "PERSIST_MARKER = True\n"
        "SECURITY_MARKER = True\n"
        "VALUE = ERROR\n"
        "EXTRA = VALUE\n",
        encoding="utf-8",
    )
    (tmp_path / "runner" / "src" / "lib.rs").write_text(
        "pub const VALUE: u8 = 1;\n", encoding="utf-8"
    )
    policy: dict[str, Any] = {
        "schema_version": "bluefire.architecture-policy.v1",
        "baseline_commit": "0" * 40,
        "line_budgets": {"new_file": 3, "existing_file": 4, "exceptions": []},
        "production_roots": [
            {"path": "bluefire", "extensions": [".py"]},
            {"path": "runner/src", "extensions": [".rs"]},
        ],
        "python_layer_rules": [
            {"layer": "adapter", "patterns": ["bluefire.adapter"]},
            {"layer": "service", "patterns": ["bluefire.service"]},
        ],
        "allowed_python_dependencies": {
            "adapter": ["adapter", "service"],
            "service": ["service"],
        },
        "rust_layers": {"lib": "foundation"},
        "allowed_rust_dependencies": {"foundation": ["foundation"]},
        "decomposition_hotspots": {
            "python": ["bluefire/service.py", "bluefire/missing.py"],
            "rust": ["runner/src/missing.rs"],
        },
        "responsibility_markers": {
            "persistence": ["PERSIST_MARKER"],
            "security_protocol": ["SECURITY_MARKER"],
        },
        "custom_crypto_markers": [],
        "maintained_crypto_markers": [],
    }
    policy_path = tmp_path / "architecture-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    def fake_git_object(_repository: Path, object_name: str) -> bool:
        return object_name.endswith("^{commit}") or ":" in object_name

    monkeypatch.setattr(architecture_gate, "_git_object_exists", fake_git_object)

    report = architecture_gate.audit_repository(tmp_path, policy_path=policy_path)
    python_decomposition = report["checks"]["python_decomposition"]
    assert python_decomposition["passed"] is False
    assert {finding["code"] for finding in python_decomposition["findings"]} == {
        "undecomposed_hotspot",
        "decomposition_hotspot_missing",
        "responsibilities_co_located",
    }
    assert report["checks"]["rust_decomposition"] == {
        "passed": False,
        "findings": [{"code": "decomposition_hotspot_missing", "path": "runner/src/missing.rs"}],
    }
    assert any(
        finding["code"] == "line_budget_exceeded" and finding["path"] == "bluefire/service.py"
        for finding in report["size_budget"]["findings"]
    )
    assert any(
        finding["code"] == "python_dependency_direction"
        and finding["source"] == "bluefire.service"
        and finding["target"] == "bluefire.adapter"
        for finding in report["dependencies"]["findings"]
    )
    assert report["responsibilities"]["findings"] == [
        {
            "code": "responsibilities_co_located",
            "path": "bluefire/service.py",
            "responsibilities": ["persistence", "security_protocol"],
        }
    ]

    invalid_path = tmp_path / "invalid-policy.json"
    invalid = dict(policy)
    invalid.pop("custom_crypto_markers")
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="policy fields are invalid"):
        architecture_gate.audit_repository(tmp_path, policy_path=invalid_path)


def test_tools_dependencies_and_cycles_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bluefire").mkdir()
    (tmp_path / "tools").mkdir()
    (tmp_path / "runner" / "src").mkdir(parents=True)
    (tmp_path / "bluefire" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "bluefire" / "domain.py").write_text(
        "import tools.one\nVALUE = tools.one.VALUE\n",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "tools" / "one.py").write_text(
        "from tools import two\nVALUE = two.VALUE\n",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "two.py").write_text(
        "from tools.one import VALUE as ONE_VALUE\nVALUE = ONE_VALUE\n",
        encoding="utf-8",
    )
    (tmp_path / "runner" / "src" / "lib.rs").write_text(
        "pub const VALUE: u8 = 1;\n", encoding="utf-8"
    )
    policy = {
        "schema_version": "bluefire.architecture-policy.v1",
        "baseline_commit": "0" * 40,
        "line_budgets": {"new_file": 100, "existing_file": 100, "exceptions": []},
        "production_roots": [
            {"path": "bluefire", "extensions": [".py"]},
            {"path": "tools", "extensions": [".py"]},
            {"path": "runner/src", "extensions": [".rs"]},
        ],
        "python_layer_rules": [
            {"layer": "foundation", "patterns": ["bluefire.*"]},
            {"layer": "acceptance", "patterns": ["tools", "tools.*"]},
        ],
        "allowed_python_dependencies": {
            "foundation": ["foundation"],
            "acceptance": ["acceptance", "foundation"],
        },
        "rust_layers": {"lib": "foundation"},
        "allowed_rust_dependencies": {"foundation": ["foundation"]},
        "decomposition_hotspots": {"python": [], "rust": []},
        "responsibility_markers": {},
        "custom_crypto_markers": [],
        "maintained_crypto_markers": [],
    }
    policy_path = tmp_path / "architecture-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(architecture_gate, "_git_object_exists", lambda *_args: True)

    report = architecture_gate.audit_repository(tmp_path, policy_path=policy_path)

    assert report["checks"]["dependency_direction"]["passed"] is False
    assert {
        (finding["source"], finding["target"])
        for finding in report["dependencies"]["findings"]
        if finding["code"] == "python_dependency_direction"
    } == {("bluefire.domain", "tools.one")}
    assert report["checks"]["import_cycles"]["passed"] is False
    assert report["dependencies"]["python"]["cycles"] == [["tools.one", "tools.two"]]
    assert report["dependencies"]["python"]["layers"]["tools.__init__"] == "acceptance"
    edges = {(edge["source"], edge["target"]) for edge in report["dependencies"]["python"]["edges"]}
    assert {
        ("bluefire.domain", "tools.one"),
        ("tools.one", "tools.__init__"),
        ("tools.one", "tools.two"),
        ("tools.two", "tools.one"),
    }.issubset(edges)


def test_dynamic_suite_rejects_skipped_tests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite_temporary: list[Path] = []

    def fake_run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        temporary = Path(environment["TEMP"])
        assert environment["TMP"] == str(temporary)
        assert environment["TMPDIR"] == str(temporary)
        assert temporary.parent == tmp_path
        suite_temporary.append(temporary)
        scratch = temporary / "pytest-of-fixture" / "test-case"
        scratch.mkdir(parents=True)
        (scratch / "product.sqlite3").write_bytes(b"temporary test store")
        junit_argument = next(item for item in command if item.startswith("--junitxml="))
        Path(junit_argument.partition("=")[2]).write_text(
            '<testsuite tests="1"><testcase classname="suite" name="case">'
            "<skipped /></testcase></testsuite>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(architecture_gate.subprocess, "run", fake_run)
    monkeypatch.setattr(architecture_gate, "_runtime_temp_parent", lambda: tmp_path)
    report = architecture_gate._run_pytest_suite(
        tmp_path,
        tmp_path,
        suite_id="skipped-suite",
        tests=("test_example.py",),
        timeout_seconds=1,
    )

    assert report["passed"] is False
    assert report["tests"] == 1
    assert report["skipped_tests"] == ["suite::case"]
    assert len(suite_temporary) == 1
    assert not suite_temporary[0].exists()


def test_registered_gate_emits_exact_truthful_proofs_and_bound_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = load_release_contract()
    gate = next(item for item in contract.gates if item.gate_id == "GATE-10")
    evidence_dir = tmp_path / "gate-10"
    evidence_dir.mkdir()
    receipt_path = evidence_dir / "gate-receipt.json"

    monkeypatch.setattr(architecture_gate, "audit_repository", _controlled_architecture_report)

    def fake_suite(
        _repository: Path,
        _evidence_dir: Path,
        *,
        suite_id: str,
        tests: Sequence[str],
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        assert timeout_seconds > 0
        return _passing_dynamic_report(suite_id, tests)

    monkeypatch.setattr(architecture_gate, "_run_pytest_suite", fake_suite)
    monkeypatch.chdir(REPOSITORY)
    bindings = {
        "BLUEFIRE_ACCEPTANCE_ID": "gate-10-fixture",
        "BLUEFIRE_ACCEPTANCE_GATE_ID": gate.gate_id,
        "BLUEFIRE_ACCEPTANCE_GATE_DIR": str(evidence_dir),
        "BLUEFIRE_ACCEPTANCE_RECEIPT": str(receipt_path),
        "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256": contract.digest,
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT": "fixture-commit",
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE": "fixture-tree",
        "BLUEFIRE_ACCEPTANCE_RELEASE": "true",
    }
    for name, value in bindings.items():
        monkeypatch.setenv(name, value)

    assert (
        product_gates.run_gate_workflow(
            gate.gate_id,
            receipt_path=receipt_path,
            evidence_dir=evidence_dir,
            release=True,
        )
        == 1
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema_version"] == "bluefire.product-gate-receipt.v1"
    assert receipt["gate_id"] == gate.gate_id
    assert receipt["acceptance_id"] == "gate-10-fixture"
    assert receipt["contract_sha256"] == contract.digest
    assert receipt["repository_commit"] == "fixture-commit"
    assert receipt["repository_tree"] == "fixture-tree"
    assert receipt["release"] is True
    assert receipt["harness_assessment"] is None
    assert receipt["status"] == "failed"

    proofs = {proof["assertion_ids"][0]: proof for proof in receipt["proofs"]}
    assert set(proofs) == set(_PROOF_EXPECTATIONS)
    for assertion_id, (kind, artifact, test_id) in _PROOF_EXPECTATIONS.items():
        assert proofs[assertion_id] == {
            "kind": kind,
            "status": "passed",
            "test_id": test_id,
            "assertion_ids": [assertion_id],
            "evidence_artifacts": [artifact],
            "run_ids": [],
            "run_bundles": [],
            "environment_limitations": [],
        }
        assert (evidence_dir / artifact).is_file()

    blocked = set(receipt["failure_reason"].partition(": ")[2].split(", "))
    assert blocked == {
        "GATE-10-RUST-DECOMPOSITION",
        "GATE-10-FILE-SIZE-BUDGET",
        "GATE-10-CRYPTO-PRIMITIVES",
        "GATE-10-RESPONSIBILITY-SEPARATION",
    }
    assert {path.name for path in evidence_dir.iterdir() if path.name.endswith("-report.json")} == {
        "architecture-report.json",
        "property-fuzz-report.json",
        "behavior-preservation-report.json",
    }

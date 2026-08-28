import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

import bluefire.cli as cli
import bluefire.product_acceptance as acceptance
import bluefire.product_acceptance_process as acceptance_process
import bluefire.product_acceptance_verifier as acceptance_verifier
import bluefire.product_gates as product_gates

_RELEASE_FLOORS = {
    "GATE-01": (("dynamic", "structural"), 3, 2, 1),
    "GATE-02": (("dynamic", "structural"), 3, 1, 1),
    "GATE-03": (("dynamic", "structural"), 4, 3, 3),
    "GATE-04": (("dynamic", "structural"), 4, 3, 1),
    "GATE-05": (("dynamic", "structural"), 4, 1, 3),
    "GATE-06": (("dynamic", "structural"), 4, 4, 2),
    "GATE-07": (("dynamic", "structural"), 4, 1, 3),
    "GATE-08": (("dynamic", "structural"), 3, 1, 2),
    "GATE-09": (("dynamic", "structural"), 3, 1, 2),
    "GATE-10": (("dynamic", "structural"), 3, 0, 3),
    "GATE-11": (("dynamic", "structural"), 4, 2, 3),
    "GATE-12": (("dynamic", "structural"), 5, 2, 4),
}

_ASSERTION_COUNTS = {
    "GATE-01": 7,
    "GATE-02": 10,
    "GATE-03": 15,
    "GATE-04": 12,
    "GATE-05": 10,
    "GATE-06": 13,
    "GATE-07": 9,
    "GATE-08": 12,
    "GATE-09": 8,
    "GATE-10": 9,
    "GATE-11": 8,
    "GATE-12": 12,
}


_HELPER = r"""
import hashlib
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

gate_id, receipt_text, gate_dir_text, assertion_id, mode = sys.argv[1:]
receipt = pathlib.Path(receipt_text)
gate_dir = pathlib.Path(gate_dir_text)
artifact = gate_dir / "proof.json"

if gate_id == "GATE-01" and mode == "command-failure":
    print("deliberate workflow failure", file=sys.stderr)
    raise SystemExit(7)
if gate_id == "GATE-01" and mode == "timeout":
    time.sleep(3)
if gate_id == "GATE-01" and mode == "no-receipt":
    raise SystemExit(0)
if gate_id == "GATE-12" and mode == "no-gate-12-receipt":
    raise SystemExit(0)

artifact.write_text(json.dumps({"gate_id": gate_id, "acceptance_id": os.environ["BLUEFIRE_ACCEPTANCE_ID"]}), encoding="utf-8")
artifact_reference = "proof.json"
proof_status = "passed"
proof_kind = "dynamic"
if gate_id == "GATE-01" and mode == "escape":
    outside = gate_dir.parent / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    artifact_reference = "../outside.json"
if gate_id == "GATE-01" and mode == "skipped":
    proof_status = "skipped"
if gate_id == "GATE-01" and mode == "structural-only":
    proof_kind = "structural"

run_ids = []
run_bundles = []
if gate_id == "GATE-01" and mode in {"real-run-bundle", "stale-run-bundle"}:
    from bluefire.run_store import RunStore

    binding_names = [
        "BLUEFIRE_ACCEPTANCE_ID",
        "BLUEFIRE_ACCEPTANCE_GATE_ID",
        "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
        "BLUEFIRE_ACCEPTANCE_RELEASE",
    ]
    saved_bindings = {}
    if mode == "stale-run-bundle":
        saved_bindings = {name: os.environ.pop(name) for name in binding_names}
    store = RunStore(gate_dir)
    handle = store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "acceptance"},
        plan={"schema_version": "bluefire.plan.v1", "steps": []},
        policy={"schema_version": "bluefire.policy.v1", "allowed": True},
        profile=None,
    )
    os.environ.update(saved_bindings)
    store.finalize(
        handle.run_id,
        result={
            "schema_version": "bluefire.run-result.v1",
            "status": "completed",
            "created_at": handle.created_at,
        },
        evidence=[],
        detections=[],
    )
    run_ids = [handle.run_id]
    run_bundles = [{"run_id": handle.run_id, "path": handle.run_id}]
if gate_id == "GATE-01" and mode == "run-id-no-bundle":
    run_ids = ["run-20260101T000000Z-0000000000000001"]
if gate_id == "GATE-01" and mode == "fabricated-run-bundle":
    run_id = "run-20260101T000000Z-0000000000000001"
    bundle = gate_dir / run_id
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "bogus",
                "run_id": run_id,
                "files": {},
                "bundle_hash": "sha256:" + hashlib.sha256(b"{}").hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    run_ids = [run_id]
    run_bundles = [{"run_id": run_id, "path": run_id}]

receipt_failed = gate_id == "GATE-01" and mode == "receipt-failure"
receipt_proofs = [] if receipt_failed else [
    {
        "kind": proof_kind,
        "status": proof_status,
        "test_id": gate_id + ".workflow.1",
        "assertion_ids": [assertion_id],
        "evidence_artifacts": [artifact_reference],
        "run_ids": run_ids,
        "run_bundles": run_bundles,
        "environment_limitations": [],
    }
]
receipt.write_text(
    json.dumps(
        {
            "schema_version": "bluefire.product-gate-receipt.v1",
            "gate_id": gate_id,
            "acceptance_id": os.environ["BLUEFIRE_ACCEPTANCE_ID"],
            "contract_sha256": os.environ["BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"],
            "repository_commit": os.environ["BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"],
            "repository_tree": os.environ["BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"],
            "release": os.environ["BLUEFIRE_ACCEPTANCE_RELEASE"] == "true",
            "harness_assessment": None,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "failed" if receipt_failed else "passed",
            "failure_reason": "deliberate receipt failure" if receipt_failed else None,
            "proofs": receipt_proofs,
        }
    ),
    encoding="utf-8",
)

if receipt_failed:
    raise SystemExit(1)

if gate_id == "GATE-02" and mode == "tamper-earlier-artifact":
    (gate_dir.parent / "gate-01" / "proof.json").write_text("tampered", encoding="utf-8")
if gate_id == "GATE-12" and mode == "dirty-repository":
    (pathlib.Path.cwd() / "postflight-drift.txt").write_text("drift", encoding="utf-8")
"""


def _fixture_contract(tmp_path: Path, mode: str = "pass") -> acceptance.ReleaseContract:
    repository = tmp_path / "repository"
    repository.mkdir(exist_ok=True)
    helper = repository / "gate_helper.py"
    helper.write_text(_HELPER, encoding="utf-8")
    document = copy.deepcopy(acceptance.load_release_contract().document)
    for raw_gate in document["gates"]:
        assertion_id = raw_gate["id"] + "-FIXTURE"
        raw_gate["assertions"] = [
            {
                "id": assertion_id,
                "proof": "dynamic",
                "description": "Focused acceptance harness fixture assertion.",
            }
        ]
        raw_gate["required_proof"] = ["dynamic"]
        raw_gate["minimum_evidence_artifacts"] = 1
        raw_gate["minimum_run_ids"] = 0
        raw_gate["minimum_test_ids"] = 1
        raw_gate["timeout_seconds"] = 5
        raw_gate["workflow"]["command"] = [
            "{python}",
            "{repository}/gate_helper.py",
            raw_gate["id"],
            "{receipt}",
            "{gate_dir}",
            assertion_id,
            mode,
        ]
    return acceptance.contract_from_mapping(document)


def _run_fixture(tmp_path: Path, mode: str = "pass") -> dict:
    repository = tmp_path / "repository"
    return acceptance.run_acceptance(
        _fixture_contract(tmp_path, mode),
        repository_root=repository,
        output_dir=tmp_path / "results",
        release=False,
    )


def _persist_result(result_path: Path, document: dict) -> None:
    result_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result_path.with_suffix(".sha256").write_text(
        hashlib.sha256(result_path.read_bytes()).hexdigest() + "  acceptance-result.json\n",
        encoding="ascii",
    )


def test_locked_release_contract_has_exact_non_weakening_gate_floors() -> None:
    contract = acceptance.load_release_contract()

    assert tuple(gate.gate_id for gate in contract.gates) == acceptance.EXPECTED_GATE_IDS
    assert contract.digest == "sha256:" + acceptance.RELEASE_CONTRACT_SHA256
    assert contract.release_command == "bluefire acceptance run --release"
    assert {
        gate.gate_id: (
            gate.required_proof,
            gate.minimum_evidence_artifacts,
            gate.minimum_run_ids,
            gate.minimum_test_ids,
        )
        for gate in contract.gates
    } == _RELEASE_FLOORS
    assert all(gate.required and "dynamic" in gate.required_proof for gate in contract.gates)
    assert {gate.gate_id: len(gate.assertions) for gate in contract.gates} == _ASSERTION_COUNTS
    assert all(
        assertion.assertion_id.startswith(gate.gate_id + "-")
        and assertion.proof in gate.required_proof
        for gate in contract.gates
        for assertion in gate.assertions
    )


def test_generated_result_schema_matches_the_committed_package_resource() -> None:
    schema_path = (
        Path(acceptance.__file__).parent / "data" / "product_acceptance_result.schema.json"
    )
    assert (
        json.loads(schema_path.read_text(encoding="utf-8")) == acceptance.result_schema_document()
    )


def test_canonical_gate_dispatcher_emits_bound_failure_until_real_workflow_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = acceptance.load_release_contract()
    gate = contract.gates[0]
    monkeypatch.delitem(product_gates._WORKFLOWS, gate.gate_id)
    evidence_dir = tmp_path / "gate-01"
    evidence_dir.mkdir()
    receipt = evidence_dir / "gate-receipt.json"
    bindings = {
        "BLUEFIRE_ACCEPTANCE_ID": "acceptance-fixture",
        "BLUEFIRE_ACCEPTANCE_GATE_ID": gate.gate_id,
        "BLUEFIRE_ACCEPTANCE_GATE_DIR": str(evidence_dir),
        "BLUEFIRE_ACCEPTANCE_RECEIPT": str(receipt),
        "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256": contract.digest,
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT": "unavailable",
        "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE": "unavailable",
        "BLUEFIRE_ACCEPTANCE_RELEASE": "true",
    }
    for key, value in bindings.items():
        monkeypatch.setenv(key, value)

    assert (
        product_gates.run_gate_workflow(
            gate.gate_id,
            receipt_path=receipt,
            evidence_dir=evidence_dir,
            release=True,
        )
        == 1
    )
    document = json.loads(receipt.read_text(encoding="utf-8"))
    assert document["status"] == "failed"
    assert document["acceptance_id"] == "acceptance-fixture"
    assert document["contract_sha256"] == contract.digest
    assert document["repository_tree"] == "unavailable"
    assert document["release"] is True
    assert document["harness_assessment"] is None
    assert all(
        assertion.assertion_id in document["failure_reason"] for assertion in gate.assertions
    )


@pytest.mark.parametrize(
    "mutation", ["missing", "disabled", "structural-only", "assertions", "placeholder"]
)
def test_contract_rejects_removed_disabled_or_downgraded_gates(mutation: str) -> None:
    document = copy.deepcopy(acceptance.load_release_contract().document)
    if mutation == "missing":
        document["gates"].pop()
    elif mutation == "disabled":
        document["gates"][0]["required"] = False
    elif mutation == "structural-only":
        document["gates"][0]["required_proof"] = ["structural"]
    elif mutation == "assertions":
        document["gates"][0]["assertions"] = []
    else:
        document["gates"][0]["workflow"]["command"].append("{shell}")

    with pytest.raises(acceptance.AcceptanceContractError):
        acceptance.contract_from_mapping(document)


def test_harness_passes_only_with_receipted_hashed_dynamic_evidence(tmp_path: Path) -> None:
    result = _run_fixture(tmp_path)

    assert result["status"] == "passed"
    assert [gate["status"] for gate in result["gates"]] == ["passed"] * 12
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    fixture_contract = _fixture_contract(tmp_path)
    acceptance.validate_acceptance_result(persisted, contract=fixture_contract)
    assert (
        acceptance_verifier.verify_result_file(
            result_path,
            contract=fixture_contract.document,
            contract_digest=fixture_contract.digest,
        )
        == persisted
    )
    validator = Draft202012Validator(
        acceptance.result_schema_document(),
        format_checker=FormatChecker(),
    )
    validator.validate(persisted)
    absolute_artifact = copy.deepcopy(persisted)
    absolute_artifact["gates"][0]["evidence_artifacts"][0]["path"] = "C:/secret/proof.json"
    with pytest.raises(ValidationError):
        validator.validate(absolute_artifact)
    digest_path = result_path.with_suffix(".sha256")
    assert (
        digest_path.read_text(encoding="ascii").split()[0]
        == hashlib.sha256(result_path.read_bytes()).hexdigest()
    )
    for gate in persisted["gates"]:
        assert gate["proof_types"] == ["dynamic"]
        assert gate["run_ids"] == []
        assert gate["test_ids"]
        assert gate["required_assertion_ids"] == gate["covered_assertion_ids"]
        assert gate["missing_assertion_ids"] == []
        assert gate["evidence_artifacts"]
        assert all(value.startswith("sha256:") for value in gate["hashes"].values())

    serialized = json.dumps(persisted)
    assert str(tmp_path) not in serialized
    assert str(Path.home()) not in serialized
    assert (
        persisted["environment"]["executable"] == Path(persisted["environment"]["executable"]).name
    )
    assert all(gate["workflow"]["command"][0] == "{python}" for gate in persisted["gates"])

    forged_results = []
    duplicate_gate = copy.deepcopy(persisted)
    duplicate_gate["gates"][1]["gate_id"] = "GATE-01"
    forged_results.append(duplicate_gate)
    contradictory_status = copy.deepcopy(persisted)
    contradictory_status["gates"][0]["status"] = "failed"
    contradictory_status["gates"][0]["failure_reason"] = "forged failure"
    forged_results.append(contradictory_status)
    empty_proof = copy.deepcopy(persisted)
    empty_proof["gates"][0]["proofs"] = []
    forged_results.append(empty_proof)
    absolute_command = copy.deepcopy(persisted)
    absolute_command["gates"][0]["workflow"]["command"][0] = str(Path.home() / "python")
    forged_results.append(absolute_command)
    forged_contract = copy.deepcopy(persisted)
    forged_contract["gates"][0]["required_assertion_ids"] = ["GATE-01-FORGED"]
    forged_contract["gates"][0]["covered_assertion_ids"] = ["GATE-01-FORGED"]
    forged_contract["gates"][0]["proofs"][0]["assertion_ids"] = ["GATE-01-FORGED"]
    forged_results.append(forged_contract)
    wrong_proof_kind = copy.deepcopy(persisted)
    wrong_proof_kind["gates"][0]["proofs"][0]["kind"] = "structural"
    wrong_proof_kind["gates"][0]["proof_types"] = ["structural"]
    forged_results.append(wrong_proof_kind)
    extra_field = copy.deepcopy(persisted)
    extra_field["unexpected"] = True
    forged_results.append(extra_field)
    for forged in forged_results:
        with pytest.raises(ValueError):
            acceptance.validate_acceptance_result(forged, contract=fixture_contract)

    artifact_path = result_path.parent / persisted["gates"][0]["evidence_artifacts"][0]["path"]
    artifact_path.write_bytes(artifact_path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="artifact (size|hash) does not match"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=fixture_contract.document,
            contract_digest=fixture_contract.digest,
        )


def test_persisted_verifier_reconciles_receipt_identity_bindings(
    tmp_path: Path,
) -> None:
    _run_fixture(tmp_path)
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    contract = _fixture_contract(tmp_path)

    def persist(document: dict) -> None:
        result_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        result_path.with_suffix(".sha256").write_text(
            hashlib.sha256(result_path.read_bytes()).hexdigest() + "  acceptance-result.json\n",
            encoding="ascii",
        )

    for field, value in (
        ("acceptance_id", "acceptance-forged"),
        ("commit", "1" * 40),
        ("tree", "2" * 40),
    ):
        forged = copy.deepcopy(persisted)
        if field == "acceptance_id":
            forged[field] = value
        else:
            forged["repository"][field] = value
        persist(forged)
        with pytest.raises(ValueError, match="receipt identity"):
            acceptance_verifier.verify_result_file(
                result_path,
                contract=contract.document,
                contract_digest=contract.digest,
            )

    forged = copy.deepcopy(persisted)
    forged_proof = forged["gates"][0]["proofs"][0]
    forged_proof["test_id"] = "GATE-01.forged"
    forged["gates"][0]["test_ids"] = ["GATE-01.forged"]
    persist(forged)
    with pytest.raises(ValueError, match="harness assessment"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )

    forged = copy.deepcopy(persisted)
    forged["gates"][0]["status"] = "failed"
    forged["gates"][0]["failure_reason"] = "forged failure"
    forged["status"] = "failed"
    forged["failure_reason"] = "required gates failed: GATE-01"
    persist(forged)
    with pytest.raises(ValueError, match="harness assessment"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )

    forged = copy.deepcopy(persisted)
    forged["status"] = "failed"
    forged["failure_reason"] = "forged top-level failure"
    persist(forged)
    with pytest.raises(ValueError, match="derived verdict"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )

    forged = copy.deepcopy(persisted)
    gate = forged["gates"][0]
    receipt_relative = gate["workflow"]["receipt_path"]
    receipt_path = result_path.parent / receipt_relative
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assertion_id = receipt["proofs"][0]["assertion_ids"][0]
    receipt["proofs"][0]["assertion_ids"] = [assertion_id, assertion_id]
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt_digest = "sha256:" + hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    receipt_artifact = next(
        item for item in gate["evidence_artifacts"] if item["path"] == receipt_relative
    )
    receipt_artifact["sha256"] = receipt_digest
    receipt_artifact["size_bytes"] = receipt_path.stat().st_size
    gate["hashes"][receipt_relative] = receipt_digest
    persist(forged)
    with pytest.raises(ValueError, match="duplicated"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )


def test_public_release_verifier_rejects_non_release_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_fixture(tmp_path)
    contract = _fixture_contract(tmp_path)
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    monkeypatch.setattr(acceptance, "load_release_contract", lambda: contract)

    with pytest.raises(ValueError, match="requires a release-mode"):
        acceptance.verify_release_result(result_path)


def test_persisted_verifier_rejects_receipt_exit_code_contradictions(tmp_path: Path) -> None:
    _run_fixture(tmp_path, "receipt-failure")
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    contract = _fixture_contract(tmp_path, "receipt-failure")
    assert (
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )
        == persisted
    )
    persisted["gates"][0]["workflow"]["exit_code"] = 0
    _persist_result(result_path, persisted)

    with pytest.raises(ValueError, match="receipt status.*exit code"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )


def test_persisted_verifier_rejects_proofs_without_a_receipt(tmp_path: Path) -> None:
    _run_fixture(tmp_path, "no-receipt")
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    gate = persisted["gates"][0]
    assertion_id = gate["required_assertion_ids"][0]
    test_id = "GATE-01.forged-without-receipt"
    gate["proofs"] = [
        {
            "kind": "dynamic",
            "status": "passed",
            "test_id": test_id,
            "assertion_ids": [assertion_id],
            "evidence_artifacts": [gate["workflow"]["stdout_path"]],
            "run_ids": [],
            "run_bundles": [],
            "environment_limitations": [],
        }
    ]
    gate["test_ids"] = [test_id]
    gate["covered_assertion_ids"] = [assertion_id]
    gate["missing_assertion_ids"] = []
    gate["proof_types"] = ["dynamic"]
    _persist_result(result_path, persisted)
    contract = _fixture_contract(tmp_path, "no-receipt")

    with pytest.raises(ValueError, match="proofs or a receipt file without a receipt path"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )


def test_postflight_assessment_binds_receiptless_gate_and_repository_details(
    tmp_path: Path,
) -> None:
    result = _run_fixture(tmp_path, "no-gate-12-receipt")
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    contract = _fixture_contract(tmp_path, "no-gate-12-receipt")
    assert (
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )
        == result
    )

    forged = copy.deepcopy(result)
    forged["repository"]["commit_after"] = "3" * 40
    forged["repository"]["tree_after"] = "4" * 40
    forged["repository"]["clean_after"] = True
    forged["gates"][-1]["workflow"]["exit_code"] = 37
    forged["gates"][-1]["failure_reason"] = "forged receiptless failure detail"
    _persist_result(result_path, forged)

    with pytest.raises(ValueError, match="postflight assessment does not match"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )


def test_verifier_rejects_release_relabel_and_noncanonical_workflow_metadata(
    tmp_path: Path,
) -> None:
    _run_fixture(tmp_path, "receipt-failure")
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    contract = _fixture_contract(tmp_path, "receipt-failure")

    mutations = (
        ("release", "start from a clean committed tree"),
        ("aliased-logs", "workflow log path or role is invalid"),
        ("hidden-receipt", "receipt artifact exists without a receipt path"),
    )
    for mutation, expected in mutations:
        forged = copy.deepcopy(persisted)
        if mutation == "release":
            forged["release"] = True
        elif mutation == "aliased-logs":
            forged["gates"][0]["workflow"]["stderr_path"] = forged["gates"][0]["workflow"][
                "stdout_path"
            ]
        else:
            forged["gates"][0]["workflow"]["receipt_path"] = None
        _persist_result(result_path, forged)
        with pytest.raises(ValueError, match=expected):
            acceptance_verifier.verify_result_file(
                result_path,
                contract=contract.document,
                contract_digest=contract.digest,
                require_release=mutation == "release",
            )


def test_persisted_verifier_rejects_cross_gate_receipt_timestamps(tmp_path: Path) -> None:
    _run_fixture(tmp_path)
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    gate = persisted["gates"][1]
    receipt_relative = gate["workflow"]["receipt_path"]
    receipt_path = result_path.parent / receipt_relative
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["timestamp"] = persisted["started_at"]
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    artifact = next(item for item in gate["evidence_artifacts"] if item["path"] == receipt_relative)
    artifact["sha256"] = digest
    artifact["size_bytes"] = receipt_path.stat().st_size
    gate["hashes"][receipt_relative] = digest
    _persist_result(result_path, persisted)
    contract = _fixture_contract(tmp_path)

    with pytest.raises(ValueError, match="outside its acceptance interval"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )


def test_run_bundle_is_fresh_and_bound_to_acceptance_identity(tmp_path: Path) -> None:
    result = _run_fixture(tmp_path, "real-run-bundle")
    first = result["gates"][0]
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    contract = _fixture_contract(tmp_path, "real-run-bundle")

    assert result["status"] == "passed"
    assert len(first["run_ids"]) == 1
    assert first["proofs"][0]["run_bundles"][0]["run_id"] == first["run_ids"][0]
    acceptance_verifier.verify_result_file(
        result_path,
        contract=contract.document,
        contract_digest=contract.digest,
    )


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("no-receipt", "did not emit the required gate receipt"),
        ("command-failure", "workflow exited with code 7"),
        ("skipped", "receipt proof status must be passed"),
        ("escape", "must stay inside its gate directory"),
        ("structural-only", "missing required proof types: dynamic"),
        ("run-id-no-bundle", "every claimed run ID must bind exactly one validated run bundle"),
        ("fabricated-run-bundle", "is not a canonical finalized bundle"),
        ("stale-run-bundle", "stale, unbound"),
    ],
)
def test_harness_rejects_non_evidence_and_false_dynamic_claims(
    tmp_path: Path,
    mode: str,
    expected: str,
) -> None:
    result = _run_fixture(tmp_path, mode)

    assert result["status"] == "failed"
    first = result["gates"][0]
    assert first["status"] == "failed"
    assert expected in first["failure_reason"]


def test_harness_kills_timed_out_workflow_and_records_exact_failure(tmp_path: Path) -> None:
    contract = _fixture_contract(tmp_path, "timeout")
    document = copy.deepcopy(contract.document)
    document["gates"][0]["timeout_seconds"] = 1
    repository = tmp_path / "repository"

    result = acceptance.run_acceptance(
        acceptance.contract_from_mapping(document),
        repository_root=repository,
        output_dir=tmp_path / "results",
        release=False,
    )

    assert result["status"] == "failed"
    assert "exceeded its 1-second timeout" in result["gates"][0]["failure_reason"]


def test_release_precondition_refuses_dirty_workflow_code_without_execution(tmp_path: Path) -> None:
    contract = _fixture_contract(tmp_path)
    repository = tmp_path / "repository"
    commands = [
        ["git", "init", "-q"],
        ["git", "config", "user.email", "acceptance@example.invalid"],
        ["git", "config", "user.name", "Acceptance Test"],
        ["git", "add", "gate_helper.py"],
        ["git", "commit", "-qm", "fixture"],
    ]
    for command in commands:
        subprocess.run(command, cwd=repository, check=True, capture_output=True)
    (repository / "uncommitted.txt").write_text("must not execute", encoding="utf-8")

    with pytest.raises(ValueError, match="refuses to execute an uncommitted worktree"):
        acceptance.run_acceptance(
            contract,
            repository_root=repository,
            output_dir=tmp_path / "results",
            release=True,
        )
    assert not (tmp_path / "results").exists()


def test_postflight_assessment_rejects_forged_clean_release_verdict(tmp_path: Path) -> None:
    contract = _fixture_contract(tmp_path, "dirty-repository")
    repository = tmp_path / "repository"
    commands = [
        ["git", "init", "-q"],
        ["git", "config", "user.email", "acceptance@example.invalid"],
        ["git", "config", "user.name", "Acceptance Test"],
        ["git", "add", "gate_helper.py"],
        ["git", "commit", "-qm", "fixture"],
    ]
    for command in commands:
        subprocess.run(command, cwd=repository, check=True, capture_output=True)

    result = acceptance.run_acceptance(
        contract,
        repository_root=repository,
        output_dir=tmp_path / "results",
        release=True,
    )
    assert result["status"] == "failed"
    assert result["failure_reason"] == "release workflows changed the committed worktree"
    assert [gate["status"] for gate in result["gates"]] == ["passed"] * 12

    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    forged = copy.deepcopy(result)
    forged["repository"]["clean_after"] = True
    forged["repository"]["commit_after"] = forged["repository"]["commit"]
    forged["repository"]["tree_after"] = forged["repository"]["tree"]
    forged["status"] = "passed"
    forged["failure_reason"] = None
    _persist_result(result_path, forged)

    with pytest.raises(ValueError, match="GATE-12 harness assessment"):
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
            require_release=True,
        )


def test_release_precondition_fails_closed_without_whole_tree_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _fixture_contract(tmp_path)
    monkeypatch.setattr(
        acceptance,
        "_process_containment_limitations",
        lambda: ("simulated unsupported platform",),
    )

    with pytest.raises(ValueError, match="kernel-backed whole-tree process isolation"):
        acceptance.run_acceptance(
            contract,
            repository_root=tmp_path / "repository",
            output_dir=tmp_path / "results",
            release=True,
        )
    assert not (tmp_path / "results").exists()


def test_workflow_cleanup_kills_descendant_after_leader_exits(tmp_path: Path) -> None:
    helper = tmp_path / "spawn_descendant.py"
    pid_path = tmp_path / "descendant.pid"
    helper.write_text(
        "\n".join(
            [
                "import pathlib, subprocess, sys",
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')",
            ]
        ),
        encoding="utf-8",
    )
    started = time.monotonic()
    outcome = acceptance_process._execute_workflow(
        [sys.executable, str(helper), str(pid_path)],
        repository=tmp_path,
        environment=os.environ,
        timeout_seconds=10,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
    )
    elapsed = time.monotonic() - started
    descendant_pid = int(pid_path.read_text(encoding="ascii"))

    def descendant_exists() -> bool:
        if os.name == "nt":
            probe = subprocess.run(
                ["tasklist", "/FI", f"PID eq {descendant_pid}", "/FO", "CSV", "/NH"],
                check=False,
                capture_output=True,
                text=True,
            )
            return f'"{descendant_pid}"' in probe.stdout
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            return False
        return True

    try:
        deadline = time.monotonic() + 3
        while descendant_exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert outcome == acceptance_process.WorkflowOutcome(0, None)
        assert elapsed < 5
        assert not descendant_exists()
    finally:
        if descendant_exists():
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(descendant_pid), "/T", "/F"],
                    check=False,
                    capture_output=True,
                )
            else:
                os.kill(descendant_pid, signal.SIGKILL)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper containment")
def test_linux_subreaper_kills_new_session_descendant(tmp_path: Path) -> None:
    helper = tmp_path / "escape_process_group.py"
    pid_path = tmp_path / "escaped.pid"
    helper.write_text(
        "\n".join(
            [
                "import pathlib, subprocess, sys",
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')",
            ]
        ),
        encoding="utf-8",
    )
    outcome = acceptance_process._execute_workflow(
        [sys.executable, str(helper), str(pid_path)],
        repository=tmp_path,
        environment=os.environ,
        timeout_seconds=10,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
    )
    descendant_pid = int(pid_path.read_text(encoding="ascii"))

    assert outcome == acceptance_process.WorkflowOutcome(0, None)
    assert not Path(f"/proc/{descendant_pid}").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object ordering")
def test_windows_workflow_is_suspended_until_job_attachment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "child-started"
    original_attach = acceptance_process._create_windows_kill_job
    marker_states = []

    def attach(process):
        marker_states.append(marker.exists())
        return original_attach(process)

    monkeypatch.setattr(acceptance_process, "_create_windows_kill_job", attach)
    outcome = acceptance_process._execute_workflow(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        repository=tmp_path,
        environment=os.environ,
        timeout_seconds=10,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
    )

    assert marker_states == [False]
    assert marker.is_file()
    assert outcome == acceptance_process.WorkflowOutcome(0, None)


def test_workflow_environment_isolates_cargo_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_cargo = tmp_path / "parent-cargo-with-credentials"
    parent_target = tmp_path / "parent-target"
    rustup = tmp_path / "rustup-toolchains"
    monkeypatch.setenv("CARGO_HOME", str(parent_cargo))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(parent_target))
    monkeypatch.setenv("RUSTUP_HOME", str(rustup))
    monkeypatch.setenv("BLUEFIRE_TEST_ACCESS_TOKEN", "parent-secret-value")
    runtime_home = tmp_path / "runtime-home"
    runtime_temp = tmp_path / "runtime-temp"
    runtime_home.mkdir()
    runtime_temp.mkdir()

    environment = acceptance_process._isolated_workflow_environment(
        runtime_home=runtime_home,
        runtime_temp=runtime_temp,
        cargo_target=tmp_path / "runtime-cargo-target",
    )

    assert environment["CARGO_HOME"] == str(runtime_home / "cargo")
    assert environment["CARGO_TARGET_DIR"] == str(tmp_path / "runtime-cargo-target")
    assert environment["RUSTUP_HOME"] == str(rustup)
    assert environment["CARGO_NET_OFFLINE"] == "true"
    assert "BLUEFIRE_TEST_ACCESS_TOKEN" not in environment
    assert str(parent_cargo) not in environment.values()


def test_public_workflow_text_and_receipts_redact_paths_and_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    run_dir = tmp_path / "results" / "acceptance-test"
    run_dir.mkdir(parents=True)
    secret = "release-secret-value-123456789"  # pragma: allowlist secret
    monkeypatch.setenv("BLUEFIRE_TEST_API_KEY", secret)
    raw = (
        f"repository={repository} api_key={secret} "
        "Authorization: Bearer bearer-token-value-123456 "
        "github=ghp_1234567890abcdefghijkl"  # pragma: allowlist secret
    )
    redacted = acceptance_process._redact_runtime_paths(
        raw,
        repository=repository,
        run_dir=run_dir,
    )
    assert str(repository) not in redacted
    assert secret not in redacted
    assert "bearer-token-value-123456" not in redacted
    assert "ghp_1234567890abcdefghijkl" not in redacted  # pragma: allowlist secret

    receipt = run_dir / "gate-receipt.json"
    receipt.write_text(
        json.dumps({"failure_reason": raw, "environment_limitations": [raw]}),
        encoding="utf-8",
    )
    acceptance_process._sanitize_gate_receipt(
        receipt,
        repository=repository,
        run_dir=run_dir,
    )
    sanitized = receipt.read_text(encoding="utf-8")
    assert secret not in sanitized
    assert str(repository) not in sanitized


def test_harness_detects_evidence_changed_by_a_later_gate(tmp_path: Path) -> None:
    result = _run_fixture(tmp_path, "tamper-earlier-artifact")

    assert result["status"] == "failed"
    assert result["failure_reason"] == "required gates failed: GATE-01"
    assert "evidence changed after validation" in result["gates"][0]["failure_reason"]
    result_path = next((tmp_path / "results").glob("*/acceptance-result.json"))
    contract = _fixture_contract(tmp_path, "tamper-earlier-artifact")
    assert (
        acceptance_verifier.verify_result_file(
            result_path,
            contract=contract.document,
            contract_digest=contract.digest,
        )
        == result
    )


def test_cli_exposes_canonical_release_command_without_starting_product_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"status": "passed", "acceptance_id": "acceptance-test"}
    calls = []

    def run_release_acceptance(**kwargs):
        calls.append(kwargs)
        return expected

    monkeypatch.setattr(cli, "run_release_acceptance", run_release_acceptance)
    parser = cli._parser()
    args = parser.parse_args(["acceptance", "run", "--release"])

    assert cli._execute(args) == expected
    assert calls == [{"repository_root": None, "output_dir": None}]
    with pytest.raises(SystemExit):
        parser.parse_args(["acceptance", "run"])


def test_cli_returns_nonzero_and_emits_complete_failed_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    failed = {"status": "failed", "failure_reason": "GATE-01 failed"}

    def reject(**_kwargs):
        raise acceptance.AcceptanceFailure(failed)

    monkeypatch.setattr(cli, "run_release_acceptance", reject)

    assert cli.main(["acceptance", "run", "--release"]) == 1
    assert json.loads(capsys.readouterr().out) == failed

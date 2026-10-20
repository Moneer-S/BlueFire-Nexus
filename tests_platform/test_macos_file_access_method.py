"""Typed in-memory artifact fakes; no native effects or filesystem report writes."""

from copy import deepcopy

import pytest

from bluefire import macos_file_access_method as method
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.util import content_hash
from tests_platform import test_macos_file_access_composition_bridge as cases

creator_fake = cases.creator_fake
original = cases.original
attempt = cases.attempt


def probe_output(attempt):
    frame = attempt.frame()
    native = attempt.dispatch(frame)
    observed = method.observation(frame, native, observed_at_ms=attempt.state["wall"])
    return {"macos_receipt": native, "observation": observed}


def test_metadata_artifacts_retain_raw_native_evidence_without_reports_or_receipts(attempt):
    output = probe_output(attempt)
    assert method.request(method.PROBE_ACTION, {}, {}) == {"params": {}}
    artifacts = method.outputs(
        method.PROBE_ACTION, {}, bound_inputs={}, runner_output=output, receipt_ids=[]
    )
    probe, workspace = artifacts["probe"], artifacts["workspace"]
    assert probe["type"] == method.PROBE_TYPE and workspace["type"] == method.ATTEMPT_TYPE
    assert probe["native_receipt"] == output["macos_receipt"]
    assert probe["native_receipt_digest"] == content_hash(output["macos_receipt"])
    assert probe["observation_digest"] == content_hash(output["observation"])
    assert not ({"path", "report", "root", "receipt_ids"} & set(probe))
    assert not ({"path", "report", "root", "receipt_ids"} & set(workspace))
    output["macos_receipt"]["state"] = "unknown"
    assert probe["native_receipt"]["state"] == "complete"


def test_owner_metadata_requires_exact_same_attempt_probe_and_receipt(attempt):
    probe = method.outputs(
        method.PROBE_ACTION,
        {},
        bound_inputs={},
        runner_output=probe_output(attempt),
        receipt_ids=[],
    )["probe"]
    frame = attempt.frame("verify_owner")
    native = attempt.dispatch(frame)
    output = {
        "macos_receipt": native,
        "observation": method.observation(frame, native, observed_at_ms=attempt.state["wall"]),
    }
    artifact = method.outputs(
        method.OWNER_ACTION, {}, bound_inputs={"probe": probe}, runner_output=output, receipt_ids=[]
    )["verification"]
    assert (
        artifact["type"] == method.VERIFY_TYPE and artifact["observation"]["outcome"] == "allowed"
    )
    assert artifact["observation"]["probe_receipt_digest"] == probe["native_receipt_digest"]
    changed = deepcopy(output)
    changed["observation"]["probe_receipt_digest"] = content_hash("other")
    with pytest.raises(MacOSFileAccessContractError):
        method.outputs(
            method.OWNER_ACTION,
            {},
            bound_inputs={"probe": probe},
            runner_output=changed,
            receipt_ids=[],
        )


@pytest.mark.parametrize(
    "change", ["native", "observation", "attempt", "request", "cleanup", "future", "extra"]
)
def test_rehashed_or_mismatched_metadata_cannot_replace_actual_receipt(attempt, change):
    output = probe_output(attempt)
    if change == "native":
        output["macos_receipt"]["terminals"][0]["outcome"] = "allowed"
        output["observation"]["native_receipt_digest"] = content_hash(output["macos_receipt"])
    elif change == "observation":
        output["observation"]["outcome"] = "allowed"
    elif change == "attempt":
        output["observation"]["attempt_id"] = "other"
    elif change == "request":
        output["macos_receipt"]["requests"][0]["request_digest"] = content_hash("other")
    elif change == "cleanup":
        output["macos_receipt"]["terminals"][0]["request_handle_cleanup"] = "unknown"
    elif change == "future":
        output["observation"]["observed_at_ms"] = output["observation"]["intent"]["expires_at_ms"]
    else:
        output["report"] = {"path": "unavailable"}
    with pytest.raises(MacOSFileAccessContractError):
        method.outputs(
            method.PROBE_ACTION, {}, bound_inputs={}, runner_output=output, receipt_ids=[]
        )


@pytest.mark.parametrize(
    "action",
    [
        "macos.file_access.probe.v1",
        "macos.file_access.verify_owner.v1",
        "macos.file_access.close_attempt.v1",
    ],
    ids=["probe", "verify_owner", "close_attempt"],
)
def test_fixed_methods_refuse_free_parameters_and_linux_artifact_reinterpretation(action):
    with pytest.raises(MacOSFileAccessContractError):
        method.request(action, {"path": "/other"}, {})
    with pytest.raises(MacOSFileAccessContractError):
        method.request(action, {}, {"probe": {"type": "artifact.file_access.probe.v1"}})


def test_no_artifact_closure_is_distinct_from_native_or_enrollment_cleanup(attempt):
    outputs = method.outputs(
        method.PROBE_ACTION,
        {},
        bound_inputs={},
        runner_output=probe_output(attempt),
        receipt_ids=[],
    )
    attempt.dispatch(attempt.frame("verify_owner"))
    closure = attempt.dispatch(attempt.frame("close_attempt"))
    artifact = method.outputs(
        method.CLOSE_ACTION,
        {},
        bound_inputs={"workspace": outputs["workspace"]},
        runner_output={"attempt_closure": closure},
        receipt_ids=[],
    )["closure"]
    assert artifact["type"] == method.CLOSURE_TYPE
    assert artifact["attempt_closure"]["attempt_artifacts"] == "not_created"
    assert artifact["attempt_closure"]["original_workers"] == "retained"
    assert not artifact["attempt_closure"]["whole_enrollment_cleanup"]
    assert "macos_receipt" not in artifact and "native_cleanup" not in artifact
    assert method.request(method.CLOSE_ACTION, {}, {}) == {"params": {}}
    assert (
        method.outputs(
            method.CLOSE_ACTION,
            {},
            bound_inputs={},
            runner_output={"attempt_closure": closure},
            receipt_ids=[],
        )["closure"]
        == artifact
    )
    with pytest.raises(MacOSFileAccessContractError):
        method.outputs(
            method.CLOSE_ACTION,
            {},
            bound_inputs={"workspace": outputs["workspace"]},
            runner_output={"attempt_closure": closure},
            receipt_ids=["0" * 64],
        )

"""Receipt provenance stays bound to the exact observation, not later failures."""

from copy import deepcopy

import pytest

from bluefire.s3_fixture_results import receipts
from tests_platform.test_s3_fixture_sdk import fixture_request, run


def owner():
    request, descriptor = fixture_request()
    return {
        "request": {
            "environment": {"scope": request.to_dict()["scope"], "fixture_lifecycle": descriptor},
            "fixture_intent_id": "a" * 64,
        },
        "progress": {"operations": []},
    }


def failed(dispatch="permit_issued"):
    return {
        "result": {"outcome": "failed", "calls": [{"request_id": "failed-request"}]},
        "provenance": "runner_reported",
        "dispatch": dispatch,
        "send_debits": 4,
    }


def test_initial_read_failure_does_not_create_observed_receipt():
    value = owner()
    before = receipts(value)
    value["progress"]["operations"] = [{"phase": "prepare", "executions": [failed()]}]
    assert receipts(value) == before
    assert before[0]["state"] == "not_prepared"
    assert before[0]["request_ids"] == []
    assert before[0]["provenance"] == "not_observed"


@pytest.mark.parametrize("dispatch", ["permit_issued", "unknown"])
def test_failed_reconciliation_keeps_original_observation_identity(dispatch):
    value = owner()
    observed, _ = run(fixture_request()[0])
    value["progress"]["operations"] = [
        {
            "phase": "prepare",
            "executions": [
                {
                    "result": observed,
                    "provenance": "synthetic",
                    "dispatch": "permit_issued",
                    "send_debits": 6,
                }
            ],
        }
    ]
    before = deepcopy(receipts(value))
    value["progress"]["operations"].append(
        {"phase": "reconcile_fixtures", "executions": [failed(dispatch)]}
    )
    assert receipts(value) == before
    assert before[0]["state"] == "owned"
    assert before[0]["provenance"] == "synthetic"
    assert "failed-request" not in before[0]["request_ids"]


def test_uncertain_mutation_replaces_receipt_with_its_own_bounded_identity():
    value = owner()
    uncertain = failed("unknown")
    uncertain["send_debits"] = 5
    value["progress"]["operations"] = [{"phase": "prepare", "executions": [uncertain]}]
    row = receipts(value)[0]
    assert row["state"] == "uncertain" and row["etag"] is None
    assert row["provenance"] == "runner_reported"
    assert row["request_ids"] == ["failed-request"]

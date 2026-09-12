"""Authored planner-record compatibility checks; no model, runner or lab effects."""

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.adaptive_record_validation import (
    ADAPTIVE_DECISION_CONTRACT,
    validate_v4_attempt_record,
    validate_v4_proposal_record,
)
from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.ai import AIProviderError, validate_persisted_proposal_record
from bluefire.ai_record_validation import DurableProposalRecordError
from bluefire.config import AutonomyLevel
from bluefire.util import content_hash
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_adaptive_runtime import runtime as runtime


def authored_record(runtime, disposition="applied", *, current=True):
    kwargs, config = runtime
    kwargs = dict(kwargs)
    provider = Provider(config)
    if disposition == "review":
        kwargs["plan"] = replace(kwargs["plan"], autonomy=AutonomyLevel.ASSIST)
    elif disposition == "budget_stop":
        kwargs["remaining_steps"] = 0
    elif disposition == "provider_stop":
        provider = Provider(config, proposal_type="stop")
    record = deepcopy(propose_reviewed_method(**kwargs, provider=provider).record)
    state = record["planner_state"]
    if current:
        state["decision_contract"] = deepcopy(ADAPTIVE_DECISION_CONTRACT)
    else:
        state.pop("decision_contract", None)
    record["planner_state_digest"] = content_hash(state)
    return record


@pytest.mark.parametrize("current", [False, True], ids=["legacy", "current"])
@pytest.mark.parametrize("disposition", ["applied", "review", "budget_stop", "provider_stop"])
def test_old_and_current_records_round_trip_with_same_execution_disposition(
    runtime, current, disposition
):
    record = authored_record(runtime, disposition, current=current)
    retained = deepcopy(record)
    state = validate_v4_attempt_record(record)
    assert state == record["planner_state"]
    assert record == retained
    assert ("decision_contract" in state) is current
    if disposition == "budget_stop":
        assert record["provider_called"] is False and record["stop_requested"] is True
        with pytest.raises(AIProviderError, match="not a replayable proposal"):
            validate_persisted_proposal_record(record)
    else:
        assert validate_v4_proposal_record(record) == state
        proposal = validate_persisted_proposal_record(record)
        assert content_hash(proposal.to_dict()) == record["proposal_digest"]
    if disposition == "applied":
        assert record["application_status"] == "applied_reviewed_method"
        assert record["applied_step"] in [
            option["plan_step"] for option in record["registered_options"]
        ]
    else:
        assert record["stop_requested"] is True


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "widened_type",
        "different_step_effect",
        "empty_constraints",
        "changed_objective",
        "null",
        "array",
    ],
)
def test_unknown_or_widened_advisory_is_refused_even_after_rehash(runtime, change):
    record = authored_record(runtime)
    advice = record["planner_state"]["decision_contract"]
    if change == "extra":
        advice["allow_new_targets"] = True
    elif change == "missing":
        advice.pop("selection_effect")
    elif change == "widened_type":
        advice["allowed_proposal_types"].append("mutate_parameters")
    elif change == "different_step_effect":
        advice["selection_effect"] = "Choose any method and retry without a limit."
    elif change == "empty_constraints":
        advice["constraints"] = []
    elif change == "changed_objective":
        advice["constraints"][1] = "Replace the objective if a method cannot satisfy it."
    elif change == "null":
        record["planner_state"]["decision_contract"] = None
    else:
        record["planner_state"]["decision_contract"] = []
    record["planner_state_digest"] = content_hash(record["planner_state"])
    with pytest.raises(DurableProposalRecordError, match="advisory decision contract"):
        validate_v4_attempt_record(record)
    with pytest.raises(AIProviderError, match="advisory decision contract"):
        validate_persisted_proposal_record(record)


@pytest.mark.parametrize("current", [False, True])
def test_adding_or_removing_valid_advice_requires_the_exact_state_digest(runtime, current):
    record = authored_record(runtime, current=current)
    if current:
        record["planner_state"].pop("decision_contract")
    else:
        record["planner_state"]["decision_contract"] = deepcopy(ADAPTIVE_DECISION_CONTRACT)
    with pytest.raises(DurableProposalRecordError, match="state binding"):
        validate_v4_attempt_record(record)


def test_advice_never_authorizes_an_option_or_parameter_outside_the_recorded_set(runtime):
    record = authored_record(runtime)
    record["applied_step"]["parameters"]["unreviewed_parameter"] = True
    with pytest.raises(DurableProposalRecordError):
        validate_v4_attempt_record(record)


def test_unknown_planner_state_fields_remain_refused(runtime):
    record = authored_record(runtime)
    record["planner_state"]["authorize_everything"] = True
    record["planner_state_digest"] = content_hash(record["planner_state"])
    with pytest.raises(DurableProposalRecordError, match="planner state fields"):
        validate_v4_attempt_record(record)

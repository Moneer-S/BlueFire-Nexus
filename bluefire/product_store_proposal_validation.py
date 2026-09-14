"""Proposal option validation shared by durable review persistence."""

from __future__ import annotations

from typing import Any, Mapping

from .ai import AIProposal, ProposalType


def validate_reviewed_option(document: Mapping[str, Any], proposal: AIProposal) -> None:
    if document.get("schema_version") == "bluefire.ai-proposal-record.v4":
        if proposal.proposal_type is not ProposalType.SELECT_REGISTERED_ACTION:
            raise ValueError("finite method review requires an exact method choice")
        matching = [
            option
            for option in document["registered_options"]
            if option["role"] == "retry"
            and (option["step_id"], option["behavior_id"], option["action_id"])
            == (
                proposal.selected_step_id,
                proposal.selected_behavior_id,
                proposal.selected_action_id,
            )
            and option["plan_step"] == document["registered_step"]
        ]
        if len(matching) != 1:
            raise ValueError("finite proposal tuple differs from its exact reviewed method")
        # validate_persisted_proposal_record has checked the v4 policy, hashes,
        # application disposition and exact selected PlanStep before this call.
        return

    role = "retry" if proposal.proposal_type is ProposalType.RETRY_REGISTERED else "next"
    options = document.get("registered_options")
    option = (
        next(
            (
                item
                for item in options
                if isinstance(item, Mapping)
                and item.get("role") == role
                and item.get("step_id") == proposal.selected_step_id
            ),
            None,
        )
        if isinstance(options, list)
        else None
    )
    if option is None or proposal.selected_behavior_id not in option.get("behavior_ids", []):
        raise ValueError("proposal tuple is outside its registered option envelope")
    if proposal.selected_action_id is not None:
        action_map = option.get("action_ids_by_behavior")
        allowed_actions = (
            action_map.get(proposal.selected_behavior_id, [])
            if isinstance(action_map, Mapping)
            else []
        )
        if proposal.selected_action_id not in allowed_actions:
            raise ValueError("proposal action is outside its behavior/profile option envelope")
    evaluation = document.get("proposal_policy_evaluation")
    if (
        not isinstance(evaluation, Mapping)
        or evaluation.get("status") != "permitted"
        or evaluation.get("policy_digest") != document.get("proposal_policy_digest")
    ):
        raise ValueError("proposal was not permitted by its recorded policy")

"""Private verified attempt hooks supplied by the composition controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .adaptive_dispatch import operation_identity
from .runner_contracts import VerifiedGrantAttempt, grant_attempt_authorization_digest
from .runner_reviewed_execution import canonical_reviewed_execution
from .util import content_hash, json_clone


def native_envelope(plan, compiled):
    return canonical_reviewed_execution(
        {
            "schema_version": "bluefire.reviewed-execution.v1",
            "authorization_digest": grant_attempt_authorization_digest(
                compiled["compiled_digest"], content_hash(plan.to_dict())
            ),
            "operations": [operation_identity(step) for step in plan.steps],
        }
    )


@dataclass(frozen=True)
class GrantExecution:
    """Internal effect adapter, never populated from an HTTP request document."""

    authority: VerifiedGrantAttempt
    envelope: Mapping[str, Any]
    check: Callable[[], None]
    bind_profile: Callable[[Mapping[str, Any]], None]
    before_task: Callable[..., None]
    after_task: Callable[..., None]
    cleanup_authority: Callable[..., Any]

    def document(self):
        if type(self.authority) is not VerifiedGrantAttempt:
            raise ValueError("Composition requires a uniquely claimed attempt authority.")
        document = self.authority.to_dict()
        if content_hash(self.envelope) != document["native_envelope_digest"]:
            raise ValueError("Composition changed its exact native envelope.")
        return document

    def validate_plan(self, plan):
        document = self.document()
        if document["plan_digest"] != content_hash(plan.to_dict()):
            raise ValueError("Composition changed its reserved exact plan.")
        operations = canonical_reviewed_execution(
            {
                "schema_version": "bluefire.reviewed-execution.v1",
                "authorization_digest": self.envelope["authorization_digest"],
                "operations": [operation_identity(step) for step in plan.steps],
            }
        )["operations"]
        if self.envelope.get("operations") != operations:
            raise ValueError("Composition changed its reserved operation identities.")
        return dict(json_clone(document))

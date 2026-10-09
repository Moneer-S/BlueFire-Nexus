"""Fixed identities for the existing receiver comparison jobs."""

from typing import Mapping

PHASES = ("baseline", "protected", "restored")
OWNER_KIND = "receiver.defense"
PREPARE_KIND = "receiver.defense.prepare"
INSPECT_KIND = "receiver.defense.inspect"
WORKFLOW = "retained_redaction"
RETAINED_PHASES = ("baseline", "protected", "legitimate")


def retained(context):
    return isinstance(context, Mapping) and context.get("workflow") == WORKFLOW


def phases(context):
    if retained(context):
        return RETAINED_PHASES[1:] if context.get("source_control") else RETAINED_PHASES
    return PHASES

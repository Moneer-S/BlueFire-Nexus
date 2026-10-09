"""Exact retained dependency identities for the two admitted capability packs."""

from .capability_packs import FILE_ACCESS_PACK, grant_pack
from .util import content_hash


def usage_document(grant, compiled, lease):
    common = {
        "attempt_id": lease["attempt_id"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "control_owner_id": lease["control_owner_id"],
        "control_digest": grant["environment"]["control_digest"],
        "lease_digest": lease["lease_digest"],
        "compiled_digest": compiled["compiled_digest"],
    }
    if grant_pack(grant) == FILE_ACCESS_PACK:
        return {
            "schema_version": "bluefire.file-access-control-usage.v1",
            **common,
            "file_access": compiled["file_access"],
        }
    return {
        "schema_version": "bluefire.receiver-control-usage.v1",
        **common,
        "policy_digest": grant["environment"]["policy_digest"],
        "handoff": compiled["handoff"],
    }


def endpoint_digest(environment):
    if "resource_id" in environment:
        fields = ("environment_id", "resource_id")
    else:
        fields = ("environment_id", "port")
    return content_hash({key: environment[key] for key in fields})

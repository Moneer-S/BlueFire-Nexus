"""Closed capability pack identities, never a model-selectable extension registry."""

RECEIVER_PACK = "bluefire.receiver-composition-pack.v1"
FILE_ACCESS_PACK = "bluefire.linux-file-access-pack.v1"
MACOS_FILE_ACCESS_PACK = "bluefire.macos-file-access-pack.v1"
MACOS_FILE_ACCESS_METHODS = (
    "macos.file_access.probe.v1",
    "macos.file_access.verify_owner.v1",
    "macos.file_access.close_attempt.v1",
)
FILE_ACCESS_METHODS = (
    "file_access.probe.non_owner.v1",
    "file_access.verify.owner.v1",
    "sandbox.cleanup.v1",
)


def review_pack(request):
    if not isinstance(request, dict):
        raise ValueError("Composition review requires an exact request object")
    common = {"control_owner_id", "question", "limits"}
    if set(request) == common:
        return RECEIVER_PACK
    if (
        set(request) == common | {"schema_version", "pack"}
        and request["schema_version"] == "bluefire.composition-review-request.v2"
        and request["pack"] in (FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK)
    ):
        return request["pack"]
    raise ValueError("Unsupported composition review schema/pack pair")


def grant_pack(grant):
    if grant.get("schema_version") == "bluefire.capability-grant.v1" and "pack" not in grant:
        pack = RECEIVER_PACK
    elif grant.get("schema_version") == "bluefire.capability-grant.v2" and grant.get("pack") in (
        FILE_ACCESS_PACK,
        MACOS_FILE_ACCESS_PACK,
    ):
        pack = grant["pack"]
    else:
        raise ValueError("Unsupported capability grant schema/pack pair")
    if grant.get("snapshot", {}).get("pack") != pack:
        raise ValueError("Capability snapshot belongs to another pack")
    return pack

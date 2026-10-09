"""Pure compilation of fixed runner filesystem scopes from reviewed plan methods."""

from .planner import ExecutionPlan


def filesystem_scope(plan: ExecutionPlan, *, opcode_for_step) -> tuple[str, ...]:
    """Compile the fixed runner roots needed by this exact reviewed plan."""

    roots_by_action = {
        "sandbox.identity-material.seed.v1": ("identity-material",),
        "sandbox.identity-material.inspect.v1": ("identity-material",),
        "sandbox.fixture.create.v1": ("fixtures",),
        "sandbox.fixture.transform.v1": ("fixtures",),
        "file_access.probe.non_owner.v1": ("fixtures",),
        "file_access.verify.owner.v1": ("fixtures",),
        "sandbox.discovery.list.v1": ("fixtures",),
        "sandbox.discovery.metadata.v1": ("fixtures",),
        "sandbox.discovery.recursive.v1": ("fixtures",),
        "sandbox.archive.tar.v1": ("fixtures", "staged"),
        "sandbox.collection.stage.v1": ("fixtures", "staged"),
        "sandbox.collection.records.v1": ("fixtures", "staged"),
        "sandbox.collection.archive.v1": ("fixtures", "staged"),
        "sandbox.collection.atomic-gzip.v1": ("fixtures", "staged"),
        "sandbox.permission.chmod.v1": ("fixtures",),
        "sandbox.network.loopback.v1": ("staged",),
        "sandbox.peer.handoff.v1": ("staged",),
        "sandbox.observability.variant.v1": ("staged", "observability"),
        "sandbox.export.local.v1": ("staged", "exports"),
        "sandbox.restricted.persistence-marker.v1": ("restricted",),
    }
    selected: list[str] = []
    for step in plan.steps:
        for root in roots_by_action.get(opcode_for_step(step) or "", ()):
            if root not in selected:
                selected.append(root)
    return tuple(selected)

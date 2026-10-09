"""Fresh server-owned endpoint context, separate from public model projections."""

from typing import Any

from .capability_packs import FILE_ACCESS_METHODS
from .contracts import ExecutionMode
from .file_access_contract import canonical_file_access_binding, verify_file_access_binding
from .file_access_enrollment import inspect_file_access_resource, read_file_access_enrollment
from .product_store_errors import ProductStoreError
from .util import content_hash

CONTROL_METHODS = (
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.permission.chmod.v1",
    *FILE_ACCESS_METHODS,
)


def enrollment(service, now_ms):
    current = read_file_access_enrollment(now_ms=now_ms)
    service.product_store.save_file_access_enrollment(
        current["document"], expected_document_digest=current["document_digest"]
    )
    stored = service.product_store.get_file_access_enrollment(current["document"]["enrollment_id"])
    if stored != current:
        raise ProductStoreError("The independently enrolled file-access generation changed.")
    return stored


def execution(service, enrolled):
    document = enrolled["document"]
    profile = service._profile(document["runner_profile_id"], ExecutionMode.EXECUTE)
    if profile is None:
        raise ProductStoreError("The enrolled file-access Execute profile is unavailable.")
    runner, sandbox, readiness = service._execute_readiness_boundary(profile, for_dispatch=True)
    raw = getattr(runner, "runner", runner)
    if not callable(getattr(raw, "execute_task", None)) or not callable(
        getattr(raw, "transport_identity", None)
    ):
        raise ProductStoreError("File access requires authenticated single-task transport.")
    transport = raw.transport_identity()
    if (
        transport.get("schema_version") != "bluefire.runner-transport-identity.v1"
        or transport.get("transport") != "mutual-tls-loopback"
        or transport.get("tls") != "TLSv1.3"
        or readiness["platform"] != "linux"
    ):
        raise ProductStoreError("The authenticated Linux file-access runner is unavailable.")
    catalog = service._catalog_snapshot
    actions = {row["action_id"]: row for row in readiness["enabled_actions"]}
    implementations = {}
    for method in CONTROL_METHODS:
        if actions.get(method, {}).get("readiness") != "ready":
            raise ProductStoreError("The enrolled profile lacks a required file-access method.")
        implementations[method] = content_hash(
            {
                "native": actions[method],
                "binding": catalog.action_bindings.get((method, method)),
                "catalog": catalog.to_dict(),
                "runner_binary_digest": transport.get("runner_binary_digest"),
            }
        )
    intent = {
        "runner_profile_id": profile.id,
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }
    collectors, runtime = service._collector_configuration(intent, mode=ExecutionMode.EXECUTE)
    return {
        "registry": catalog.registry,
        "implementation_digests": implementations,
        "profile": profile,
        "runner": runner,
        "sandbox": sandbox,
        "runner_readiness": readiness,
        "transport": transport,
        "run_intent": intent,
        "collector_ids": collectors,
        "collector_runtime": runtime,
        "enrollment": enrolled,
        "expires_at_ms": document["expires_at_ms"],
    }


def binding(enrolled, *, revision, now_ms):
    observation = inspect_file_access_resource(
        expected_enrollment_digest=enrolled["document_digest"], now_ms=now_ms
    )
    source = enrolled["document"]
    return canonical_file_access_binding(
        {
            "schema_version": "bluefire.file-access-execution.v1",
            **{
                key: source[key]
                for key in (
                    "enrollment_id",
                    "resource_id",
                    "resource_generation",
                    "expires_at_ms",
                    "worker",
                )
            },
            "enrollment_digest": enrolled["document_digest"],
            "control_revision": revision,
            **observation,
        }
    )


def composition(service, owner_id: str, now_ms: int) -> dict[str, Any]:
    stored = service.product_store.get_file_access_control(owner_id)
    control = stored["document"]
    enrolled = enrollment(service, now_ms)
    if (
        control["status"] != "hardened"
        or stored["pending_operation"]
        or control["enrollment_id"] != enrolled["document"]["enrollment_id"]
    ):
        raise ProductStoreError("Composition requires the exact settled hardened file control.")
    actual = binding(enrolled, revision=control["revision"], now_ms=now_ms)
    if actual != control["binding"] or content_hash(actual) != control["binding_digest"]:
        raise ProductStoreError("The retained file or enrolled principal changed since review.")
    current = execution(service, enrolled)
    profile, readiness, transport, intent = (
        current[key] for key in ("profile", "runner_readiness", "transport", "run_intent")
    )
    environment = {
        "environment_id": "environment-" + readiness["sandbox"]["root_digest"][7:],
        "environment_generation": "generation-"
        + content_hash(
            {
                "sandbox": readiness["sandbox"],
                "enrollment_generation": transport["enrollment_generation"],
                "runner_identity": readiness["runner_identity_digest"],
            }
        )[7:],
        "runner_id": transport["runner_id"],
        "enrollment_digest": content_hash(transport),
        "profile_digest": content_hash(profile.to_dict()),
        "target_scope_digest": content_hash(intent["target_scope"]),
        "collector_digest": content_hash(
            service._collector_binding(current["collector_ids"], current["collector_runtime"])
        ),
        "control_owner_id": owner_id,
        "control_digest": stored["document_digest"],
        "resource_id": actual["resource_id"],
        "resource_generation": actual["resource_generation"],
        "resource_digest": content_hash(actual["resource"]),
        "probe_enrollment_digest": enrolled["document_digest"],
        "baseline_digest": control["baseline"]["baseline_digest"],
        "control_revision": control["revision"],
        "mode": actual["mode"],
    }
    return {
        **current,
        "implementation_digests": {
            key: current["implementation_digests"][key] for key in FILE_ACCESS_METHODS
        },
        "current_environment": environment,
        "record_count": actual["resource"]["record_count"],
        "resource_sha256": actual["resource"]["sha256"],
        "baseline": control["baseline"],
        "file_access_binding": verify_file_access_binding(
            actual, expected_document_digest=control["binding_digest"], now_ms=now_ms
        ),
    }

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from bluefire.linux_engine_boundary import (
    LinuxAttemptBoundaryPlan,
    LinuxBoundaryActivationReceipt,
    LinuxBoundaryCleanupReceipt,
    LinuxBoundaryCleanupRequest,
    LinuxBoundaryPrepareRequest,
    LinuxBoundaryReplayState,
    LinuxEngineBoundaryError,
    NamespaceKind,
    validate_activation_receipt,
    validate_activation_revalidation,
    validate_cleanup_receipt,
    validate_cleanup_request,
    validate_prepare_request,
)
from bluefire.util import content_hash


def _d(label: str) -> str:
    return content_hash({"label": label})


def _root(purpose: str, owner: int, *, write: bool) -> dict[str, object]:
    return {
        "purpose": purpose,
        "root_ref": _d(f"root:{purpose}"),
        "parent_ref": _d(f"parent:{purpose}"),
        "expected_owner_uid": owner,
        "expected_mode": 0o700,
        "engine_write_allowed": write,
    }


def _host_namespace_identities() -> dict[NamespaceKind, str]:
    return {kind: _d(f"host-kernel-ns:{kind.value}") for kind in NamespaceKind}


def _host_namespace_snapshot_digest() -> str:
    identities = _host_namespace_identities()
    return content_hash(
        {
            "schema_version": "bluefire.linux-host-namespace-snapshot.v1",
            "identities": [
                {"kind": kind.value, "identity_digest": identities[kind]}
                for kind in sorted(NamespaceKind, key=lambda item: item.value)
            ],
        }
    )


def _plan_document() -> dict[str, object]:
    return {
        "schema_version": "bluefire.linux-engine-boundary-plan.v1",
        "attempt_id": "engine-attempt-" + "a" * 32,
        "owner_ref": _d("owner"),
        "binding_digest": _d("binding"),
        "delegation_digest": _d("delegation"),
        "authority_generation": 7,
        "authority_record_digest": _d("authority"),
        "admission_record_ref": _d("admission-ref"),
        "admission_record_digest": _d("admission-record"),
        "runtime_qualification_ref": _d("qualification"),
        "replay_ledger_ref": _d("replay-ledger"),
        "controller_uid": 0,
        "executable_digest": _d("executable"),
        "leader_ref": _d("leader"),
        "supervisor_ref": _d("supervisor"),
        "created_at": "2026-11-04T16:00:00Z",
        "expires_at": "2026-11-04T16:30:00Z",
        "disposable_identity": {
            "uid": 20_001,
            "gid": 20_001,
            "generation": 3,
            "lease_ref": _d("uid-lease"),
            "preflight_absence_digest": _d("uid-preflight-absence"),
        },
        "namespaces": {
            "mount_ref": _d("ns:mount"),
            "pid_ref": _d("ns:pid"),
            "network_ref": _d("ns:network"),
            "ipc_ref": _d("ns:ipc"),
            "uts_ref": _d("ns:uts"),
            "host_namespace_snapshot_digest": _host_namespace_snapshot_digest(),
        },
        "cgroup": {
            "cgroup_ref": _d("cgroup"),
            "memory_bytes": 512 * 1024**2,
            "cpu_quota_micros": 200_000,
            "cpu_period_micros": 100_000,
            "pids_max": 256,
            "io_policy_digest": _d("io-policy"),
        },
        "protected_roots": sorted(
            (
                _root("worker_workspace", 20_001, write=True),
                _root("controller_control", 0, write=False),
                _root("controller_artifact", 0, write=False),
            ),
            key=lambda row: str(row["purpose"]),
        ),
        "network": {
            "network_policy_digest": _d("network-policy"),
            "bridge_ref": _d("bridge"),
            "target_alias_ref": _d("target-alias"),
            "model_gateway_alias_ref": _d("model-alias"),
            "daemon_ref": _d("daemon"),
            "daemon_proxy_ref": _d("daemon-proxy"),
            "target_relay_ref": _d("target-relay"),
            "model_relay_ref": _d("model-relay"),
            "firewall_policy_digest": _d("firewall-policy"),
        },
    }


def _plan() -> LinuxAttemptBoundaryPlan:
    return LinuxAttemptBoundaryPlan.from_mapping(_plan_document())


def _replay() -> LinuxBoundaryReplayState:
    return LinuxBoundaryReplayState.empty(
        ledger_ref=_d("replay-ledger"), head_digest=_d("replay-head")
    )


def _prepare(plan: LinuxAttemptBoundaryPlan) -> LinuxBoundaryPrepareRequest:
    return LinuxBoundaryPrepareRequest.create(plan, _replay(), requested_at="2026-11-04T16:01:00Z")


def _activation_document(
    plan: LinuxAttemptBoundaryPlan, request: LinuxBoundaryPrepareRequest
) -> dict[str, object]:
    namespace_rows = []
    host_namespaces = _host_namespace_identities()
    for kind in sorted(NamespaceKind, key=lambda item: item.value):
        namespace_rows.append(
            {
                "kind": kind.value,
                "namespace_ref": plan.namespaces.ref_for(kind),
                "kernel_identity_digest": _d(f"kernel-ns:{kind.value}"),
                "host_kernel_identity_digest": host_namespaces[kind],
                "owner_uid": plan.controller_uid,
            }
        )
    root_rows = []
    for root in plan.protected_roots:
        root_rows.append(
            {
                "purpose": root.purpose.value,
                "root_ref": root.root_ref,
                "parent_ref": root.parent_ref,
                "object_identity_digest": _d(f"object:{root.purpose.value}"),
                "parent_identity_digest": _d(f"parent-object:{root.purpose.value}"),
                "mount_identity_digest": _d(f"mount:{root.purpose.value}"),
                "owner_uid": root.expected_owner_uid,
                "mode": root.expected_mode,
                "object_type": "directory",
                "symlink": False,
                "reparse": False,
                "hardlink": False,
                "engine_write_allowed": root.engine_write_allowed,
            }
        )
    network = plan.network
    return {
        "schema_version": "bluefire.linux-engine-boundary-activation.v1",
        "request_ref": request.request_ref,
        "plan_digest": plan.plan_digest,
        "attempt_id": plan.attempt_id,
        "owner_ref": plan.owner_ref,
        "binding_digest": plan.binding_digest,
        "delegation_digest": plan.delegation_digest,
        "authority_generation": plan.authority_generation,
        "authority_record_digest": plan.authority_record_digest,
        "admission_record_ref": plan.admission_record_ref,
        "admission_record_digest": plan.admission_record_digest,
        "uid": plan.disposable_identity.uid,
        "uid_generation": plan.disposable_identity.generation,
        "uid_lease_ref": plan.disposable_identity.lease_ref,
        "observed_at": "2026-11-04T16:02:00Z",
        "host_namespace_snapshot_digest": plan.namespaces.host_namespace_snapshot_digest,
        "namespaces": namespace_rows,
        "cgroup": {
            "cgroup_ref": plan.cgroup.cgroup_ref,
            "kernel_identity_digest": _d("kernel-cgroup"),
            "limits_digest": plan.cgroup.limits_digest,
            "controllers": ["cpu", "io", "memory", "pids"],
            "delegated": True,
            "empty_before_start": True,
        },
        "protected_roots": root_rows,
        "network": {
            "network_policy_digest": network.network_policy_digest,
            "bridge_ref": network.bridge_ref,
            "bridge_identity_digest": _d("bridge-id"),
            "target_alias_ref": network.target_alias_ref,
            "target_alias_identity_digest": _d("target-alias-id"),
            "model_gateway_alias_ref": network.model_gateway_alias_ref,
            "model_gateway_alias_identity_digest": _d("model-alias-id"),
            "daemon_ref": network.daemon_ref,
            "daemon_identity_digest": _d("daemon-id"),
            "daemon_proxy_ref": network.daemon_proxy_ref,
            "daemon_proxy_identity_digest": _d("daemon-proxy-id"),
            "target_relay_ref": network.target_relay_ref,
            "target_relay_identity_digest": _d("target-relay-id"),
            "model_relay_ref": network.model_relay_ref,
            "model_relay_identity_digest": _d("model-relay-id"),
            "firewall_policy_digest": network.firewall_policy_digest,
            "firewall_observation_digest": _d("firewall-observation"),
            "default_egress_denied": True,
            "host_gateway_absent": True,
            "metadata_blocked": True,
        },
        "leader": {
            "leader_ref": plan.leader_ref,
            "supervisor_ref": plan.supervisor_ref,
            "pid": 42_001,
            "start_ticks": 8_800_001,
            "boot_id_digest": _d("boot"),
            "pidfd_ref": _d("pidfd"),
            "pid_namespace_ref": plan.namespaces.pid_ref,
            "session_id": 42_001,
            "process_group_id": 42_001,
            "executable_digest": plan.executable_digest,
        },
        "effective": True,
    }


def _activation(
    plan: LinuxAttemptBoundaryPlan, request: LinuxBoundaryPrepareRequest
) -> LinuxBoundaryActivationReceipt:
    return LinuxBoundaryActivationReceipt.from_mapping(_activation_document(plan, request))


def _cleanup_receipt_document(
    plan: LinuxAttemptBoundaryPlan,
    activation: LinuxBoundaryActivationReceipt,
    request: LinuxBoundaryCleanupRequest,
) -> dict[str, object]:
    return {
        "schema_version": "bluefire.linux-engine-boundary-cleanup-receipt.v1",
        "request_ref": request.request_ref,
        "plan_digest": plan.plan_digest,
        "activation_receipt_digest": activation.receipt_digest,
        "attempt_id": plan.attempt_id,
        "owner_ref": plan.owner_ref,
        "admission_record_ref": plan.admission_record_ref,
        "observed_at": "2026-11-04T16:04:00Z",
        "boot_id_digest": activation.leader.boot_id_digest,
        "daemon_identity_digest": activation.network.daemon_identity_digest,
        "settlement": "verified_absent",
        "leader_absent": True,
        "descendants_absent": True,
        "cgroup_empty": True,
        "cgroup_removed": True,
        "namespaces_absent": True,
        "bridge_removed": True,
        "target_alias_absent": True,
        "model_gateway_alias_absent": True,
        "firewall_removed": True,
        "daemon_proxy_absent": True,
        "supervisor_absent": True,
        "target_relay_absent": True,
        "model_relay_absent": True,
        "protected_roots_absent": True,
        "uid_released": True,
        "residue_refs": [],
        "unverified_refs": [],
    }


def _activation_replay(
    plan: LinuxAttemptBoundaryPlan, request: LinuxBoundaryPrepareRequest
) -> LinuxBoundaryReplayState:
    generation_ref = content_hash(
        {
            "schema_version": "bluefire.linux-disposable-identity-generation.v1",
            "uid": plan.disposable_identity.uid,
            "generation": plan.disposable_identity.generation,
        }
    )
    return replace(
        _replay(),
        head_digest=_d("post-activation-replay-head"),
        ancestor_head_digests=(request.replay_head_digest,),
        consumed_prepare_request_refs=(request.request_ref,),
        consumed_uid_lease_refs=(plan.disposable_identity.lease_ref,),
        consumed_uid_generation_refs=(generation_ref,),
    )


def _cleanup_replay(request: LinuxBoundaryCleanupRequest) -> LinuxBoundaryReplayState:
    return replace(
        _replay(),
        head_digest=_d("post-cleanup-replay-head"),
        ancestor_head_digests=(request.replay_head_digest,),
        consumed_cleanup_request_refs=(request.request_ref,),
    )


def test_round_trip_contract_is_deterministic_and_contains_no_execution_grammar():
    plan = _plan()
    request = _prepare(plan)
    activation = _activation(plan, request)
    replay = _replay()
    validate_activation_receipt(plan, request, activation, replay, retained_receipt=None)
    cleanup = LinuxBoundaryCleanupRequest.create(
        plan, request, activation, replay, requested_at="2026-11-04T16:03:00Z"
    )
    receipt = LinuxBoundaryCleanupReceipt.from_mapping(
        _cleanup_receipt_document(plan, activation, cleanup)
    )
    validate_cleanup_receipt(
        plan,
        request,
        activation,
        cleanup,
        receipt,
        replay,
        retained_receipt=None,
    )

    assert LinuxAttemptBoundaryPlan.from_mapping(plan.to_dict()) == plan
    assert LinuxBoundaryPrepareRequest.from_mapping(request.to_dict()) == request
    assert LinuxBoundaryActivationReceipt.from_mapping(activation.to_dict()) == activation
    assert LinuxBoundaryCleanupRequest.from_mapping(cleanup.to_dict()) == cleanup
    assert LinuxBoundaryCleanupReceipt.from_mapping(receipt.to_dict()) == receipt
    assert plan.plan_digest == content_hash(plan.to_dict())
    assert activation.receipt_digest == content_hash(activation.to_dict())
    assert receipt.receipt_digest == content_hash(receipt.to_dict())
    serialized = json.dumps(
        [
            plan.to_dict(),
            request.to_dict(),
            activation.to_dict(),
            cleanup.to_dict(),
            receipt.to_dict(),
        ]
    ).lower()
    for forbidden in (
        '"argv"',
        '"command"',
        '"environment"',
        '"path"',
        '"credential"',
        '"secret"',
        '"token"',
        '"/"',
        '"~"',
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "field",
    [
        "attempt_id",
        "owner_ref",
        "authority_record_digest",
        "admission_record_ref",
        "admission_record_digest",
    ],
)
def test_prepare_refuses_binding_drift(field: str):
    plan = _plan()
    request = _prepare(plan)
    replacement: object = (
        "engine-attempt-" + "b" * 32 if field == "attempt_id" else _d("drift:" + field)
    )
    with pytest.raises(LinuxEngineBoundaryError, match="identity|not bound"):
        validate_prepare_request(
            plan,
            replace(request, **{field: replacement, "request_ref": _d("new-request")}),
            _replay(),
        )


@pytest.mark.parametrize("field", ["binding_digest", "delegation_digest"])
def test_prepare_refuses_plan_authority_drift(field: str):
    plan = _plan()
    changed = replace(plan, **{field: _d(field)})
    request = LinuxBoundaryPrepareRequest.create(
        changed, _replay(), requested_at="2026-11-04T16:01:00Z"
    )
    with pytest.raises(LinuxEngineBoundaryError, match="identity|not bound"):
        validate_prepare_request(plan, request, _replay())


def test_prepare_refuses_extra_fields_unknown_schema_and_noncanonical_request_identity():
    plan = _plan()
    request = _prepare(plan)
    document = request.to_dict()
    document["command"] = "unshare"
    with pytest.raises(LinuxEngineBoundaryError, match="fields"):
        LinuxBoundaryPrepareRequest.from_mapping(document)
    with pytest.raises(LinuxEngineBoundaryError, match="unsupported"):
        LinuxBoundaryPrepareRequest.from_mapping(
            {**request.to_dict(), "schema_version": "bluefire.linux-engine-boundary-prepare.v2"}
        )
    with pytest.raises(LinuxEngineBoundaryError, match="identity"):
        LinuxBoundaryPrepareRequest.from_mapping(
            {**request.to_dict(), "request_ref": _d("replacement")}
        )


def test_prepare_refuses_request_lease_and_uid_generation_replay():
    plan = _plan()
    request = _prepare(plan)
    with pytest.raises(LinuxEngineBoundaryError, match="already consumed"):
        validate_prepare_request(
            plan,
            request,
            replace(_replay(), consumed_prepare_request_refs=(request.request_ref,)),
        )
    with pytest.raises(LinuxEngineBoundaryError, match="lease was already used"):
        validate_prepare_request(
            plan,
            request,
            replace(
                _replay(),
                consumed_uid_lease_refs=(plan.disposable_identity.lease_ref,),
            ),
        )
    with pytest.raises(LinuxEngineBoundaryError, match="generation was already used"):
        generation_ref = content_hash(
            {
                "schema_version": "bluefire.linux-disposable-identity-generation.v1",
                "uid": plan.disposable_identity.uid,
                "generation": plan.disposable_identity.generation,
            }
        )
        validate_prepare_request(
            plan,
            request,
            replace(_replay(), consumed_uid_generation_refs=(generation_ref,)),
        )


def test_replay_state_is_strict_canonical_and_round_trips():
    state = _replay()
    assert LinuxBoundaryReplayState.from_mapping(state.to_dict()) == state
    with pytest.raises(LinuxEngineBoundaryError, match="fields"):
        LinuxBoundaryReplayState.from_mapping({**state.to_dict(), "request": "run"})
    with pytest.raises(LinuxEngineBoundaryError, match="unique and sorted"):
        unsorted_refs = sorted((_d("a"), _d("b")), reverse=True)
        LinuxBoundaryReplayState.from_mapping(
            {
                **state.to_dict(),
                "consumed_prepare_request_refs": unsorted_refs,
            }
        )
    plan = _plan()
    request = _prepare(plan)
    for drifted in (
        replace(state, ledger_ref=_d("other-ledger")),
        replace(state, head_digest=_d("other-head")),
    ):
        with pytest.raises(LinuxEngineBoundaryError, match="not bound"):
            validate_prepare_request(plan, request, drifted)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda row: row["disposable_identity"].update(uid=1), "UID"),
        (lambda row: row.update(controller_uid=20_001), "identities overlap"),
        (lambda row: row.update(expires_at="2026-11-04T16:31:00Z"), "stale"),
        (
            lambda row: row["namespaces"].update(
                mount_ref=row["namespaces"]["host_namespace_snapshot_digest"]
            ),
            "not isolated",
        ),
        (lambda row: row["network"].update(bridge_ref=row["network"]["daemon_ref"]), "overlap"),
        (lambda row: row["protected_roots"][0].update(root_ref="/"), "sha256"),
        (lambda row: row["protected_roots"][0].update(expected_mode=0o755), "owner private"),
        (lambda row: row["protected_roots"][0].update(engine_write_allowed=True), "write policy"),
    ],
)
def test_plan_refuses_broad_or_reused_boundary_identity(mutate, match: str):
    document = _plan_document()
    mutate(document)
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        LinuxAttemptBoundaryPlan.from_mapping(document)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("binding_digest",), _d("other-binding"), "not bound"),
        (("delegation_digest",), _d("other-delegation"), "not bound"),
        (("authority_generation",), 8, "not bound"),
        (("admission_record_digest",), _d("other-admission"), "not bound"),
        (("uid",), 20_002, "not bound"),
        (("uid_lease_ref",), _d("other-lease"), "not bound"),
        (("effective",), False, "not effective"),
        (("observed_at",), "2026-11-04T16:29:59Z", "stale"),
    ],
)
def test_activation_refuses_authority_or_chronology_drift(path, value, match: str):
    plan = _plan()
    request = _prepare(plan)
    document = _activation_document(plan, request)
    document[path[0]] = value
    receipt = (
        LinuxBoundaryActivationReceipt.from_mapping(document) if path[0] != "effective" else None
    )
    if path[0] == "effective":
        with pytest.raises(LinuxEngineBoundaryError, match=match):
            LinuxBoundaryActivationReceipt.from_mapping(document)
    else:
        assert receipt is not None
        with pytest.raises(LinuxEngineBoundaryError, match=match):
            validate_activation_receipt(plan, request, receipt, _replay(), retained_receipt=None)


def test_activation_binds_the_exact_canonical_host_namespace_snapshot():
    plan = _plan()
    request = _prepare(plan)
    wrong_snapshot = _activation_document(plan, request)
    wrong_snapshot["host_namespace_snapshot_digest"] = _d("other-host-snapshot")
    with pytest.raises(LinuxEngineBoundaryError, match="snapshot changed"):
        validate_activation_receipt(
            plan,
            request,
            LinuxBoundaryActivationReceipt.from_mapping(wrong_snapshot),
            _replay(),
            retained_receipt=None,
        )
    wrong_member = _activation_document(plan, request)
    namespaces = wrong_member["namespaces"]
    assert isinstance(namespaces, list)
    namespaces[0]["host_kernel_identity_digest"] = _d("other-host-ipc")
    with pytest.raises(LinuxEngineBoundaryError, match="not canonical"):
        validate_activation_receipt(
            plan,
            request,
            LinuxBoundaryActivationReceipt.from_mapping(wrong_member),
            _replay(),
            retained_receipt=None,
        )


@pytest.mark.parametrize(
    ("section", "index", "field", "value", "match"),
    [
        (
            "namespaces",
            0,
            "kernel_identity_digest",
            _host_namespace_identities()[NamespaceKind.IPC],
            "not distinct",
        ),
        ("namespaces", 0, "namespace_ref", _d("other-ns"), "changed from the plan"),
        ("namespaces", 0, "owner_uid", 20_001, "owner changed"),
        ("protected_roots", 0, "symlink", True, "link-backed"),
        ("protected_roots", 0, "reparse", True, "link-backed"),
        ("protected_roots", 0, "hardlink", True, "link-backed"),
        ("protected_roots", 0, "object_type", "file", "owner-private directory"),
        ("protected_roots", 0, "mode", 0o777, "owner-private directory"),
    ],
)
def test_activation_refuses_namespace_and_root_substitution(
    section: str, index: int, field: str, value: object, match: str
):
    plan = _plan()
    request = _prepare(plan)
    document = _activation_document(plan, request)
    rows = document[section]
    assert isinstance(rows, list)
    rows[index][field] = value
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        receipt = LinuxBoundaryActivationReceipt.from_mapping(document)
        validate_activation_receipt(plan, request, receipt, _replay(), retained_receipt=None)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("cgroup_ref", _d("other-cgroup"), "changed from the plan"),
        ("limits_digest", _d("other-limits"), "changed from the plan"),
        ("controllers", ["cpu", "memory", "pids"], "incomplete"),
        ("delegated", False, "custody"),
        ("empty_before_start", False, "custody"),
    ],
)
def test_activation_refuses_cgroup_drift(field: str, value: object, match: str):
    plan = _plan()
    request = _prepare(plan)
    document = _activation_document(plan, request)
    cgroup = document["cgroup"]
    assert isinstance(cgroup, dict)
    cgroup[field] = value
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        receipt = LinuxBoundaryActivationReceipt.from_mapping(document)
        validate_activation_receipt(plan, request, receipt, _replay(), retained_receipt=None)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("bridge_ref", _d("other-bridge"), "changed from the plan"),
        ("firewall_policy_digest", _d("other-firewall"), "changed from the plan"),
        ("default_egress_denied", False, "fail-closed"),
        ("host_gateway_absent", False, "fail-closed"),
        ("metadata_blocked", False, "fail-closed"),
        ("bridge_identity_digest", _d("daemon-id"), "overlap"),
    ],
)
def test_activation_refuses_network_drift(field: str, value: object, match: str):
    plan = _plan()
    request = _prepare(plan)
    document = _activation_document(plan, request)
    network = document["network"]
    assert isinstance(network, dict)
    network[field] = value
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        receipt = LinuxBoundaryActivationReceipt.from_mapping(document)
        validate_activation_receipt(plan, request, receipt, _replay(), retained_receipt=None)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("leader_ref", _d("other-leader"), "changed from the plan"),
        ("pid_namespace_ref", _d("other-pid-ns"), "changed from the plan"),
        ("executable_digest", _d("other-executable"), "changed from the plan"),
        ("session_id", 42_002, "private session"),
        ("process_group_id", 42_002, "private session"),
        ("start_ticks", 0, "outside"),
    ],
)
def test_activation_refuses_process_identity_drift(field: str, value: object, match: str):
    plan = _plan()
    request = _prepare(plan)
    document = _activation_document(plan, request)
    leader = document["leader"]
    assert isinstance(leader, dict)
    leader[field] = value
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        receipt = LinuxBoundaryActivationReceipt.from_mapping(document)
        validate_activation_receipt(plan, request, receipt, _replay(), retained_receipt=None)


def test_cleanup_allows_expired_plan_but_refuses_replay_and_wrong_activation():
    plan = _plan()
    prepare = _prepare(plan)
    activation = _activation(plan, prepare)
    cleanup = LinuxBoundaryCleanupRequest.create(
        plan, prepare, activation, _replay(), requested_at="2026-11-05T16:03:00Z"
    )
    validate_cleanup_request(plan, prepare, activation, cleanup, _replay())
    for drifted in (
        replace(_replay(), ledger_ref=_d("other-cleanup-ledger")),
        replace(_replay(), head_digest=_d("other-cleanup-head")),
    ):
        with pytest.raises(LinuxEngineBoundaryError, match="not bound"):
            validate_cleanup_request(plan, prepare, activation, cleanup, drifted)
    with pytest.raises(LinuxEngineBoundaryError, match="already consumed"):
        validate_cleanup_request(
            plan,
            prepare,
            activation,
            cleanup,
            replace(_replay(), consumed_cleanup_request_refs=(cleanup.request_ref,)),
        )
    with pytest.raises(LinuxEngineBoundaryError, match="identity|not bound"):
        validate_cleanup_request(
            plan,
            prepare,
            activation,
            replace(
                cleanup,
                activation_receipt_digest=_d("other-activation"),
                request_ref=_d("other-request"),
            ),
            _replay(),
        )
    with pytest.raises(LinuxEngineBoundaryError, match="not bound"):
        validate_cleanup_request(
            plan,
            prepare,
            replace(activation, binding_digest=_d("forged-binding")),
            cleanup,
            _replay(),
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("settlement", "unknown", "not verified absent"),
        ("leader_absent", False, "incomplete"),
        ("descendants_absent", False, "incomplete"),
        ("cgroup_empty", False, "incomplete"),
        ("cgroup_removed", False, "incomplete"),
        ("namespaces_absent", False, "incomplete"),
        ("bridge_removed", False, "incomplete"),
        ("target_alias_absent", False, "incomplete"),
        ("model_gateway_alias_absent", False, "incomplete"),
        ("firewall_removed", False, "incomplete"),
        ("daemon_proxy_absent", False, "incomplete"),
        ("supervisor_absent", False, "incomplete"),
        ("target_relay_absent", False, "incomplete"),
        ("model_relay_absent", False, "incomplete"),
        ("protected_roots_absent", False, "incomplete"),
        ("uid_released", False, "incomplete"),
        ("residue_refs", [_d("residue")], "residue"),
        ("unverified_refs", [_d("unverified")], "uncertainty"),
    ],
)
def test_cleanup_receipt_refuses_partial_or_unknown_settlement(
    field: str, value: object, match: str
):
    plan = _plan()
    prepare = _prepare(plan)
    activation = _activation(plan, prepare)
    cleanup = LinuxBoundaryCleanupRequest.create(
        plan, prepare, activation, _replay(), requested_at="2026-11-04T16:03:00Z"
    )
    document = _cleanup_receipt_document(plan, activation, cleanup)
    document[field] = value
    with pytest.raises(LinuxEngineBoundaryError, match=match):
        LinuxBoundaryCleanupReceipt.from_mapping(document)


def test_cleanup_receipt_refuses_binding_and_stale_observation():
    plan = _plan()
    prepare = _prepare(plan)
    activation = _activation(plan, prepare)
    cleanup = LinuxBoundaryCleanupRequest.create(
        plan, prepare, activation, _replay(), requested_at="2026-11-04T16:03:00Z"
    )
    document = _cleanup_receipt_document(plan, activation, cleanup)
    receipt = LinuxBoundaryCleanupReceipt.from_mapping({**document, "owner_ref": _d("other-owner")})
    with pytest.raises(LinuxEngineBoundaryError, match="not bound"):
        validate_cleanup_receipt(
            plan,
            prepare,
            activation,
            cleanup,
            receipt,
            _replay(),
            retained_receipt=None,
        )
    stale = LinuxBoundaryCleanupReceipt.from_mapping(
        {**document, "observed_at": "2026-11-04T16:14:01Z"}
    )
    with pytest.raises(LinuxEngineBoundaryError, match="stale"):
        validate_cleanup_receipt(
            plan,
            prepare,
            activation,
            cleanup,
            stale,
            _replay(),
            retained_receipt=None,
        )

    for field in ("boot_id_digest", "daemon_identity_digest"):
        drifted = LinuxBoundaryCleanupReceipt.from_mapping(
            {**document, field: _d("other-" + field)}
        )
        with pytest.raises(LinuxEngineBoundaryError, match="not bound"):
            validate_cleanup_receipt(
                plan,
                prepare,
                activation,
                cleanup,
                drifted,
                _replay(),
                retained_receipt=None,
            )


def test_cleanup_receipt_exact_reopen_requires_consumed_descendant_claim():
    plan = _plan()
    prepare = _prepare(plan)
    activation = _activation(plan, prepare)
    cleanup = LinuxBoundaryCleanupRequest.create(
        plan, prepare, activation, _replay(), requested_at="2026-11-04T16:03:00Z"
    )
    receipt = LinuxBoundaryCleanupReceipt.from_mapping(
        _cleanup_receipt_document(plan, activation, cleanup)
    )
    validate_cleanup_receipt(
        plan,
        prepare,
        activation,
        cleanup,
        receipt,
        _replay(),
        retained_receipt=None,
    )
    consumed = _cleanup_replay(cleanup)
    validate_cleanup_receipt(
        plan,
        prepare,
        activation,
        cleanup,
        receipt,
        consumed,
        retained_receipt=receipt,
    )
    with pytest.raises(LinuxEngineBoundaryError, match="retry changed"):
        validate_cleanup_receipt(
            plan,
            prepare,
            activation,
            cleanup,
            replace(receipt, observed_at="2026-11-04T16:04:01Z"),
            consumed,
            retained_receipt=receipt,
        )
    with pytest.raises(LinuxEngineBoundaryError, match="consumed replay claim"):
        validate_cleanup_receipt(
            plan,
            prepare,
            activation,
            cleanup,
            receipt,
            replace(consumed, consumed_cleanup_request_refs=()),
            retained_receipt=receipt,
        )


def test_activation_exact_digest_detects_root_or_service_replacement():
    plan = _plan()
    prepare = _prepare(plan)
    first = _activation(plan, prepare)
    changed_document = _activation_document(plan, prepare)
    roots = changed_document["protected_roots"]
    assert isinstance(roots, list)
    roots[0]["object_identity_digest"] = _d("replacement-root-object")
    second = LinuxBoundaryActivationReceipt.from_mapping(changed_document)
    validate_activation_receipt(plan, prepare, first, _replay(), retained_receipt=None)
    consumed = _activation_replay(plan, prepare)
    validate_activation_receipt(plan, prepare, first, consumed, retained_receipt=first)
    with pytest.raises(LinuxEngineBoundaryError, match="consumed replay claim"):
        validate_activation_receipt(plan, prepare, first, _replay(), retained_receipt=first)
    with pytest.raises(LinuxEngineBoundaryError, match="retry changed"):
        validate_activation_receipt(plan, prepare, second, consumed, retained_receipt=first)
    with pytest.raises(LinuxEngineBoundaryError, match="changed during revalidation"):
        validate_activation_revalidation(
            plan,
            prepare,
            first,
            replace(second, observed_at="2026-11-04T16:02:30Z"),
        )
    with pytest.raises(LinuxEngineBoundaryError, match="chronology"):
        validate_activation_revalidation(plan, prepare, first, first)
    fresh = replace(first, observed_at="2026-11-04T16:02:30Z")
    validate_activation_revalidation(plan, prepare, first, fresh)

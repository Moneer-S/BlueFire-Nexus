from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any, Mapping, Sequence

import pytest

from bluefire.engine_container_custody import (
    V2_RUNTIME_PLATFORM,
    ContainerCustodyPlan,
    ContainerCustodyPlanV2,
    CustodySettlement,
    DaemonInventory,
    DaemonInventoryV2,
    EngineContainerCustodyError,
    assess_container_custody,
    container_image_identity_digest,
    settle_container_custody,
)

ATTEMPT_ID = "engine-attempt-" + "a" * 32
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
IMAGE_REFERENCE_V2 = "ghcr.io/usestrix/sandbox@" + DIGEST_A
NETWORK_ID = "1" * 64
PREEXISTING_ID = "2" * 64
OWNED_ID = "3" * 64
UNEXPECTED_ID = "4" * 64


def container(
    resource_id: str,
    *,
    labels: Mapping[str, str] | None = None,
    image_digest: str = DIGEST_B,
) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "name": "strix-sandbox-" + resource_id[:12],
        "labels": dict(labels or {}),
        "image_digest": image_digest,
        "network_ids": [NETWORK_ID],
        "mounts": [mount()],
        "capabilities": ["NET_ADMIN", "NET_RAW"],
        "user": "1000:1000",
        "privileged": False,
        "devices": [],
        "network_mode": "bluefire-engine",
        "pid_mode": "private",
        "ipc_mode": "private",
        "uts_mode": "private",
        "memory_bytes": 2 * 1024**3,
        "nano_cpus": 2_000_000_000,
        "pids_limit": 512,
    }


def mount(
    *,
    mount_type: str = "tmpfs",
    source: str = "",
    destination: str = "/workspace",
    read_only: bool = False,
    options_digest: str = DIGEST_A,
) -> dict[str, Any]:
    return {
        "mount_type": mount_type,
        "source": source,
        "destination": destination,
        "read_only": read_only,
        "options_digest": options_digest,
    }


def volume(resource_id: str, *, labels: Mapping[str, str] | None = None) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "name": "resource-" + resource_id[:12],
        "labels": dict(labels or {}),
    }


def network(
    resource_id: str = NETWORK_ID,
    *,
    labels: Mapping[str, str] | None = None,
    internal: bool = True,
    policy_digest: str = DIGEST_C,
) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "name": "network-" + resource_id[:12],
        "labels": dict(labels or {"bluefire.owner": "controller"}),
        "internal": internal,
        "policy_digest": policy_digest,
    }


def inventory(
    *,
    containers: list[dict[str, Any]] | None = None,
    networks: list[dict[str, Any]] | None = None,
    volumes: list[dict[str, Any]] | None = None,
    daemon_digest: str = DIGEST_A,
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-daemon-inventory.v1",
        "daemon_instance_digest": daemon_digest,
        "containers": containers or [],
        "networks": [network()] if networks is None else networks,
        "volumes": [] if volumes is None else volumes,
    }


def plan(baseline: DaemonInventory) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-container-custody.v1",
        "attempt_id": ATTEMPT_ID,
        "daemon_instance_digest": DIGEST_A,
        "disposable_boundary_ref": DIGEST_B,
        "baseline_inventory_digest": baseline.inventory_digest,
        "required_labels": {"bluefire.engine.attempt": ATTEMPT_ID},
        "sandbox_image_digest": DIGEST_B,
        "network_id": NETWORK_ID,
        "network_policy_digest": DIGEST_C,
        "expected_mounts": [mount()],
        "expected_capabilities": ["NET_ADMIN", "NET_RAW"],
        "expected_user": "1000:1000",
        "memory_bytes": 2 * 1024**3,
        "nano_cpus": 2_000_000_000,
        "pids_limit": 512,
        "expected_container_count": 1,
    }


def plan_v2(baseline: DaemonInventoryV2) -> dict[str, Any]:
    common = plan(DaemonInventory.from_mapping(inventory()))
    common["schema_version"] = "bluefire.engine-container-custody.v2"
    common["baseline_inventory_digest"] = baseline.inventory_digest
    common.pop("sandbox_image_digest")
    identity = {
        "image_reference": IMAGE_REFERENCE_V2,
        "runtime_platform": V2_RUNTIME_PLATFORM,
        "platform_child_manifest_digest": DIGEST_B,
        "image_config_digest": DIGEST_C,
        "image_relation_receipt_ref": DIGEST_D,
    }
    common.update(identity)
    common["required_labels"] = {
        "bluefire.engine.attempt": ATTEMPT_ID,
        "bluefire.engine.image-identity": container_image_identity_digest(**identity),
    }
    return common


def inventory_v2(*, containers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        **inventory(containers=containers),
        "schema_version": "bluefire.engine-daemon-inventory.v2",
    }


def container_v2(*, config: str = DIGEST_C, reference: str = IMAGE_REFERENCE_V2) -> dict[str, Any]:
    row = container(
        OWNED_ID,
        labels={
            "bluefire.engine.attempt": ATTEMPT_ID,
            "bluefire.engine.image-identity": container_image_identity_digest(
                image_reference=IMAGE_REFERENCE_V2,
                runtime_platform=V2_RUNTIME_PLATFORM,
                platform_child_manifest_digest=DIGEST_B,
                image_config_digest=DIGEST_C,
                image_relation_receipt_ref=DIGEST_D,
            ),
        },
    )
    row.pop("image_digest")
    row["image_config_digest"] = config
    row["configured_image_reference"] = reference
    return row


def attempt_labels() -> dict[str, str]:
    return {"bluefire.engine.attempt": ATTEMPT_ID}


class FakeControl:
    def __init__(self, snapshots: Sequence[Mapping[str, Any]], *, fail: bool = False) -> None:
        self._snapshots = [deepcopy(dict(item)) for item in snapshots]
        self.removed: list[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = []
        self.fail = fail

    def snapshot(self) -> Mapping[str, Any]:
        if not self._snapshots:
            raise RuntimeError("no snapshot")
        if len(self._snapshots) == 1:
            return self._snapshots[0]
        return self._snapshots.pop(0)

    def remove_owned_resources(
        self,
        *,
        container_ids: Sequence[str],
        network_ids: Sequence[str],
        volume_ids: Sequence[str],
    ) -> None:
        self.removed.append((tuple(container_ids), tuple(network_ids), tuple(volume_ids)))
        if self.fail:
            raise RuntimeError("cleanup failed")


def test_canonical_round_trip_and_plan_digest() -> None:
    baseline = DaemonInventory.from_mapping(
        inventory(containers=[container(PREEXISTING_ID, labels={"owner": "prepared-lab"})])
    )
    parsed = ContainerCustodyPlan.from_mapping(plan(baseline))

    assert ContainerCustodyPlan.from_mapping(parsed.to_dict()) == parsed
    assert DaemonInventory.from_mapping(baseline.to_dict()) == baseline
    assert parsed.plan_digest.startswith("sha256:")
    assert baseline.inventory_digest.startswith("sha256:")


def test_v2_custody_binds_distinct_image_roles_and_observes_config_and_reference() -> None:
    baseline = DaemonInventoryV2.from_mapping(inventory_v2())
    custody = ContainerCustodyPlanV2.from_mapping(plan_v2(baseline))
    current = DaemonInventoryV2.from_mapping(inventory_v2(containers=[container_v2()]))
    assert ContainerCustodyPlanV2.from_mapping(custody.to_dict()) == custody
    assert DaemonInventoryV2.from_mapping(current.to_dict()) == current
    assert (
        custody.plan_digest
        != ContainerCustodyPlan.from_mapping(
            plan(DaemonInventory.from_mapping(inventory()))
        ).plan_digest
    )
    assert assess_container_custody(custody, baseline, current).qualified
    for field, replacement in (
        ("image_reference", "ghcr.io/bluefire/other@" + DIGEST_A),
        ("platform_child_manifest_digest", DIGEST_D),
        ("image_config_digest", DIGEST_D),
        ("image_relation_receipt_ref", "sha256:" + "e" * 64),
    ):
        changed = plan_v2(baseline)
        changed[field] = replacement
        identity = {
            key: changed[key]
            for key in (
                "image_reference",
                "runtime_platform",
                "platform_child_manifest_digest",
                "image_config_digest",
                "image_relation_receipt_ref",
            )
        }
        changed["required_labels"]["bluefire.engine.image-identity"] = (
            container_image_identity_digest(**identity)
        )
        assert ContainerCustodyPlanV2.from_mapping(changed).plan_digest != custody.plan_digest

    wrong_config = DaemonInventoryV2.from_mapping(
        inventory_v2(containers=[container_v2(config=DIGEST_B)])
    )
    wrong_reference = DaemonInventoryV2.from_mapping(
        inventory_v2(containers=[container_v2(reference="ghcr.io/other/repo@" + DIGEST_A)])
    )
    assert any(
        item.endswith(":image_config_digest")
        for item in assess_container_custody(custody, baseline, wrong_config).policy_violations
    )
    assert any(
        item.endswith(":configured_image_reference")
        for item in assess_container_custody(custody, baseline, wrong_reference).policy_violations
    )


def test_v2_custody_rejects_legacy_fields_mixed_snapshots_and_role_substitution() -> None:
    baseline = DaemonInventoryV2.from_mapping(inventory_v2())
    value = plan_v2(baseline)
    for field, replacement in (
        ("platform_child_manifest_digest", DIGEST_A),
        ("image_config_digest", DIGEST_B),
        ("image_relation_receipt_ref", ""),
    ):
        changed = deepcopy(value)
        changed[field] = replacement
        with pytest.raises(EngineContainerCustodyError):
            ContainerCustodyPlanV2.from_mapping(changed)
    changed = deepcopy(value)
    changed["sandbox_image_digest"] = DIGEST_C
    with pytest.raises(EngineContainerCustodyError, match="fields"):
        ContainerCustodyPlanV2.from_mapping(changed)
    legacy = plan(DaemonInventory.from_mapping(inventory()))
    legacy["image_config_digest"] = DIGEST_C
    with pytest.raises(EngineContainerCustodyError, match="fields"):
        ContainerCustodyPlan.from_mapping(legacy)
    custody = ContainerCustodyPlanV2.from_mapping(value)
    malformed_direct_plan = replace(
        custody, required_labels=(("bluefire.engine.attempt", ATTEMPT_ID),)
    )
    with pytest.raises(EngineContainerCustodyError, match="v2 custody inputs"):
        assess_container_custody(malformed_direct_plan, baseline, baseline)
    malformed_direct_inventory = replace(
        baseline, schema_version="bluefire.engine-daemon-inventory.v1"
    )
    with pytest.raises(EngineContainerCustodyError, match="v2 custody inputs"):
        assess_container_custody(custody, malformed_direct_inventory, baseline)
    with pytest.raises(EngineContainerCustodyError, match="v2 daemon inventories"):
        assess_container_custody(
            custody,
            DaemonInventory.from_mapping(inventory()),
            DaemonInventory.from_mapping(inventory()),
        )
    changed_inventory = inventory_v2(containers=[container_v2()])
    changed_inventory["containers"][0]["image_digest"] = DIGEST_C
    with pytest.raises(EngineContainerCustodyError, match="fields"):
        DaemonInventoryV2.from_mapping(changed_inventory)


@pytest.mark.parametrize(
    "reference",
    [
        "repo/image@" + DIGEST_A,
        "ghcr.io/repo:tag@" + DIGEST_A,
        "ghcr.io:5000/repo@" + DIGEST_A,
        "ghcr.io//repo@" + DIGEST_A,
        "https://ghcr.io/repo@" + DIGEST_A,
        "GHCR.io/repo@" + DIGEST_A,
    ],
)
def test_v2_custody_and_observations_use_strict_contract_reference(reference: str) -> None:
    baseline = DaemonInventoryV2.from_mapping(inventory_v2())
    value = plan_v2(baseline)
    value["image_reference"] = reference
    with pytest.raises(EngineContainerCustodyError, match="image reference"):
        ContainerCustodyPlanV2.from_mapping(value)
    with pytest.raises(EngineContainerCustodyError, match="image reference"):
        DaemonInventoryV2.from_mapping(inventory_v2(containers=[container_v2(reference=reference)]))


def test_plan_requires_attempt_bound_labels_and_pinned_image() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    value = plan(baseline)
    value["required_labels"] = {"bluefire.engine.attempt": "engine-attempt-" + "b" * 32}
    with pytest.raises(EngineContainerCustodyError, match="bind the attempt"):
        ContainerCustodyPlan.from_mapping(value)

    value = plan(baseline)
    value["sandbox_image_digest"] = "strix-sandbox:latest"
    with pytest.raises(EngineContainerCustodyError, match="sandbox image"):
        ContainerCustodyPlan.from_mapping(value)


@pytest.mark.parametrize("mount_type", ["bind", "npipe"])
def test_host_and_socket_mount_types_are_rejected(mount_type: str) -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    value = plan(baseline)
    value["expected_mounts"] = [mount(mount_type=mount_type, source="/host/path")]
    with pytest.raises(EngineContainerCustodyError, match="source-free tmpfs"):
        ContainerCustodyPlan.from_mapping(value)

    row = container(OWNED_ID, labels=attempt_labels())
    row["mounts"] = [mount(mount_type=mount_type, source="/host/path")]
    current = DaemonInventory.from_mapping(inventory(containers=[row]))
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    result = assess_container_custody(custody, baseline, current)
    assert f"container:{OWNED_ID}:host_mount" in result.policy_violations


def test_tmpfs_destination_and_options_are_bound_exactly() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    row = container(OWNED_ID, labels=attempt_labels())
    row["mounts"] = [mount(destination="/tmp", options_digest=DIGEST_B)]
    current = DaemonInventory.from_mapping(inventory(containers=[row]))

    result = assess_container_custody(custody, baseline, current)

    assert f"container:{OWNED_ID}:mounts" in result.policy_violations
    assert f"container:{OWNED_ID}:host_mount" not in result.policy_violations


def test_owned_container_with_no_mounts_is_still_stopped() -> None:
    baseline_mapping = inventory()
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    row = container(OWNED_ID, labels=attempt_labels())
    row["mounts"] = []
    control = FakeControl([inventory(containers=[row]), baseline_mapping])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.VERIFIED_ABSENT
    assert f"container:{OWNED_ID}:mounts" in result.assessment.policy_violations
    assert control.removed == [((OWNED_ID,), (), ())]


def test_baseline_diff_and_label_are_both_required_for_ownership() -> None:
    preexisting = container(PREEXISTING_ID, labels=attempt_labels())
    baseline = DaemonInventory.from_mapping(inventory(containers=[preexisting]))
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    current = DaemonInventory.from_mapping(
        inventory(
            containers=[
                preexisting,
                container(OWNED_ID, labels=attempt_labels()),
                container(UNEXPECTED_ID, labels={"owner": "someone-else"}),
            ]
        )
    )

    result = assess_container_custody(custody, baseline, current)

    assert result.owned_container_ids == (OWNED_ID,)
    assert result.unowned_new_ids == (f"container:{UNEXPECTED_ID}",)
    assert PREEXISTING_ID not in result.owned_container_ids
    assert not result.qualified


def test_effective_container_settings_are_checked() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    row = container(OWNED_ID, labels=attempt_labels(), image_digest=DIGEST_C)
    row.update(
        {
            "network_ids": ["5" * 64],
            "capabilities": ["NET_RAW"],
            "user": "root",
            "privileged": True,
            "devices": ["gpu0"],
            "network_mode": "host",
            "pid_mode": "host",
            "memory_bytes": 1024,
            "nano_cpus": 1,
            "pids_limit": 1,
        }
    )
    current = DaemonInventory.from_mapping(inventory(containers=[row]))

    result = assess_container_custody(custody, baseline, current)

    assert result.owned_container_ids == (OWNED_ID,)
    assert not result.qualified
    assert any(item.endswith(":image_digest") for item in result.policy_violations)
    assert any(item.endswith(":host_network") for item in result.policy_violations)
    assert any(item.endswith(":host_namespace") for item in result.policy_violations)
    assert any(item.endswith(":privileged") for item in result.policy_violations)


def test_settlement_stops_only_positively_owned_resources_and_proves_absence() -> None:
    preexisting = container(PREEXISTING_ID, labels={"owner": "prepared-lab"})
    baseline_mapping = inventory(containers=[preexisting])
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    active = inventory(containers=[preexisting, container(OWNED_ID, labels=attempt_labels())])
    control = FakeControl([active, baseline_mapping])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.VERIFIED_ABSENT
    assert control.removed == [((OWNED_ID,), (), ())]
    assert PREEXISTING_ID not in control.removed[0][0]
    assert result.final_inventory_digest == baseline.inventory_digest


def test_unowned_new_resource_makes_settlement_unknown_without_cleanup() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    active = inventory(containers=[container(UNEXPECTED_ID, labels={"owner": "other"})])
    control = FakeControl([active])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.UNKNOWN
    assert result.limitations == ("dedicated_daemon_baseline_violated",)
    assert control.removed == [((), (), ())]


def test_owned_policy_violation_is_still_cleaned_but_not_qualified() -> None:
    baseline_mapping = inventory()
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    row = container(OWNED_ID, labels=attempt_labels(), image_digest=DIGEST_C)
    control = FakeControl([inventory(containers=[row]), baseline_mapping])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.VERIFIED_ABSENT
    assert not result.assessment.qualified
    assert control.removed == [((OWNED_ID,), (), ())]


def test_owned_network_and_volume_are_removed_and_remain_policy_violations() -> None:
    baseline_mapping = inventory()
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    network_id = "6" * 64
    volume_id = "7" * 64
    active = inventory(
        networks=[network(), network(network_id, labels=attempt_labels())],
        volumes=[volume(volume_id, labels=attempt_labels())],
    )
    control = FakeControl([active, baseline_mapping])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.VERIFIED_ABSENT
    assert set(result.assessment.policy_violations) == {
        "container_count_mismatch",
        "unexpected_network_created",
        "unexpected_volume_created",
    }
    assert control.removed == [((), (network_id,), (volume_id,))]


def test_remaining_owned_resource_reports_residue() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    active = inventory(containers=[container(OWNED_ID, labels=attempt_labels())])
    control = FakeControl([active, active])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.RESIDUE
    assert result.limitations == ("owned_resources_remain",)


def test_cleanup_failure_and_daemon_change_are_unknown() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    active = inventory(containers=[container(OWNED_ID, labels=attempt_labels())])

    failed = settle_container_custody(custody, baseline, FakeControl([active], fail=True))
    changed = settle_container_custody(
        custody,
        baseline,
        FakeControl([inventory(daemon_digest=DIGEST_C)]),
    )

    assert failed.state is CustodySettlement.UNKNOWN
    assert failed.limitations == ("custody_cleanup_failed:RuntimeError",)
    assert changed.state is CustodySettlement.UNKNOWN
    assert changed.limitations == ("custody_snapshot_failed:EngineContainerCustodyError",)


def test_inventory_rejects_noncanonical_order_and_label_order() -> None:
    with pytest.raises(EngineContainerCustodyError, match="unique and sorted"):
        DaemonInventory.from_mapping(
            inventory(
                containers=[
                    container(OWNED_ID, labels=attempt_labels()),
                    container(PREEXISTING_ID, labels=attempt_labels()),
                ]
            )
        )

    row = container(OWNED_ID, labels={"z": "last", "a": "first"})
    with pytest.raises(EngineContainerCustodyError, match="sorted keys"):
        DaemonInventory.from_mapping(inventory(containers=[row]))


def test_missing_or_changed_baseline_resource_makes_settlement_unknown() -> None:
    preexisting = container(PREEXISTING_ID, labels={"owner": "prepared-lab"})
    baseline_mapping = inventory(containers=[preexisting])
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    owned = container(OWNED_ID, labels=attempt_labels())
    active = inventory(containers=[preexisting, owned])
    mutated = deepcopy(preexisting)
    mutated["memory_bytes"] = 0
    final = inventory(containers=[mutated])
    control = FakeControl([active, final])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.UNKNOWN
    assert control.removed == [((OWNED_ID,), (), ())]
    assert result.limitations == ("dedicated_daemon_baseline_violated",)


def test_no_observed_sandbox_does_not_qualify_settings() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))

    result = assess_container_custody(custody, baseline, baseline)

    assert not result.qualified
    assert "container_count_mismatch" in result.policy_violations


def test_expected_network_policy_and_internal_mode_are_verified() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    changed_network = network(internal=False, policy_digest=DIGEST_B)
    current = DaemonInventory.from_mapping(
        inventory(
            containers=[container(OWNED_ID, labels=attempt_labels())],
            networks=[changed_network],
        )
    )

    result = assess_container_custody(custody, baseline, current)

    assert "expected_network_not_internal" in result.policy_violations
    assert "expected_network_policy_mismatch" in result.policy_violations
    assert f"baseline_network_changed:{NETWORK_ID}" in result.policy_violations


def test_resource_identity_is_qualified_by_kind() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    shared_id = "8" * 64
    current = DaemonInventory.from_mapping(
        inventory(
            containers=[container(shared_id, labels=attempt_labels())],
            volumes=[volume(shared_id, labels={"owner": "other"})],
        )
    )

    result = assess_container_custody(custody, baseline, current)

    assert result.owned_container_ids == (shared_id,)
    assert result.owned_volume_ids == ()
    assert result.unowned_new_ids == (f"volume:{shared_id}",)


def test_expected_network_must_preexist_in_the_bound_baseline() -> None:
    baseline = DaemonInventory.from_mapping(inventory(networks=[]))
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    current = DaemonInventory.from_mapping(
        inventory(
            containers=[container(OWNED_ID, labels=attempt_labels())],
            networks=[network()],
        )
    )

    result = assess_container_custody(custody, baseline, current)

    assert "expected_network_missing_from_baseline" in result.policy_violations
    assert "unexpected_network_created" not in result.policy_violations
    assert result.unowned_new_ids == (f"network:{NETWORK_ID}",)


def test_named_volume_handle_can_be_custodied_and_removed() -> None:
    baseline_mapping = inventory()
    baseline = DaemonInventory.from_mapping(baseline_mapping)
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    handle = "bluefire_engine_attempt_workspace"
    active = inventory(volumes=[volume(handle, labels=attempt_labels())])
    control = FakeControl([active, baseline_mapping])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.VERIFIED_ABSENT
    assert control.removed == [((), (), (handle,))]


def test_unowned_named_volume_is_not_touched_while_owned_container_is_stopped() -> None:
    baseline = DaemonInventory.from_mapping(inventory())
    custody = ContainerCustodyPlan.from_mapping(plan(baseline))
    handle = "unrelated_named_volume"
    active = inventory(
        containers=[container(OWNED_ID, labels=attempt_labels())],
        volumes=[volume(handle, labels={"owner": "other"})],
    )
    final = inventory(volumes=[volume(handle, labels={"owner": "other"})])
    control = FakeControl([active, final])

    result = settle_container_custody(custody, baseline, control)

    assert result.state is CustodySettlement.UNKNOWN
    assert control.removed == [((OWNED_ID,), (), ())]
    assert result.assessment.unowned_new_ids == (f"volume:{handle}",)

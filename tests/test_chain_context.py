"""Chain context v2 — typed view over accumulated step artifacts.

The orchestrator threads a :class:`ChainContext` through its scenario
loop and exposes a serialisable snapshot under ``context["chain"]`` to
every module's ``execute``. These tests pin the behaviour modules
(and the planner / report / AI surfaces) rely on:

- typed indexing by canonical artifact type
- per-step indexing for "what did this upstream step emit?"
- latest_artifact / candidate_artifacts lookups
- provenance (step_id, module, key) follows every propagated value
- consumer warnings when a required input has not been produced
- prior results cannot be mutated downstream
"""

from __future__ import annotations

import pytest

from src.core.modules import (
    ArtifactSpec,
    CapabilityIOContract,
    ChainContext,
    chain_provenance,
    consumes,
    latest_artifact_value,
    produces,
)
from src.core.modules.contracts import (
    CREDENTIAL,
    HOST,
    STAGED_FILE,
    USER,
)


def _discovery_contract() -> CapabilityIOContract:
    return CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=HOST, key="targets", description="enumerated hosts"),
        ),
    )


def _credential_contract() -> CapabilityIOContract:
    return CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, key="target", description="target host"),
        ),
        produces=produces(
            ArtifactSpec(type=CREDENTIAL, key="credential", description="extracted credential"),
        ),
    )


def _exfiltration_contract() -> CapabilityIOContract:
    return CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=STAGED_FILE, key="staged_file", description="file to exfil"),
        ),
    )


def test_record_step_indexes_typed_artifacts_by_type_and_step():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.5", "10.0.0.6"]},
    )
    snapshot = chain.snapshot()
    assert "host" in snapshot["artifacts_by_type"]
    assert snapshot["artifacts_by_type"]["host"][0]["value"] == [
        "10.0.0.5",
        "10.0.0.6",
    ]
    assert snapshot["artifacts_by_step"]["disc-1"][0]["type"] == "host"


def test_latest_artifact_returns_most_recent_emission():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.5"]},
    )
    chain.record_step(
        step_id="disc-2",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.99"]},
    )
    latest = chain.latest_artifact("host")
    assert latest is not None
    assert latest.value == ["10.0.0.99"]
    assert latest.step_id == "disc-2"


def test_candidate_artifacts_returns_every_emission_in_insertion_order():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.1"]},
    )
    chain.record_step(
        step_id="disc-2",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.2"]},
    )
    rows = chain.candidate_artifacts("host")
    assert len(rows) == 2
    assert [r.step_id for r in rows] == ["disc-1", "disc-2"]


def test_provenance_records_step_module_and_key():
    chain = ChainContext()
    chain.record_step(
        step_id="creds-1",
        module="credential_access",
        contract=_credential_contract(),
        artifacts={"credential": {"hash": "abc"}},
    )
    latest = chain.latest_artifact("credential")
    assert latest is not None
    assert latest.provenance == {
        "step_id": "creds-1",
        "module": "credential_access",
        "key": "credential",
    }


def test_consumer_warning_fires_when_required_type_is_missing():
    chain = ChainContext()
    # No upstream emissions before the consumer runs.
    chain.record_consumer_warning(
        step_id="exfil-1",
        module="exfiltration",
        contract=_exfiltration_contract(),
    )
    snapshot = chain.snapshot()
    assert len(snapshot["warnings"]) == 1
    warning = snapshot["warnings"][0]
    assert warning == {
        "step_id": "exfil-1",
        "module": "exfiltration",
        "missing_type": "staged_file",
        "missing_key": "staged_file",
    }


def test_consumer_warning_silent_when_required_type_already_present():
    chain = ChainContext()
    chain.record_step(
        step_id="coll-1",
        module="collection",
        contract=CapabilityIOContract(
            produces=produces(
                ArtifactSpec(type=STAGED_FILE, key="staged_file", description="staged"),
            ),
        ),
        artifacts={"staged_file": "stage_001.bin"},
    )
    chain.record_consumer_warning(
        step_id="exfil-1",
        module="exfiltration",
        contract=_exfiltration_contract(),
    )
    snapshot = chain.snapshot()
    assert snapshot["warnings"] == []


def test_optional_consumer_slots_do_not_emit_warnings():
    optional_contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=USER, key="user", required=False),
        ),
    )
    chain = ChainContext()
    chain.record_consumer_warning(
        step_id="step-1",
        module="some_module",
        contract=optional_contract,
    )
    assert chain.snapshot()["warnings"] == []


def test_record_step_skips_keys_with_empty_value():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": []},
    )
    assert chain.snapshot()["artifacts_by_type"] == {}


def test_record_step_no_contract_is_no_op():
    chain = ChainContext()
    chain.record_step(
        step_id="x",
        module="anonymous",
        contract=None,
        artifacts={"anything": "value"},
    )
    assert chain.snapshot() == {
        "artifacts_by_type": {},
        "artifacts_by_step": {},
        "warnings": [],
    }


def test_chain_snapshot_is_isolated_from_subsequent_mutation():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.1"]},
    )
    snapshot = chain.snapshot()
    # Subsequent record on the live chain must not change the snapshot.
    chain.record_step(
        step_id="disc-2",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.2"]},
    )
    assert len(snapshot["artifacts_by_type"]["host"]) == 1
    # And mutating the snapshot must not affect the chain.
    snapshot["artifacts_by_type"]["host"][0]["value"].append("mutated")
    refreshed = chain.snapshot()
    assert refreshed["artifacts_by_type"]["host"][0]["value"] == [
        "10.0.0.1"
    ]


def test_latest_artifact_value_helper_resolves_from_snapshot():
    chain = ChainContext()
    chain.record_step(
        step_id="creds-1",
        module="credential_access",
        contract=_credential_contract(),
        artifacts={"credential": {"hash": "abc"}},
    )
    snapshot = chain.snapshot()
    assert latest_artifact_value(snapshot, "credential") == {"hash": "abc"}
    assert latest_artifact_value(snapshot, "host") is None
    # Aliases should normalise.
    assert latest_artifact_value(snapshot, "credentials") == {"hash": "abc"}


def test_chain_provenance_helper_resolves_from_snapshot():
    chain = ChainContext()
    chain.record_step(
        step_id="creds-1",
        module="credential_access",
        contract=_credential_contract(),
        artifacts={"credential": "lab-token"},
    )
    snapshot = chain.snapshot()
    prov = chain_provenance(snapshot, "credential")
    assert prov == {
        "step_id": "creds-1",
        "module": "credential_access",
        "key": "credential",
    }


def test_chain_provenance_returns_none_when_type_absent():
    chain = ChainContext()
    snapshot = chain.snapshot()
    assert chain_provenance(snapshot, "credential") is None


def test_artifacts_by_step_returns_only_that_steps_emissions():
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=_discovery_contract(),
        artifacts={"targets": ["10.0.0.1"]},
    )
    chain.record_step(
        step_id="creds-1",
        module="credential_access",
        contract=_credential_contract(),
        artifacts={"credential": "x"},
    )
    rows = chain.artifacts_by_step("disc-1")
    assert len(rows) == 1
    assert rows[0].type == "host"


def test_chain_starts_empty_and_safely_returns_none():
    chain = ChainContext()
    assert chain.latest_artifact("host") is None
    assert chain.candidate_artifacts("host") == ()
    assert chain.has("host") is False
    assert chain.snapshot() == {
        "artifacts_by_type": {},
        "artifacts_by_step": {},
        "warnings": [],
    }


def test_lookup_apis_normalise_alias_inputs():
    """Codex P2: ``has`` / ``latest_artifact`` / ``candidate_artifacts``
    must normalise an operator alias (``credentials`` -> ``credential``,
    ``hosts`` -> ``host``, ``c2_endpoints`` -> ``c2_endpoint``) before
    reading the type-indexed map. Without it a consumer that uses
    :class:`ChainContext` directly silently misses valid upstream
    data, since :meth:`record_step` always indexes under contract
    types (canonical) but the lookup compared raw input keys.

    The helper functions ``latest_artifact_value`` and
    ``chain_provenance`` already normalised; the in-memory builder
    API must agree.
    """

    chain = ChainContext()
    chain.record_step(
        step_id="creds-1",
        module="credential_access",
        contract=_credential_contract(),
        artifacts={"credential": {"hash": "abc"}},
    )
    # Canonical lookup still works.
    assert chain.has("credential") is True
    assert chain.latest_artifact("credential") is not None
    # Alias lookups must find the same row.
    assert chain.has("credentials") is True
    assert chain.has("creds") is True
    latest_alias = chain.latest_artifact("credentials")
    assert latest_alias is not None
    assert latest_alias.value == {"hash": "abc"}
    candidates_alias = chain.candidate_artifacts("creds")
    assert len(candidates_alias) == 1


def test_lookup_apis_treat_unknown_type_as_missing():
    """Unknown artifact-type labels must not raise from the lookup APIs.

    The helper functions ``latest_artifact_value`` /
    ``chain_provenance`` raise ``ValueError`` on unknown labels via
    :func:`normalise_artifact_type`. The in-memory builder API stays
    permissive — callers that use ``ChainContext`` directly should
    treat unknown labels as "no match" rather than crashing the run.
    """

    chain = ChainContext()
    assert chain.has("definitely-not-a-real-type") is False
    assert chain.latest_artifact("definitely-not-a-real-type") is None
    assert chain.candidate_artifacts("definitely-not-a-real-type") == ()


def test_produced_if_scalar_value_matches():
    """ArtifactSpec(produced_if=("kind", "host")) should only index when
    the run's artifacts['kind'] equals "host"."""

    contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(
                type=HOST,
                key="targets",
                produced_if=("kind", "host"),
            ),
            ArtifactSpec(
                type=USER,
                key="targets",
                produced_if=("kind", "user"),
            ),
        ),
    )
    chain = ChainContext()
    chain.record_step(
        step_id="step-1",
        module="discovery",
        contract=contract,
        artifacts={"kind": "host", "targets": ["10.0.0.1"]},
    )
    snapshot = chain.snapshot()
    assert "host" in snapshot["artifacts_by_type"]
    assert "user" not in snapshot["artifacts_by_type"]


def test_produced_if_tuple_value_matches_any_member():
    """A tuple ``produced_if`` value should match if the run's value is
    in the tuple (any-match wins)."""

    contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(
                type=HOST,
                key="targets",
                produced_if=("kind", ("host_discovery", "network_scan", "port_scan")),
            ),
        ),
    )
    chain = ChainContext()
    for kind in ("host_discovery", "network_scan", "port_scan"):
        ch = ChainContext()
        ch.record_step(
            step_id="step-1",
            module="discovery",
            contract=contract,
            artifacts={"kind": kind, "targets": ["10.0.0.1"]},
        )
        assert "host" in ch.snapshot()["artifacts_by_type"], (
            f"expected host emission for kind={kind}"
        )


def test_produced_if_predicate_failure_skips_indexing():
    """When the discriminator does not match, the spec is skipped
    entirely. The same key with a passing spec still indexes."""

    contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=HOST, key="targets", produced_if=("kind", "host")),
            ArtifactSpec(type=USER, key="targets", produced_if=("kind", "user")),
            ArtifactSpec(type=CREDENTIAL, key="extracted"),  # always-applicable
        ),
    )
    chain = ChainContext()
    chain.record_step(
        step_id="step-1",
        module="multi",
        contract=contract,
        artifacts={
            "kind": "user",
            "targets": ["alice", "bob"],
            "extracted": "lab-token",
        },
    )
    snapshot = chain.snapshot()
    by_type = snapshot["artifacts_by_type"]
    assert "user" in by_type
    assert by_type["user"][0]["value"] == ["alice", "bob"]
    assert "host" not in by_type  # predicate failed
    assert "credential" in by_type  # no predicate, always applies


def test_produced_if_missing_discriminator_key_skips_spec():
    """If the run's artifacts dict does not carry the discriminator
    key at all, the predicate fails (compared against ``None``) and
    the spec is skipped."""

    contract = CapabilityIOContract(
        produces=produces(
            ArtifactSpec(type=HOST, key="targets", produced_if=("kind", "host")),
        ),
    )
    chain = ChainContext()
    chain.record_step(
        step_id="step-1",
        module="discovery",
        contract=contract,
        artifacts={"targets": ["10.0.0.1"]},  # no "kind"
    )
    assert chain.snapshot()["artifacts_by_type"] == {}


def test_discovery_contract_files_only_emits_file(tmp_path):
    """End-to-end Codex P1 fix: discovery's IO contract has six specs
    sharing key=targets (host / service / share / user / file /
    impact_target). Without ``produced_if`` discrimination, a single
    ``targets`` value would be indexed under ALL six types.

    Pinned shape: ``discovery_type: files`` only emits ``file`` rows
    (plus ``discovery_result`` when the discovered list is non-empty).
    """

    from src.core.modules import build_runtime_modules

    registry = build_runtime_modules()
    discovery = registry["discovery"]
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=discovery.io_contract,
        artifacts={
            "discovery_type": "files",
            "targets": ["/etc/passwd", "/var/log"],
            "discovered": [{"target": "/etc/passwd", "status": "simulated_up"}],
        },
    )
    by_type = chain.snapshot()["artifacts_by_type"]
    # File is the only typed-target emission for discovery_type=files.
    assert set(by_type.keys()) == {"discovery_result", "file"}
    assert by_type["file"][0]["value"] == ["/etc/passwd", "/var/log"]


def test_discovery_contract_host_discovery_emits_host_and_impact_target():
    """``discovery_type: host_discovery`` should emit both ``host``
    (the canonical host enumeration) and ``impact_target`` (the
    abstract view that impact-tactic consumers want).
    """

    from src.core.modules import build_runtime_modules

    registry = build_runtime_modules()
    discovery = registry["discovery"]
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=discovery.io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [{"target": "10.0.0.5", "status": "simulated_up"}],
        },
    )
    by_type = chain.snapshot()["artifacts_by_type"]
    assert "host" in by_type
    assert "impact_target" in by_type
    # Files / users / services are NOT indexed for a host scan.
    assert "file" not in by_type
    assert "user" not in by_type
    assert "service" not in by_type

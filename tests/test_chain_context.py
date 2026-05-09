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

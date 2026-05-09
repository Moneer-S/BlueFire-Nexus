"""Capability IO contract registry-wide invariants.

Every module returned by ``build_runtime_modules`` must declare a
meaningful :class:`CapabilityIOContract` so the chaining engine,
scenario planner, AI orchestrator, and report views can reason about
what the module produces and consumes. A module that genuinely has no
chain-relevant IO must opt out explicitly via
``not_applicable=True`` with a written reason.
"""

from __future__ import annotations

import pytest

from src.core.modules import (
    ARTIFACT_TYPES,
    ArtifactSpec,
    CapabilityIOContract,
    build_runtime_modules,
    is_meaningful_contract,
    normalise_artifact_type,
)
from src.core.modules.contracts import (
    C2_ENDPOINT,
    COLLECTED_DATA,
    CREDENTIAL,
    EXFIL_PACKAGE,
    HOST,
    PROCESS,
    STAGED_FILE,
    TOKEN,
    USER,
    consumes,
    produces,
)


@pytest.fixture(scope="module")
def registry() -> dict:
    """Single shared registry instantiation for the contract checks."""

    return build_runtime_modules()


def test_every_registered_module_declares_meaningful_contract(registry):
    """Either declare produces / consumes, or explicitly opt out."""

    missing = []
    for name, module in registry.items():
        contract = getattr(module, "io_contract", None)
        if not is_meaningful_contract(contract):
            missing.append(name)
    assert not missing, (
        "Modules without a meaningful CapabilityIOContract: "
        f"{sorted(missing)}. Either declare produces/consumes or set "
        "not_applicable=True with a reason."
    )


def test_every_declared_artifact_type_is_in_vocabulary(registry):
    """No module can declare a type outside ``ARTIFACT_TYPES``."""

    bad: list[tuple[str, str, str]] = []  # (module, slot, type)
    for name, module in registry.items():
        contract = getattr(module, "io_contract", None)
        if contract is None:
            continue
        for spec in contract.produces:
            if spec.type not in ARTIFACT_TYPES:
                bad.append((name, "produces", spec.type))
        for spec in contract.consumes:
            if spec.type not in ARTIFACT_TYPES:
                bad.append((name, "consumes", spec.type))
    assert not bad, (
        f"Modules declaring out-of-vocabulary artifact types: {bad}. "
        f"Allowed: {ARTIFACT_TYPES}"
    )


def test_offensive_chain_pairs_have_compatible_contracts(registry):
    """Pin known chain pairings against the declared contracts.

    These pairings are the offensive backbone: discovery -> credential
    access (host -> credential), credential access -> lateral movement
    (credential -> host pivot), collection -> exfiltration (staged
    file / collected data -> exfil package), etc.

    A regression in any consumer's required types or in any producer's
    declared types should fail this test loudly.
    """

    chains = [
        # (producer, producer_emits_type, consumer, consumer_consumes_type)
        ("discovery", HOST, "credential_access", HOST),
        ("discovery", HOST, "lateral_movement", HOST),
        ("credential_access", CREDENTIAL, "lateral_movement", CREDENTIAL),
        ("collection", STAGED_FILE, "exfiltration", STAGED_FILE),
        ("collection", COLLECTED_DATA, "exfiltration", COLLECTED_DATA),
        ("collection", STAGED_FILE, "impact", STAGED_FILE),
        ("resource_development", C2_ENDPOINT, "command_control", C2_ENDPOINT),
        ("execution", PROCESS, "persistence", PROCESS),
        ("execution", PROCESS, "defense_evasion", PROCESS),
        ("initial_access", USER, "credential_access", USER),
        ("credential_access", TOKEN, "privilege_escalation", TOKEN),
        ("privilege_escalation", TOKEN, "lateral_movement", TOKEN),
    ]
    for producer_name, produced_type, consumer_name, consumed_type in chains:
        producer = registry[producer_name]
        consumer = registry[consumer_name]
        assert produced_type in producer.io_contract.produced_types(), (
            f"{producer_name} should declare {produced_type!r} as a produced "
            f"type but only declares {producer.io_contract.produced_types()}"
        )
        assert consumed_type in consumer.io_contract.consumed_types(), (
            f"{consumer_name} should declare {consumed_type!r} as a consumed "
            f"type but only declares {consumer.io_contract.consumed_types()}"
        )


def test_chain_terminator_modules_produce_chain_relevant_artifact(registry):
    """Exfiltration / impact / persistence are chain terminators.

    Each must produce *something* the report layer or downstream stage
    can correlate against — not an empty produces list.
    """

    for terminator in ("exfiltration", "impact", "persistence"):
        contract = registry[terminator].io_contract
        assert contract.produces, (
            f"{terminator} must declare at least one produced artifact "
            f"so report / downstream stages can correlate against it."
        )


def test_legacy_capability_summary_uses_not_applicable_optout(registry):
    """Diagnostic adapter must flag itself as not-applicable."""

    contract = registry["legacy_capability_summary"].io_contract
    assert contract.not_applicable, (
        "legacy_capability_summary should opt out via not_applicable=True"
    )
    assert contract.not_applicable_reason.strip(), (
        "legacy_capability_summary not_applicable_reason must be set"
    )


def test_artifact_aliases_normalise_into_canonical_types():
    """Common synonym strings normalise to the canonical vocabulary."""

    assert normalise_artifact_type("credentials") == CREDENTIAL
    assert normalise_artifact_type("creds") == CREDENTIAL
    assert normalise_artifact_type("hosts") == HOST
    assert normalise_artifact_type("c2_endpoints") == C2_ENDPOINT
    assert normalise_artifact_type("HOST") == HOST  # case-insensitive


def test_normalise_rejects_unknown_artifact_type():
    """Unknown labels must raise so a typo never silently lands."""

    with pytest.raises(ValueError):
        normalise_artifact_type("definitely-not-a-real-type")


def test_artifact_spec_normalises_aliases_at_construction():
    """``ArtifactSpec(type='credentials')`` should land as ``credential``."""

    spec = ArtifactSpec(type="credentials", key="x")
    assert spec.type == CREDENTIAL


def test_capability_io_contract_rejects_not_applicable_without_reason():
    """The opt-out flag without a reason is a defect, not a shortcut."""

    with pytest.raises(ValueError):
        CapabilityIOContract(not_applicable=True)


def test_required_consumed_types_excludes_optional_slots():
    """Optional slots must not appear in the required-consumed view."""

    contract = CapabilityIOContract(
        consumes=consumes(
            ArtifactSpec(type=HOST, required=True),
            ArtifactSpec(type=USER, required=False),
        ),
    )
    assert contract.required_consumed_types() == (HOST,)


def test_produces_consumes_helpers_accept_bare_strings():
    """Convenience: bare type strings wrap as required, key-less specs."""

    p = produces(HOST, USER)
    assert all(spec.required for spec in p)
    assert {spec.type for spec in p} == {HOST, USER}

    c = consumes(CREDENTIAL)
    assert all(spec.required for spec in c)


def test_every_module_consumed_type_is_produced_by_at_least_one_other(registry):
    """A consumed type that no other module produces is dead metadata.

    The sole exception is the chain entry: ``initial_access`` and
    ``execution`` and ``discovery`` may consume ``host`` because the
    operator supplies it directly via params. Anything else consumed
    must be producible somewhere in the registry, otherwise the chain
    metadata is misleading.
    """

    produced_types: set[str] = set()
    for module in registry.values():
        produced_types.update(module.io_contract.produced_types())

    dead_consumes: list[tuple[str, str]] = []
    for name, module in registry.items():
        for spec in module.io_contract.consumes:
            if spec.type not in produced_types:
                dead_consumes.append((name, spec.type))

    assert not dead_consumes, (
        "Modules consuming artifact types that no other module produces: "
        f"{dead_consumes}. Either fix the producer's contract or remove "
        "the unrealistic consumer."
    )


def test_exfil_package_terminator_visible(registry):
    """``exfil_package`` is the terminator type — confirm exfil emits it."""

    assert EXFIL_PACKAGE in registry["exfiltration"].io_contract.produced_types()

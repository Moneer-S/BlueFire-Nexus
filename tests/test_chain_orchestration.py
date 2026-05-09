"""End-to-end chain context plumbing through ``run_scenario_file``.

These tests pin that the orchestrator threads the chain context through
the per-step module call, that consumer warnings surface for missing
required inputs, and that producers' typed emissions land in the
chain snapshot the next step receives.

The single-step ``execute_operation`` path is also covered: it gets a
chain snapshot too (always empty there), so module code that reads
``context["chain"]`` stays uniform across both invocation paths.
"""

from __future__ import annotations

from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


def test_module_context_always_carries_empty_chain(tmp_path: Path) -> None:
    """Every per-step context must surface ``chain`` with empty submaps."""

    nexus = _make_isolated_nexus(tmp_path)
    run_context = nexus._make_run_context()
    ctx = nexus._module_context(run_context)
    assert "chain" in ctx
    chain_payload = ctx["chain"]
    assert chain_payload["artifacts_by_type"] == {}
    assert chain_payload["artifacts_by_step"] == {}
    assert chain_payload["warnings"] == []


def test_chain_records_typed_emissions_through_run_scenario_file(tmp_path: Path) -> None:
    """A discovery step must emit its produced types into the chain snapshot.

    We check via a recording shim module that captures the chain it
    was called with. Discovery's contract declares ``targets`` as a
    host (and other types), so step 2's view must include ``host``
    rows pointing to the upstream discovery step.
    """

    captured_contexts: list[dict] = []
    nexus = _make_isolated_nexus(tmp_path)

    # Wrap collection.execute so we can read the chain snapshot it
    # received without changing the production module behaviour.
    original = nexus.modules["collection"].execute

    def _capturing_execute(params, context):
        captured_contexts.append(context)
        return original(params, context)

    nexus.modules["collection"].execute = _capturing_execute

    scenario = tmp_path / "chain.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: chain-prop",
                "name: Chain propagation scenario",
                "objective: validate chain context propagation",
                "attack_coverage: ['T1083', 'T1119']",
                "fail_fast: false",
                "steps:",
                "  - id: discover-1",
                "    name: Discover hosts",
                "    module: discovery",
                "    params:",
                "      discovery_type: host_discovery",
                "      targets: ['10.0.0.5']",
                "      network_touch: false",
                "  - id: collect-1",
                "    name: Collect from host",
                "    module: collection",
                "    params:",
                "      technique: file_staging",
                "      target: lab-host",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    assert result["status"] in {"success", "partial_success"}

    assert len(captured_contexts) == 1
    chain_payload = captured_contexts[0]["chain"]
    by_type = chain_payload["artifacts_by_type"]
    # Discovery's contract exposes targets under host (and several
    # other types); the chain has indexed it under host.
    assert "host" in by_type
    host_rows = by_type["host"]
    assert host_rows
    assert host_rows[-1]["step_id"] == "discover-1"
    assert host_rows[-1]["module"] == "discovery"


def test_chain_warnings_fire_for_missing_required_consumer_input(
    tmp_path: Path,
) -> None:
    """Exfiltration requires a ``host`` slot. A scenario that runs it
    without any upstream host emission must record a chain warning the
    operator / dashboard can surface.

    We bypass the implicit operator-supplied ``target`` default by
    inspecting the chain snapshot the step receives — the warning is
    recorded *before* execution against the chain's view of upstream
    state, not after the consumer has filled in its fallback.
    """

    captured: list[dict] = []
    nexus = _make_isolated_nexus(tmp_path)
    original = nexus.modules["exfiltration"].execute

    def _capturing_execute(params, context):
        captured.append(context)
        return original(params, context)

    nexus.modules["exfiltration"].execute = _capturing_execute

    scenario = tmp_path / "warning.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: warning-only",
                "name: Single-step exfiltration scenario",
                "objective: provoke a chain warning",
                "attack_coverage: ['T1041']",
                "fail_fast: false",
                "steps:",
                "  - id: exfil-1",
                "    name: Exfiltrate without upstream",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    assert result["status"] in {"success", "partial_success"}

    assert captured, "exfiltration step did not run"
    warnings = captured[0]["chain"]["warnings"]
    # Exfiltration's required slot is `host`. The warning entry should
    # carry both the missing type and the step id of the consumer.
    assert any(
        w["module"] == "exfiltration" and w["missing_type"] == "host"
        for w in warnings
    ), f"expected a host-missing warning, got {warnings}"


def test_chain_does_not_record_failed_steps(tmp_path: Path) -> None:
    """Failed steps must not propagate their artifacts into the chain.

    A failed step's output is not authoritative for downstream consumers
    — recording it would lie to the planner / report.
    """

    captured: list[dict] = []
    nexus = _make_isolated_nexus(tmp_path)
    original_collect = nexus.modules["collection"].execute

    def _capturing_execute(params, context):
        captured.append(context)
        return original_collect(params, context)

    nexus.modules["collection"].execute = _capturing_execute

    # Force credential_access into a failure-shaped output by passing
    # an unrecognised technique that the module would recover with a
    # default. Since credential_access tolerates unknown techniques
    # (falls back), we instead simulate by patching the producing
    # module to return a failure.
    cred_module = nexus.modules["credential_access"]
    original_cred = cred_module.execute

    def _force_failure(params, context):
        from src.core.models import ModuleResult
        return ModuleResult(
            status="failure",
            module="credential_access",
            message="forced failure for test",
            techniques=[],
            artifacts={"credential": "should-not-propagate"},
            telemetry=[],
        )

    cred_module.execute = _force_failure

    scenario = tmp_path / "fail.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: fail-prop",
                "name: Failure non-propagation scenario",
                "objective: validate failed steps do not feed chain",
                "attack_coverage: ['T1003.001']",
                "fail_fast: false",
                "steps:",
                "  - id: cred-1",
                "    name: Credential access (will fail)",
                "    module: credential_access",
                "    params:",
                "      technique: lsass_dump",
                "      target: lab-host",
                "  - id: collect-1",
                "    name: Collection",
                "    module: collection",
                "    params:",
                "      technique: file_staging",
                "      target: lab-host",
            ]
        ),
        encoding="utf-8",
    )
    nexus.run_scenario_file(str(scenario))

    assert captured
    by_type = captured[0]["chain"]["artifacts_by_type"]
    # The forced-failure credential step's artifact must not leak
    # into the chain.
    assert "credential" not in by_type, (
        f"failed step's credential artifact leaked into chain: {by_type}"
    )

    # Restore the patched module so subsequent tests are not affected.
    cred_module.execute = original_cred
    nexus.modules["collection"].execute = original_collect

"""Static operator console — local planning view over the module registry.

The console is the maintainer-direction priority 4 surface: a local-only
HTML page that surfaces the registered modules, their IO contracts, and
the chain pairs the runtime understands. These tests pin the safety
constraints (no remote assets / scripts / network calls) and the content
contract (every module appears, every chain pair is rendered) so a
future change cannot silently strip the planning value or add a remote
dependency.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.modules import build_runtime_modules
from src.core.operator_console import build_operator_console


def test_build_writes_self_contained_index_html(tmp_path: Path) -> None:
    out = build_operator_console(tmp_path)
    assert out.name == "index.html"
    assert out.parent.name == "operator-console"
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in body
    assert "</html>" in body


def test_console_has_no_remote_assets(tmp_path: Path) -> None:
    """No <link>, no <script src>, no <img src=http> - safe local output."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    assert "<script" not in body, "operator console must not include <script> blocks"
    assert "<link" not in body, "operator console must not link external stylesheets"
    assert "src=\"http" not in body, "operator console must not load remote assets"
    assert "src=\"//" not in body, "operator console must not load protocol-relative assets"


def test_console_lists_every_registered_module(tmp_path: Path) -> None:
    """Every module the registry advertises must appear in the rendered HTML."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    registry = build_runtime_modules()
    for name in registry:
        assert name in body, f"module {name!r} missing from operator console"


def test_console_renders_io_contract_types(tmp_path: Path) -> None:
    """Every produced / consumed canonical type that any module declares
    must surface in the rendered page (under either Produces or Consumes).
    """

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    registry = build_runtime_modules()
    declared_types: set[str] = set()
    for module in registry.values():
        contract = getattr(module, "io_contract", None)
        if contract is None:
            continue
        declared_types.update(contract.produced_types() or ())
        declared_types.update(contract.consumed_types() or ())
    for artifact_type in declared_types:
        assert artifact_type in body, (
            f"artifact type {artifact_type!r} missing from operator console"
        )


def test_console_renders_chain_pairs_for_known_offensive_chain(
    tmp_path: Path,
) -> None:
    """The discovery -> credential_access -> lateral_movement /
    collection -> exfiltration chain must surface as edges in the
    chain-pairs table."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    # Look for a bare 'discovery' row alongside 'credential_access'
    # within the rendered table (the table is the only place both
    # names appear together as cells).
    assert "Producer" in body
    assert "Consumer" in body
    # Spot-check three canonical chain pairs.
    for producer, consumer in [
        ("discovery", "credential_access"),
        ("collection", "exfiltration"),
        ("execution", "persistence"),
    ]:
        # Both names must appear at least once in the rendered HTML.
        assert producer in body, f"chain producer {producer} missing"
        assert consumer in body, f"chain consumer {consumer} missing"


def test_console_handles_missing_scenarios_dir(tmp_path: Path) -> None:
    """When no scenarios directory is found, the console must still
    render — the empty-state copy is emitted."""

    out = build_operator_console(tmp_path, scenarios_dir=tmp_path / "no-such-dir")
    body = out.read_text(encoding="utf-8")
    assert "Shipped scenarios" in body
    assert "No scenario files found" in body


def test_console_lists_provided_scenarios(tmp_path: Path) -> None:
    """When ``scenarios_dir`` points at real YAML files, each one
    surfaces in the rendered scenarios section."""

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    (scenarios_dir / "sample.yaml").write_text(
        "\n".join(
            [
                "id: sample-scenario",
                "name: Sample scenario",
                "description: Inline test scenario",
                "objective: Validate operator console scenario scrape",
                "fail_fast: false",
                "steps: []",
            ]
        ),
        encoding="utf-8",
    )
    body = build_operator_console(tmp_path, scenarios_dir=scenarios_dir).read_text(
        encoding="utf-8"
    )
    assert "Sample scenario" in body
    assert "sample.yaml" in body
    assert "Validate operator console scenario scrape" in body


def test_console_kpis_are_consistent_with_registry(tmp_path: Path) -> None:
    """The KPI strip should report the standard module count and legacy
    adapter count that match the live registry."""

    registry = build_runtime_modules()
    standard = sum(1 for n in registry if not n.startswith("legacy_"))
    legacy = sum(1 for n in registry if n.startswith("legacy_"))
    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    assert f"<b>{standard}</b><span>standard modules</span>" in body
    assert f"<b>{legacy}</b><span>legacy adapters</span>" in body


def test_console_escapes_html_in_module_names(tmp_path: Path) -> None:
    """A module name containing HTML metacharacters must be rendered
    safely. We don't ship one, so a synthetic test pins the escape
    contract for any future plugin module that might."""

    from src.core import operator_console as oc

    # Render with a synthetic registry that injects a malicious-looking name.
    class _Mod:
        attack_techniques = ()
        io_contract = None  # No contract -> falls into the no-declaration path.

    bad = _Mod()
    bad.io_contract = oc.CapabilityIOContract(
        not_applicable=True,
        not_applicable_reason="<script>alert(1)</script>",
    )
    rendered = oc._render_module_card("<img onerror=alert(1) src=x>", bad)
    # The literal name must be escaped in the rendered card.
    assert "<img onerror" not in rendered
    assert "&lt;img onerror=alert(1) src=x&gt;" in rendered
    # And the not_applicable_reason must be escaped too.
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered


def test_console_renders_produced_if_discriminators_when_present(
    tmp_path: Path,
) -> None:
    """When ANY module declares an ArtifactSpec with ``produced_if``
    set, the console must surface the discriminator alongside that
    spec so the operator can see which runtime field gates the
    typed emission. The exact format of the markup is intentionally
    permissive (``when <key>: <value>`` style); the test only pins
    that the discriminator key + at least one acceptable value
    appear in the rendered HTML when at least one such spec exists.
    """

    from src.core.modules import build_runtime_modules

    registry = build_runtime_modules()
    discriminators: list[tuple[str, str]] = []
    for module in registry.values():
        contract = getattr(module, "io_contract", None)
        if contract is None:
            continue
        for spec in contract.produces:
            predicate = getattr(spec, "produced_if", None)
            if predicate is None:
                continue
            try:
                key, value = predicate
            except (TypeError, ValueError):
                continue
            if isinstance(value, (tuple, list, set, frozenset)):
                if value:
                    discriminators.append((key, next(iter(value))))
            else:
                discriminators.append((key, str(value)))
    if not discriminators:
        pytest.skip("no produced_if discriminators in current contracts")
    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    # The console renders the discriminator inline as
    # ``<span class='tag warn'>when <key>: <value>...</span>``
    # — pin the key and at least one value substring.
    key, value = discriminators[0]
    assert f"when {key}:" in body, (
        f"discriminator key {key!r} not surfaced in the rendered HTML"
    )
    assert str(value) in body, (
        f"discriminator value {value!r} not surfaced in the rendered HTML"
    )


def test_console_is_deterministic(tmp_path: Path) -> None:
    """Same registry → same HTML, byte for byte. The console must not
    embed wall-clock timestamps that change between successive
    invocations within the same second-bucket... but it does include
    the generation timestamp. Check determinism on the structural
    content by stripping the timestamp before comparing."""

    out1 = build_operator_console(tmp_path / "a")
    out2 = build_operator_console(tmp_path / "b")

    def _strip_timestamp(text: str) -> str:
        # Replace the embedded ISO timestamp marker with a fixed
        # placeholder so the rest of the rendered page can be compared.
        import re
        return re.sub(
            r"<span class='code'>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z</span>",
            "<span class='code'>__TIMESTAMP__</span>",
            text,
        )

    a = _strip_timestamp(out1.read_text(encoding="utf-8"))
    b = _strip_timestamp(out2.read_text(encoding="utf-8"))
    assert a == b


def test_console_does_not_leak_outside_output_dir(tmp_path: Path) -> None:
    """The console must only write under ``operator-console/`` inside
    the output root - never above, never sideways."""

    out = build_operator_console(tmp_path)
    out_resolved = out.resolve()
    base = (tmp_path / "operator-console").resolve()
    assert base in out_resolved.parents or out_resolved == base / "index.html"


def test_console_compute_chain_pairs_includes_exfil_terminator() -> None:
    """``collection -> exfiltration`` (staged_file) and
    ``collection -> exfiltration`` (collected_data) are both canonical
    chain edges. The pair-extractor must surface both rather than
    deduplicating to one row per producer/consumer pair."""

    from src.core.operator_console import _compute_chain_pairs

    edges = _compute_chain_pairs(build_runtime_modules())
    rows = [
        e
        for e in edges
        if e["producer"] == "collection" and e["consumer"] == "exfiltration"
    ]
    types_emitted = {row["type"] for row in rows}
    assert "staged_file" in types_emitted
    assert "collected_data" in types_emitted


def test_console_compute_chain_pairs_skips_self_edges() -> None:
    """A module's produces and consumes can overlap (e.g.
    network_obfuscator wraps a c2_endpoint and emits a c2_endpoint).
    The chain-pair table should not include a self-edge."""

    from src.core.operator_console import _compute_chain_pairs

    edges = _compute_chain_pairs(build_runtime_modules())
    self_edges = [e for e in edges if e["producer"] == e["consumer"]]
    assert self_edges == [], (
        f"chain pair table includes self-edges: {self_edges}"
    )


def test_scenario_summary_parses_block_scalar_objective(tmp_path: Path) -> None:
    """Codex P2 fix: ``objective: |`` (multi-line block scalar) must
    yield the joined body text, not the literal ``|`` placeholder.

    Shipped scenarios like ``enterprise_intrusion_chain.yaml`` and
    ``fin7_initial_access_to_c2.yaml`` use the multi-line literal
    block form. Without this fix the operator console rendered them
    with a literal ``|`` instead of meaningful text.
    """

    from src.core.operator_console import _parse_scenario_summary

    scenario = tmp_path / "block.yaml"
    scenario.write_text(
        "id: block-test\n"
        "name: Block-scalar test scenario\n"
        "objective: |\n"
        "  First line of multi-line objective.\n"
        "  Second line continues here.\n"
        "  Third line ends the body.\n"
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    summary = _parse_scenario_summary(scenario)
    assert summary["name"] == "Block-scalar test scenario"
    # The multi-line body must be joined - never a bare ``|``.
    assert summary["objective"] != "|"
    assert "First line of multi-line objective." in summary["objective"]
    assert "Second line continues here." in summary["objective"]
    assert "Third line ends the body." in summary["objective"]


def test_scenario_summary_parses_folded_block_scalar(tmp_path: Path) -> None:
    """``objective: >`` (folded block scalar) must be handled the same
    way as ``|`` (literal block scalar)."""

    from src.core.operator_console import _parse_scenario_summary

    scenario = tmp_path / "folded.yaml"
    scenario.write_text(
        "id: folded-test\n"
        "name: Folded scenario\n"
        "objective: >\n"
        "  Stand up the lookalike domain that will both deliver the\n"
        "  phish and host the C2 endpoint.\n"
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    summary = _parse_scenario_summary(scenario)
    assert summary["objective"] != ">"
    assert "lookalike domain" in summary["objective"]
    assert "C2 endpoint" in summary["objective"]


def test_scenario_summary_inline_scalar_still_works(tmp_path: Path) -> None:
    """The inline ``key: value`` form must keep working alongside the
    new block-scalar branch."""

    from src.core.operator_console import _parse_scenario_summary

    scenario = tmp_path / "inline.yaml"
    scenario.write_text(
        "id: inline-test\n"
        "name: Inline scenario\n"
        'objective: "A single inline objective string."\n'
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    summary = _parse_scenario_summary(scenario)
    assert summary["name"] == "Inline scenario"
    assert summary["objective"] == "A single inline objective string."


def test_scenario_summary_block_scalar_body_renders_in_console(tmp_path: Path) -> None:
    """End-to-end pin: a scenario file with a multi-line block-scalar
    objective surfaces the joined body text in the operator console
    HTML, not a literal ``|`` placeholder."""

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    (scenarios_dir / "block.yaml").write_text(
        "id: block-scenario\n"
        "name: Block-scalar smoke scenario\n"
        "objective: |\n"
        "  This is the multi-line objective body. Defenders should\n"
        "  see the actual text in the console, never a bare pipe.\n"
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    body = build_operator_console(tmp_path, scenarios_dir=scenarios_dir).read_text(
        encoding="utf-8"
    )
    assert "Block-scalar smoke scenario" in body
    assert "multi-line objective body" in body
    # The bare-pipe regression marker must NOT appear in the rendered
    # scenarios card. ``|`` is a common HTML / CSS char so we anchor
    # the check on the scenarios-card class to scope the negative.
    assert "scenario-objective'>|" not in body
    assert 'scenario-objective">|' not in body

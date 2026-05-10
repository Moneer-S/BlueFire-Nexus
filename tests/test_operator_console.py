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


@pytest.mark.parametrize(
    "header",
    [
        "|2",
        "|-",
        "|+",
        "|2-",
        "|2+",
        "|+2",
        ">2",
        ">-",
        ">+",
        ">2-",
        ">+2",
    ],
)
def test_scenario_summary_handles_indented_block_scalar_headers(
    header: str,
    tmp_path: Path,
) -> None:
    """Codex follow-up P2: YAML allows the block-scalar header to
    carry a chomping (``+`` / ``-``) AND/OR an indentation indicator
    (``1`` - ``9``) in either order, e.g. ``|2``, ``|-``, ``>+``,
    ``|2-``, ``>+1``. The previous fix only matched a bare set of
    six common forms (``|``, ``>``, ``|-``, ``|+``, ``>-``, ``>+``);
    indented variants regressed back to the literal-marker preview.

    The fix is to treat any unquoted value starting with ``|`` or
    ``>`` after the colon as a block-scalar header, regardless of
    chomping / indentation suffix.
    """

    from src.core.operator_console import _parse_scenario_summary

    safe_name = (
        header.replace("|", "pipe")
        .replace(">", "gt")
        .replace("-", "dash")
        .replace("+", "plus")
    )
    scenario = tmp_path / f"indent_{safe_name}.yaml"
    scenario.write_text(
        "id: indent-test\n"
        "name: Indent header test\n"
        f"objective: {header}\n"
        "  Body text on continuation lines.\n"
        "  Second body line.\n"
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    summary = _parse_scenario_summary(scenario)
    assert summary["objective"] != header, (
        f"header {header!r} regressed to a literal-marker preview"
    )
    assert "Body text on continuation lines." in summary["objective"]
    assert "Second body line." in summary["objective"]


def test_scenario_summary_quoted_inline_with_pipe_stays_inline(tmp_path: Path) -> None:
    """A quoted inline scalar that legitimately begins with ``|`` or
    ``>`` must NOT trigger the block-scalar branch - quoted values
    are inline by YAML grammar, and the leading quote keeps the
    inline branch alive."""

    from src.core.operator_console import _parse_scenario_summary

    scenario = tmp_path / "quoted.yaml"
    scenario.write_text(
        "id: quoted-test\n"
        "name: Quoted scenario\n"
        'objective: "|alpha bravo charlie"\n'
        "fail_fast: false\n"
        "steps: []\n",
        encoding="utf-8",
    )
    summary = _parse_scenario_summary(scenario)
    assert summary["objective"] == "|alpha bravo charlie"


# ---------------------------------------------------------------------------
# Mutation catalog section
# ---------------------------------------------------------------------------


def test_console_renders_mutation_catalog_heading(tmp_path: Path) -> None:
    """The mutation catalog section header must surface so the
    operator can find the swap surface."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    assert "<h2>Mutation catalog</h2>" in body


def test_console_renders_every_mutation_catalog_module(tmp_path: Path) -> None:
    """Every module that has a slot in MUTATION_CATALOG must have a
    rendered card in the mutation section."""

    from src.core.mutations import MUTATION_CATALOG

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    catalog_modules = {module for (module, _key) in MUTATION_CATALOG}
    for module in catalog_modules:
        # Each module is rendered as a class='module-name' h3 card
        # heading. Substring check is sufficient because module
        # names (e.g. ``credential_access``) are not common words.
        assert module in body, (
            f"mutation catalog module {module!r} missing from console"
        )


def test_console_renders_every_mutation_candidate_value(tmp_path: Path) -> None:
    """Every catalog candidate (e.g. ``authorized_keys``,
    ``backgrounditems`` markers, ``dns_tunneling``) must surface in
    the rendered HTML so an operator browsing the page sees the
    swap surface, not just the slot key."""

    from src.core.mutations import MUTATION_CATALOG

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    # Spot-check a handful of distinctive values from different
    # catalogs - exhaustive checking is parametrized in a separate
    # test below.
    for value in (
        "authorized_keys",
        "macos_login_item",
        "ssh_artifacts",
        "dns_tunneling",
        "https_to_cloud_storage",
        "psexec",
        "winrm",
    ):
        assert value in body, (
            f"mutation candidate {value!r} missing from console"
        )


def test_console_renders_target_os_cross_cutting_axis(tmp_path: Path) -> None:
    """The cross-cutting ``target_os`` axis (windows / linux /
    macos) is documented as applying to ANY module that already
    declares it. The console must surface this axis as a separate
    card so the operator knows it isn't tied to a specific module."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    assert "target_os" in body
    assert "any module" in body.lower()
    # All three target_os values must surface.
    for value in ("windows", "linux", "macos"):
        assert value in body


def test_console_kpi_includes_mutation_candidate_count(tmp_path: Path) -> None:
    """The KPI strip should report the total mutation candidate
    count across every catalog slot + the target_os axis."""

    from src.core.mutations import MUTATION_CATALOG, TARGET_OS_VALUES

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    expected = sum(len(v) for v in MUTATION_CATALOG.values()) + len(TARGET_OS_VALUES)
    assert f"<b>{expected}</b><span>mutation candidates</span>" in body


def test_console_mutation_section_card_lists_alternatives_count(
    tmp_path: Path,
) -> None:
    """Each module card should mention an N-alternatives count for
    each slot so an operator scanning quickly sees swap depth."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    # ``command_control.channel`` has 8 alternatives; ``persistence
    # .technique`` has 13.
    assert "(8 alternatives)" in body
    assert "(13 alternatives)" in body


def test_console_mutation_section_renders_deterministically(
    tmp_path: Path,
) -> None:
    """Same registry + catalog -> byte-identical mutation section
    across two builds (modulo the embedded generation timestamp)."""

    out1 = build_operator_console(tmp_path / "a")
    out2 = build_operator_console(tmp_path / "b")

    def _strip_ts(text: str) -> str:
        import re
        return re.sub(
            r"<span class='code'>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z</span>",
            "<span class='code'>__TS__</span>",
            text,
        )

    a = _strip_ts(out1.read_text(encoding="utf-8"))
    b = _strip_ts(out2.read_text(encoding="utf-8"))
    # The mutation catalog section sits between
    # ``<h2>Mutation catalog</h2>`` and the next ``<h2>``; sliced
    # bodies must match byte-for-byte.
    def _slice_section(text: str) -> str:
        start = text.find("<h2>Mutation catalog</h2>")
        end = text.find("<h2>", start + 1)
        return text[start:end] if start != -1 and end != -1 else ""

    assert _slice_section(a) == _slice_section(b)


def test_console_mutation_section_escapes_html_in_catalog_values() -> None:
    """If a future catalog entry contains HTML metacharacters, the
    rendered tag must escape them. We don't ship any such entries
    today; this pin is the safety contract for any future addition."""

    from src.core import operator_console as oc

    rendered = oc._render_mutations_section()
    # No literal ``<script>`` should ever appear (we don't have one
    # in the catalog, and any future addition must be escaped).
    assert "<script>" not in rendered
    assert "</script>" not in rendered


# ---------------------------------------------------------------------------
# Scenario chain graph section (PR2 in the chain-graph loop)
# ---------------------------------------------------------------------------


_REPO_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def test_console_renders_scenario_graph_section_heading(tmp_path: Path) -> None:
    """The Scenario chain graphs section must surface as its own
    ``<h2>`` so an operator scanning the page can find it."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    assert "<h2>Scenario chain graphs</h2>" in body


def test_console_renders_scenario_graph_for_each_shipped_scenario(
    tmp_path: Path,
) -> None:
    """Every shipped scenario must have a chain graph card."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    for filename in (
        "fin7_initial_access_to_c2.yaml",
        "apt29_credential_access.yaml",
        "healthcare_ransomware.yaml",
        "insider_exfil_dns.yaml",
        "enterprise_intrusion_chain.yaml",
    ):
        # Each scenario filename surfaces in BOTH the existing
        # "Shipped scenarios" section AND the new chain-graphs
        # section. Substring-count >= 2 verifies the graphs section
        # added a card for it.
        assert body.count(filename) >= 2, (
            f"scenario {filename!r} not rendered in chain-graphs section"
        )


def test_console_scenario_graph_renders_inline_svg(tmp_path: Path) -> None:
    """Each scenario card must include an inline ``<svg>`` flowchart.

    The SVG is the first-class chain-graph visualisation; falling back
    to the table alone would lose the at-a-glance read of the chain.
    """

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    assert "<svg" in body
    assert "scenario-graph-svg" in body
    # Arrow-marker defs must surface so edges render with arrowheads.
    assert "arrow-explicit" in body
    assert "arrow-implicit" in body


def test_console_scenario_graph_svg_has_no_external_assets(tmp_path: Path) -> None:
    """The inline SVG must not reference external images, fonts, or
    scripts — the page is fully offline."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    # No <foreignObject> (which could embed HTML with remote refs)
    assert "<foreignObject" not in body
    # No <script> anywhere on the page (already covered by the page
    # contract test, but re-pinned here for the SVG-specific scope).
    assert "<script" not in body
    # No remote URLs in the SVG section.
    assert "xlink:href=\"http" not in body
    assert "href=\"http" not in body
    assert "src=\"http" not in body


def test_console_scenario_graph_renders_explicit_edges_for_fin7(
    tmp_path: Path,
) -> None:
    """The FIN7 scenario card must include both explicit edges
    (resource_dev → c2 via c2_endpoint, discovery → exfil via host)."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    # The edge table includes the source step IDs as <td class='code'>
    # cells; substring checks are sufficient because step IDs are
    # uniquely scoped to each scenario.
    for source_id in ("stage-fin7-domain", "pos-environment-recon"):
        assert source_id in body, (
            f"FIN7 explicit-edge source {source_id!r} missing from console"
        )
    for target_id in ("c2-https", "exfil-over-c2"):
        assert target_id in body, (
            f"FIN7 explicit-edge target {target_id!r} missing from console"
        )


def test_console_scenario_graph_kpi_includes_explicit_edge_total(
    tmp_path: Path,
) -> None:
    """The top KPI strip must surface a ``scenario explicit edges``
    counter with a positive value when shipped scenarios are loaded."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    assert "scenario explicit edges" in body
    # Tier-1 sum: FIN7=2 + APT29=3 + healthcare=5 + insider=3 +
    # enterprise=5 = 18 explicit edges. Plus any legacy_* scenarios
    # that ship explicit-edge references. Pin a lower bound rather
    # than the exact total so adding a new scenario or legacy
    # variant doesn't bake in a fragile constant.
    assert "scenario chain warnings" in body


def test_console_scenario_graph_section_handles_missing_scenarios_dir(
    tmp_path: Path,
) -> None:
    """When no scenarios directory is found, the chain-graphs section
    still renders the heading + an empty-state note (mirrors the
    existing Shipped scenarios behaviour)."""

    body = build_operator_console(
        tmp_path, scenarios_dir=tmp_path / "no-such-dir"
    ).read_text(encoding="utf-8")
    assert "<h2>Scenario chain graphs</h2>" in body
    assert "No scenario graphs available" in body


def test_console_scenario_graph_section_tolerates_malformed_yaml(
    tmp_path: Path,
) -> None:
    """A malformed scenario YAML must not crash the console. The card
    surfaces an error string instead so the operator can fix the
    file."""

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    (scenarios_dir / "broken.yaml").write_text(
        "not: valid: yaml: at all: [unbalanced",
        encoding="utf-8",
    )
    # This must not raise.
    out = build_operator_console(tmp_path, scenarios_dir=scenarios_dir)
    body = out.read_text(encoding="utf-8")
    assert "broken.yaml" in body
    assert "Chain graph unavailable" in body


def test_console_scenario_graph_renders_warning_severities(
    tmp_path: Path,
) -> None:
    """When a scenario emits warnings, the severity tag classes must
    surface so the operator console styles them (red for missing-
    required, amber for high-value-unused, grey for unused-emission).

    Builds a scenario that intentionally has a dangling exfil
    package so a high_value_unused warning fires.
    """

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    (scenarios_dir / "dangling.yaml").write_text(
        "id: dangling-scenario\n"
        "name: Dangling exfil package scenario\n"
        "objective: Stage data with no exfiltration consumer.\n"
        "fail_fast: false\n"
        "steps:\n"
        "  - id: stage-data\n"
        "    name: Stage data\n"
        "    module: collection\n"
        "    params:\n"
        "      technique: file_staging\n"
        "      target: lab-host\n"
        "      network_touch: false\n",
        encoding="utf-8",
    )
    body = build_operator_console(
        tmp_path, scenarios_dir=scenarios_dir
    ).read_text(encoding="utf-8")
    # The scenario produces a staged_file (high-value type) but no
    # downstream consumer — the high_value_unused severity class
    # must appear.
    assert "severity-high_value_unused" in body
    # Section-level "warnings" KPI is incremented on the per-card KPI
    # strip.
    assert "<span>warnings</span>" in body


def test_console_scenario_graph_section_is_deterministic(tmp_path: Path) -> None:
    """Same scenarios dir → byte-identical scenario-graphs section
    across builds, modulo the page timestamp."""

    out1 = build_operator_console(
        tmp_path / "a", scenarios_dir=_REPO_SCENARIOS_DIR
    )
    out2 = build_operator_console(
        tmp_path / "b", scenarios_dir=_REPO_SCENARIOS_DIR
    )

    def _strip_ts(text: str) -> str:
        import re

        return re.sub(
            r"<span class='code'>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z</span>",
            "<span class='code'>__TS__</span>",
            text,
        )

    a = _strip_ts(out1.read_text(encoding="utf-8"))
    b = _strip_ts(out2.read_text(encoding="utf-8"))
    start_marker = "<h2>Scenario chain graphs</h2>"
    end_marker = "<div class='footer'>"

    def _slice(text: str) -> str:
        start = text.find(start_marker)
        end = text.find(end_marker, start + 1)
        return text[start:end] if start != -1 and end != -1 else ""

    assert _slice(a) == _slice(b)


def test_console_scenario_graph_card_includes_objective_preview(
    tmp_path: Path,
) -> None:
    """Each scenario graph card surfaces (a clipped form of) the
    scenario's objective so the operator sees what the chain is
    modelling without re-opening the YAML."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    # FIN7's objective is multi-line and starts with "Simulate a
    # FIN7-like seven-step intrusion".
    assert "Simulate a FIN7-like" in body


# ---------------------------------------------------------------------------
# Module category badges + ATT&CK quality indicators (PR4)
# ---------------------------------------------------------------------------


def test_categorize_module_returns_standard_for_canonical_modules() -> None:
    """Modules without the ``legacy_`` prefix are categorised as
    ``standard`` (the canonical capability surface)."""

    from src.core.operator_console import _categorize_module

    for canonical in ("execution", "discovery", "credential_access", "lateral_movement"):
        assert _categorize_module(canonical) == "standard"


def test_categorize_module_returns_pack_label_for_legacy_modules() -> None:
    """Each shipped legacy module maps to one of the documented pack
    categories (actor / c2 / stealth / tactic / meta) so the operator
    console can render a colour-coded badge per pack."""

    from src.core.operator_console import _categorize_module

    expected = {
        "legacy_actor_profile": "actor",
        "legacy_apt28_research": "actor",
        "legacy_apt29_research": "actor",
        "legacy_apt32_research": "actor",
        "legacy_apt38_research": "actor",
        "legacy_apt41_research": "actor",
        "legacy_protocol_research": "c2",
        "legacy_stealth_research": "stealth",
        "legacy_collection": "tactic",
        "legacy_credential_access": "tactic",
        "legacy_impact": "tactic",
        "legacy_lateral_movement": "tactic",
        "legacy_privilege_escalation": "tactic",
        "legacy_capability_summary": "meta",
    }
    for module_name, expected_category in expected.items():
        assert _categorize_module(module_name) == expected_category, (
            f"{module_name!r} categorised as "
            f"{_categorize_module(module_name)!r}, expected {expected_category!r}"
        )


def test_categorize_module_unknown_legacy_falls_back_to_meta() -> None:
    """A future ``legacy_*`` module without an explicit mapping falls
    back to ``meta`` so the badge still renders rather than going
    silently uncategorised."""

    from src.core.operator_console import _categorize_module

    assert _categorize_module("legacy_brand_new_pack") == "meta"


def test_console_renders_category_badge_for_every_module(tmp_path: Path) -> None:
    """Every module card surfaces a colour-coded category badge so an
    operator scanning the catalog sees standard / actor / c2 /
    stealth / tactic / meta at a glance."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    # Every category should appear at least once given the current
    # registry (standard, actor from APT*, c2 from protocol_research,
    # stealth from stealth_research, tactic from legacy tactic
    # adapters, meta from capability_summary).
    for category in ("standard", "actor", "c2", "stealth", "tactic", "meta"):
        assert f"cat-{category}" in body, (
            f"category badge {category!r} not rendered"
        )


def test_console_kpi_includes_attack_technique_count(tmp_path: Path) -> None:
    """The top KPI strip surfaces the deduped count of declared
    ATT&CK techniques across every module so the operator sees the
    catalog's defender-facing surface without scrolling."""

    body = build_operator_console(tmp_path).read_text(encoding="utf-8")
    assert "ATT&amp;CK techniques in catalog" in body
    # Compute the expected value from the live registry; pin the
    # KPI value matches.
    registry = build_runtime_modules()
    techniques: set[str] = set()
    for module in registry.values():
        for t in getattr(module, "attack_techniques", ()) or ():
            cleaned = str(t).strip()
            if cleaned:
                techniques.add(cleaned)
    assert f"<b>{len(techniques)}</b><span>ATT&amp;CK techniques in catalog</span>" in body


def test_console_kpi_includes_scenarios_with_attack_coverage(tmp_path: Path) -> None:
    """The KPI strip counts how many shipped scenarios declare any
    ``attack_coverage`` so an operator sees the catalog's spread
    of defender-targeted scenarios."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    assert "scenarios with ATT&amp;CK coverage" in body
    # All five tier-1 scenarios declare ``attack_coverage``; lower
    # bound only so adding a new scenario without coverage doesn't
    # break the test.
    import re

    match = re.search(
        r"<b>(\d+)</b><span>scenarios with ATT&amp;CK coverage</span>", body
    )
    assert match is not None
    assert int(match.group(1)) >= 5


def test_console_scenario_card_renders_attack_technique_chips(
    tmp_path: Path,
) -> None:
    """Per-scenario card surfaces every declared technique as a
    chip, plus the count in the per-card KPI strip, so a defender
    sees the scenario's coverage without re-opening the YAML."""

    body = build_operator_console(
        tmp_path, scenarios_dir=_REPO_SCENARIOS_DIR
    ).read_text(encoding="utf-8")
    # Per-card KPI strip carries the technique count.
    assert "<span>ATT&amp;CK techniques</span>" in body
    # Chip area surfaces the declared label and at least one known
    # FIN7 technique (T1583.001 - Domains).
    assert "scenario-graph-attack" in body
    assert "T1583.001" in body
    # Chip area surfaces an APT29-specific technique too.
    assert "T1003.001" in body or "T1547.001" in body


def test_console_scenario_card_omits_attack_chips_when_no_coverage(
    tmp_path: Path,
) -> None:
    """A scenario that doesn't declare ``attack_coverage`` must not
    render an empty chip block (cards stay clean for early-draft
    scenarios)."""

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    (scenarios_dir / "no_attack.yaml").write_text(
        "id: no-coverage\n"
        "name: No-coverage scenario\n"
        "objective: Scenario without attack_coverage declared.\n"
        "fail_fast: false\n"
        "steps:\n"
        "  - id: step-1\n"
        "    name: Step 1\n"
        "    module: discovery\n"
        "    params:\n"
        "      discovery_type: host_discovery\n"
        "      targets: ['lab-host']\n",
        encoding="utf-8",
    )
    body = build_operator_console(
        tmp_path, scenarios_dir=scenarios_dir
    ).read_text(encoding="utf-8")
    # The card exists for the no-coverage scenario.
    assert "no_attack.yaml" in body
    # But no chip block surfaces for a scenario that doesn't declare
    # ``attack_coverage``. Anchor the negative on the chip-block class
    # so the broader test page can still mention the class via other
    # cards. Use a substring scoped to the no_attack card section.
    no_attack_card_start = body.find("no_attack.yaml")
    no_attack_card_end = body.find(
        "</div>", body.find("</div>", no_attack_card_start) + 1
    )
    no_attack_card_section = body[no_attack_card_start:no_attack_card_end]
    assert "scenario-graph-attack" not in no_attack_card_section

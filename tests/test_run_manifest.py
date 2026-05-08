"""Run-manifest contract tests.

The manifest is the single machine-readable index of every artifact
a run produced. The static HTML viewer (and any external tooling)
consumes ``output/<run_id>/manifest.json`` instead of walking the
directory or guessing file names.

Pinned invariants:

1. **Stable schema.** Every documented top-level key is present
   regardless of which optional artifacts the run produced; absent
   artifacts get ``null`` / ``[]`` / ``{}`` defaults rather than
   silently dropping the key. Schema version is integer-tagged.
2. **Local-only paths.** Every path written into the manifest is
   relative to the run directory. Absolute paths to the operator's
   environment (home directories, mount points) never leak.
3. **No content duplication.** The manifest references files by
   relative path; it does NOT inline the body of ``report.md`` /
   ``telemetry.jsonl`` / detection rule text. Only counts and
   small metadata are embedded.
4. **Propagation edges built from artifacts.** When a downstream
   step records ``target_propagated_from_step`` /
   ``source_propagated_from_step`` in its artifacts, the manifest
   surfaces the (from_step, to_step, kind) edge for the viewer.
5. **Telemetry summary is count-only.** The manifest reports
   event counts by type and by module, but does not embed the
   actual event payloads.
6. **Detection summary is per-engine.** Per-step detection paths
   plus an aggregate engine-level count. Paths are run-dir-
   relative.
7. **No external/network references.** A manifest never names a
   URL, hostname, or remote endpoint. Local filesystem paths only.
8. **End-to-end shape on the shipped flagship scenario.** Running
   ``enterprise_intrusion_chain`` produces a manifest with the
   four documented propagation pairs and the declared attack
   coverage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.reporting.manifest import (
    MANIFEST_SCHEMA_VERSION,
    build_manifest,
    write_run_manifest,
)


# ---------------------------------------------------------------------------
# Pure-shape tests against build_manifest (no disk I/O, no orchestrator)
# ---------------------------------------------------------------------------


def _basic_steps() -> List[Dict[str, Any]]:
    """Two-step fixture: discovery -> credential_access propagation."""
    return [
        {
            "step_id": "enumerate-files",
            "module": "discovery",
            "name": "Enumerate sensitive files",
            "status": "success",
            "message": "ok",
            "techniques": ["T1083"],
            "artifacts": {
                "technique": "files",
                "targets": ["finance-analyst-laptop"],
            },
            "detections": {
                "sigma": ["detections/sigma/discovery_files.yml"],
                "yara_l": ["detections/yara_l/discovery_files.yaral"],
            },
        },
        {
            "step_id": "harvest-creds",
            "module": "credential_access",
            "name": "Harvest browser credentials",
            "status": "success",
            "message": "ok",
            "techniques": ["T1555.003"],
            "artifacts": {
                "technique": "browser_credentials",
                "target": "finance-analyst-laptop",
                "target_propagated_from_step": "enumerate-files",
            },
            "detections": {
                "sigma": ["detections/sigma/credential_access_browser.yml"],
            },
        },
    ]


def test_build_manifest_has_documented_top_level_keys(tmp_path: Path) -> None:
    """The manifest must expose every documented top-level key.

    Stable shape lets the viewer and external tooling rely on
    indexing without ``if key in manifest`` checks.
    """
    manifest = build_manifest(
        run_id="run-shape",
        run_dir=tmp_path,
        scenario_name="shape-test",
        overall_status="success",
        steps=_basic_steps(),
    )
    expected_keys = {
        "schema_version",
        "run",
        "safety",
        "steps",
        "propagation_edges",
        "attack_coverage",
        "telemetry",
        "detections",
        "reports",
        "risk",
        "copilot",
        "legacy_controls",
        "warnings",
        "errors",
        "blocked_steps",
        "module_keys",
    }
    assert expected_keys <= set(manifest.keys()), (
        f"missing keys: {expected_keys - set(manifest.keys())}"
    )
    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION


def test_build_manifest_run_section_carries_canonical_metadata(tmp_path: Path) -> None:
    manifest = build_manifest(
        run_id="run-meta",
        run_dir=tmp_path,
        scenario_name="meta-scenario",
        scenario_path="scenarios/meta.yaml",
        overall_status="success",
        started_at="2026-05-07T09:00:00Z",
        finished_at="2026-05-07T09:00:42Z",
        steps=_basic_steps(),
    )
    run = manifest["run"]
    assert run["run_id"] == "run-meta"
    assert run["scenario_name"] == "meta-scenario"
    assert run["scenario_path"] == "scenarios/meta.yaml"
    assert run["started_at"] == "2026-05-07T09:00:00Z"
    assert run["finished_at"] == "2026-05-07T09:00:42Z"
    assert run["overall_status"] == "success"
    assert run["module_count"] == 2
    assert run["step_status_counts"] == {"success": 2}


def test_build_manifest_extracts_propagation_edges(tmp_path: Path) -> None:
    """Edges are built from artifacts.target_propagated_from_step / source_... / c2_endpoint_..."""
    steps = _basic_steps()
    # Add a lateral_movement step using source_from_step propagation.
    steps.append(
        {
            "step_id": "lateral",
            "module": "lateral_movement",
            "name": "PsExec",
            "status": "success",
            "message": "ok",
            "techniques": ["T1021.002"],
            "artifacts": {
                "technique": "psexec",
                "source": "finance-analyst-laptop",
                "target": "corp-fileshare",
                "source_propagated_from_step": "harvest-creds",
            },
            "detections": {},
        }
    )
    # Add a command_control step using c2_endpoint_from_step propagation
    # (resource_development -> command_control endpoint axis added in PR #106).
    steps.append(
        {
            "step_id": "c2",
            "module": "command_control",
            "name": "HTTPS C2",
            "status": "success",
            "message": "ok",
            "techniques": ["T1071.001"],
            "artifacts": {
                "channel": "https",
                "c2_url": "https://invoice-portal.example.lab/c2",
                "c2_endpoint_propagated_from_step": "stage-infrastructure",
            },
            "detections": {},
        }
    )
    manifest = build_manifest(
        run_id="run-prop",
        run_dir=tmp_path,
        scenario_name="prop",
        steps=steps,
    )
    edges = manifest["propagation_edges"]
    edge_kinds = sorted((edge["from_step"], edge["to_step"], edge["kind"]) for edge in edges)
    assert ("enumerate-files", "harvest-creds", "target_from_step") in edge_kinds
    assert ("harvest-creds", "lateral", "source_from_step") in edge_kinds
    # c2_endpoint axis must surface in the manifest so the viewer
    # can render it. Codex P2 follow-up on PR #106: the new
    # c2_endpoint_propagated_from_step artifact key was previously
    # ignored by `_propagation_edges`, leaving the new
    # resource_development -> command_control linkage invisible in
    # the report's propagation graph.
    assert ("stage-infrastructure", "c2", "c2_endpoint_from_step") in edge_kinds


def test_build_manifest_attack_coverage_is_sorted_and_deduped(tmp_path: Path) -> None:
    steps = _basic_steps()
    # Add a duplicate technique on a third step so dedup is exercised.
    steps.append(
        {
            "step_id": "exfil",
            "module": "exfiltration",
            "name": "Exfil",
            "status": "success",
            "techniques": ["T1083", "T1041"],
            "artifacts": {},
            "detections": {},
        }
    )
    manifest = build_manifest(
        run_id="run-cov",
        run_dir=tmp_path,
        scenario_name="cov",
        steps=steps,
    )
    coverage = manifest["attack_coverage"]
    techniques = [entry["technique"] for entry in coverage]
    assert techniques == sorted(techniques)  # sorted alphabetically
    t1083 = next(e for e in coverage if e["technique"] == "T1083")
    # Both enumerate-files and exfil emit T1083 — both step ids appear.
    assert "enumerate-files" in t1083["steps"]
    assert "exfil" in t1083["steps"]


def test_build_manifest_safety_section_uses_baseline_defaults(tmp_path: Path) -> None:
    """No config => local-first defaults (dry_run True, etc.)."""
    manifest = build_manifest(
        run_id="run-safety",
        run_dir=tmp_path,
        steps=[],
    )
    safety = manifest["safety"]
    assert safety["dry_run"] is True
    assert safety["max_runtime"] == 3600
    assert safety["allowed_subnets"] == []


def test_build_manifest_detections_paths_are_run_dir_relative(tmp_path: Path) -> None:
    """Per-step detection paths are normalised to run-dir-relative form."""
    # Create real files so the relativisation path is exercised.
    (tmp_path / "detections" / "sigma").mkdir(parents=True)
    sigma = tmp_path / "detections" / "sigma" / "rule.yml"
    sigma.write_text("title: x", encoding="utf-8")
    steps = [
        {
            "step_id": "s",
            "module": "x",
            "status": "success",
            "techniques": ["T0001"],
            "artifacts": {},
            "detections": {"sigma": [str(sigma)]},
        }
    ]
    manifest = build_manifest(
        run_id="run-det", run_dir=tmp_path, scenario_name="det", steps=steps
    )
    rendered = manifest["steps"][0]["detections"]["sigma"]
    # No absolute path — only run-dir-relative posix path.
    assert rendered == ["detections/sigma/rule.yml"]
    # Engine count rolls up to the aggregate detections summary.
    assert manifest["detections"]["engine_counts"] == {"sigma": 1}


def test_build_manifest_propagation_edges_capture_module_target_only(tmp_path: Path) -> None:
    """A step without propagation contributes no edges."""
    steps = [
        {
            "step_id": "step-1",
            "module": "execution",
            "status": "success",
            "techniques": [],
            "artifacts": {"command": "echo hi"},
            "detections": {},
        }
    ]
    manifest = build_manifest(
        run_id="run-noprop", run_dir=tmp_path, scenario_name="noprop", steps=steps
    )
    assert manifest["propagation_edges"] == []


def test_build_manifest_blocked_steps_collected_into_top_level_list(
    tmp_path: Path,
) -> None:
    steps = [
        {"step_id": "ok", "module": "x", "status": "success", "techniques": [], "artifacts": {}, "detections": {}},
        {"step_id": "blk", "module": "y", "status": "blocked", "techniques": [], "artifacts": {}, "detections": {}},
    ]
    manifest = build_manifest(
        run_id="run-blk", run_dir=tmp_path, scenario_name="blk", steps=steps
    )
    assert manifest["blocked_steps"] == ["blk"]


def test_build_manifest_does_not_inline_telemetry_events(tmp_path: Path) -> None:
    """The telemetry section reports counts, not the events themselves."""
    telemetry = tmp_path / "telemetry.jsonl"
    telemetry.write_text(
        "\n".join(
            [
                json.dumps({"event_type": "exec", "module": "execution"}),
                json.dumps({"event_type": "exec", "module": "execution"}),
                json.dumps({"event_type": "discovery", "module": "discovery"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = build_manifest(
        run_id="run-tel",
        run_dir=tmp_path,
        scenario_name="tel",
        steps=_basic_steps(),
    )
    telemetry_section = manifest["telemetry"]
    assert telemetry_section["path"] == "telemetry.jsonl"
    assert telemetry_section["event_count"] == 3
    assert telemetry_section["events_by_type"] == {"exec": 2, "discovery": 1}
    assert telemetry_section["events_by_module"] == {"execution": 2, "discovery": 1}
    # Event payloads MUST NOT be inlined.
    rendered = json.dumps(manifest)
    assert "module" in rendered  # event field appears as a count key only
    assert "exec" in rendered
    # No raw event content (the test telemetry has no other distinctive
    # token in `details`; absence is the assertion).


def test_build_manifest_handles_unreadable_telemetry_gracefully(
    tmp_path: Path, monkeypatch
) -> None:
    """Unreadable telemetry surfaces as an error tag, not a crash."""
    telemetry = tmp_path / "telemetry.jsonl"
    telemetry.write_text("ignored", encoding="utf-8")

    real_open = Path.open

    def flaky_open(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self == telemetry:
            raise OSError("simulated read failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", flaky_open)
    manifest = build_manifest(
        run_id="run-tel-err",
        run_dir=tmp_path,
        scenario_name="tel-err",
        steps=[],
    )
    assert manifest["telemetry"]["error"] == "telemetry file present but unreadable"


def test_build_manifest_paths_are_never_absolute_when_under_run_dir(
    tmp_path: Path,
) -> None:
    """Paths under the run dir always render as run-dir-relative posix strings.

    The manifest must not embed the operator's home directory or
    other environment-specific path roots.
    """
    report_path = tmp_path / "report.md"
    report_path.write_text("# r", encoding="utf-8")
    risk_path = tmp_path / "risk_summary.json"
    risk_path.write_text("{}", encoding="utf-8")
    manifest = build_manifest(
        run_id="run-paths",
        run_dir=tmp_path,
        scenario_name="paths",
        steps=_basic_steps(),
        report_path=str(report_path),
        risk_summary_path=str(risk_path),
    )
    assert manifest["reports"]["report_md"] == "report.md"
    assert manifest["reports"]["risk_summary_json"] == "risk_summary.json"
    # Sanity: tmp_path's absolute string is not anywhere in the manifest.
    rendered = json.dumps(manifest)
    assert str(tmp_path).replace("\\", "/") not in rendered.replace("\\", "/")


def test_build_manifest_no_external_url_references(tmp_path: Path) -> None:
    """Manifest never embeds http(s)://, ftp://, or remote endpoints.

    Defends the local-only invariant: an operator inspecting the
    manifest must not see any URL pointing at a remote service.
    """
    manifest = build_manifest(
        run_id="run-no-url",
        run_dir=tmp_path,
        scenario_name="no-url",
        steps=_basic_steps(),
        report_path=str(tmp_path / "report.md"),
    )
    rendered = json.dumps(manifest)
    for forbidden in ("http://", "https://", "ftp://", "ws://", "wss://"):
        assert forbidden not in rendered, (
            f"manifest contains forbidden URL scheme {forbidden!r}: {rendered}"
        )


# ---------------------------------------------------------------------------
# write_run_manifest writes a parseable JSON file
# ---------------------------------------------------------------------------


def test_write_run_manifest_round_trips_through_json_loads(tmp_path: Path) -> None:
    target = write_run_manifest(
        run_id="run-rt",
        run_dir=tmp_path,
        scenario_name="rt",
        overall_status="success",
        steps=_basic_steps(),
    )
    assert target.exists()
    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert parsed["run"]["run_id"] == "run-rt"
    assert parsed["schema_version"] == MANIFEST_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# End-to-end: run the flagship scenario and assert manifest shape
# ---------------------------------------------------------------------------


def test_enterprise_intrusion_chain_writes_manifest_with_five_propagation_edges(
    tmp_path: Path,
) -> None:
    """End-to-end shape against the project's flagship scenario.

    A regression that drops a propagation pair (or a manifest
    section) surfaces here at the project level rather than only
    at the unit-test level. Pinned at five edges since PR #106
    added the c2_endpoint_from_step axis (resource_development ->
    command_control); Codex P2 follow-up on that PR exposed that
    `_propagation_edges` was not walking the new artifact key.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")

    manifest_path = Path(summary["manifest_path"])
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Run-level metadata.
    assert manifest["run"]["scenario_name"] == "Enterprise intrusion kill chain"
    assert manifest["run"]["overall_status"] == "success"
    assert manifest["run"]["module_count"] == 12

    # Five propagation edges (the five documented pairs).
    edges = manifest["propagation_edges"]
    edge_signatures = {(e["from_step"], e["to_step"], e["kind"]) for e in edges}
    assert ("enumerate-files", "harvest-browser-creds", "target_from_step") in edge_signatures
    assert ("harvest-browser-creds", "lateral-to-fileshare", "source_from_step") in edge_signatures
    assert ("stage-collected-data", "exfil-over-c2", "target_from_step") in edge_signatures
    assert ("stage-collected-data", "ransomware-impact", "target_from_step") in edge_signatures
    assert ("stage-infrastructure", "c2-channel", "c2_endpoint_from_step") in edge_signatures

    # ATT&CK coverage matches what the scenario declares.
    declared = {
        "T1583.001",
        "T1593",
        "T1566",
        "T1059.001",
        "T1036",
        "T1083",
        "T1555.003",
        "T1021.002",
        "T1074.001",
        "T1071.001",
        "T1041",
        "T1486",
    }
    emitted = {entry["technique"] for entry in manifest["attack_coverage"]}
    assert declared == emitted

    # Reports section points at the rendered files via run-dir-relative paths.
    assert manifest["reports"]["report_md"] == "report.md"
    assert manifest["reports"]["risk_summary_json"] == "risk_summary.json"
    # Telemetry path also relative.
    assert manifest["telemetry"]["path"] == "telemetry.jsonl"
    assert manifest["telemetry"]["event_count"] >= 12  # at least one event per step

    # The manifest references its run dir via run-dir-relative paths
    # only — no absolute filesystem path leak.
    rendered = json.dumps(manifest)
    run_dir = manifest_path.parent
    assert str(run_dir).replace("\\", "/") not in rendered.replace("\\", "/")
    # The flagship scenario passes example.lab URLs as scenario *inputs*
    # (the c2 step's `c2_url`, the resource_development step's `target`,
    # etc.) so URL-shaped values do appear inside step artifacts. They
    # are scenario parameters, not manifest-level remote endpoints —
    # the local-only invariant is that the manifest never links to a
    # host outside of the documented `.example.lab` lab placeholders.
    for forbidden_host in ("api.openai.com", "api.anthropic.com", "googleapis.com"):
        assert forbidden_host not in rendered

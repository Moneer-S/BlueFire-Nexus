"""Telemetry events carry step_id + run_id so events are self-describing.

Pre-#147 the on-disk ``telemetry.jsonl`` recorded ``module``,
``event_type``, ``details``, ``severity``, and ``timestamp`` — but no
``step_id`` or ``run_id``. A defender concatenating multiple
``telemetry.jsonl`` streams (e.g. for cross-run analysis, or scenarios
with multiple steps that re-use the same module) had no way to tell
which step / run produced each event. The events were anchored to
their file location only.

PR #147:
- Adds top-level ``step_id`` and ``run_id`` fields to ``TelemetryEvent``
  (schema-additive, empty-string default for backwards compat).
- ``TelemetryBus.emit`` / ``emit_many`` accept ``step_id`` /
  ``run_id`` kwargs and annotate every passed event before dispatch.
- The orchestrator passes ``context.run_id`` (always) and
  ``step.step_id`` (scenario path) so every emitted event carries the
  correct identifiers without changing module-side code.

Pinned invariants:

1. ``TelemetryEvent`` dataclass has top-level ``step_id`` and
   ``run_id`` fields with empty-string defaults.
2. ``TelemetryBus.emit_many`` annotates each event with supplied
   ``step_id`` / ``run_id``.
3. Pre-set ``step_id`` / ``run_id`` on the original event are NOT
   overwritten — out-of-tree modules that set their own context win.
4. Single-module ``execute_operation`` path passes ``run_id`` only;
   ``step_id`` stays empty (no scenario step).
5. Scenario-step path passes both — every event in the showcase
   carries its scenario step_id and the run_id end-to-end.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path

from src.core.models import TelemetryEvent
from src.core.telemetry.bus import TelemetryBus


# ---------------------------------------------------------------------------
# 1. Dataclass schema
# ---------------------------------------------------------------------------


def test_telemetry_event_dataclass_has_step_id_and_run_id_with_empty_defaults() -> None:
    """``TelemetryEvent`` carries top-level ``step_id`` / ``run_id`` (empty default)."""
    event = TelemetryEvent(event_type="x", module="m")
    assert event.step_id == ""
    assert event.run_id == ""


def test_telemetry_event_dataclass_accepts_step_id_and_run_id() -> None:
    """Both fields land in ``asdict`` output for downstream sinks."""
    event = TelemetryEvent(
        event_type="x",
        module="m",
        step_id="alpha",
        run_id="run-test-1",
    )
    payload = asdict(event)
    assert payload["step_id"] == "alpha"
    assert payload["run_id"] == "run-test-1"


# ---------------------------------------------------------------------------
# 2. Bus annotates events with supplied step_id / run_id
# ---------------------------------------------------------------------------


def _bus_with_jsonl_sink(tmp_path: Path) -> TelemetryBus:
    """Build a bus that writes events to ``telemetry.jsonl`` under tmp_path."""
    config = {
        "telemetry": {
            "sinks": [{"type": "jsonl", "path": str(tmp_path / "telemetry.jsonl")}]
        }
    }
    return TelemetryBus(config, tmp_path)


def _emitted_events(tmp_path: Path) -> list:
    return [
        json.loads(line)
        for line in (tmp_path / "telemetry.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_emit_many_annotates_each_event_with_supplied_identifiers(tmp_path: Path) -> None:
    bus = _bus_with_jsonl_sink(tmp_path)
    events = [
        TelemetryEvent(event_type="phase", module="m1"),
        TelemetryEvent(event_type="phase", module="m2"),
    ]
    bus.emit_many(events, step_id="alpha", run_id="run-bus-1")
    written = _emitted_events(tmp_path)
    assert len(written) == 2
    for ev in written:
        assert ev["step_id"] == "alpha"
        assert ev["run_id"] == "run-bus-1"


def test_emit_many_preserves_pre_set_step_id_and_run_id(tmp_path: Path) -> None:
    """Out-of-tree modules that set identifiers themselves keep them."""
    bus = _bus_with_jsonl_sink(tmp_path)
    events = [
        TelemetryEvent(
            event_type="x",
            module="m",
            step_id="from-module-itself",
            run_id="run-from-module",
        )
    ]
    # Bus tries to override; original wins.
    bus.emit_many(events, step_id="bus-step", run_id="bus-run")
    written = _emitted_events(tmp_path)
    assert written[0]["step_id"] == "from-module-itself"
    assert written[0]["run_id"] == "run-from-module"


def test_emit_many_fills_only_missing_field(tmp_path: Path) -> None:
    """Per-field precedence: pre-set fields win, empty fields get filled."""
    bus = _bus_with_jsonl_sink(tmp_path)
    events = [
        TelemetryEvent(
            event_type="x",
            module="m",
            step_id="explicit",  # set
            # run_id left empty
        )
    ]
    bus.emit_many(events, step_id="ignored", run_id="run-applied")
    written = _emitted_events(tmp_path)
    assert written[0]["step_id"] == "explicit"
    assert written[0]["run_id"] == "run-applied"


def test_emit_many_without_step_or_run_id_leaves_fields_empty(tmp_path: Path) -> None:
    """No annotation supplied + module didn't set them => empty strings."""
    bus = _bus_with_jsonl_sink(tmp_path)
    bus.emit_many([TelemetryEvent(event_type="x", module="m")])
    written = _emitted_events(tmp_path)
    assert written[0]["step_id"] == ""
    assert written[0]["run_id"] == ""


def test_emit_single_event_also_supports_annotation(tmp_path: Path) -> None:
    bus = _bus_with_jsonl_sink(tmp_path)
    bus.emit(
        TelemetryEvent(event_type="x", module="m"),
        step_id="alpha",
        run_id="run-emit-1",
    )
    written = _emitted_events(tmp_path)
    assert written[0]["step_id"] == "alpha"
    assert written[0]["run_id"] == "run-emit-1"


# ---------------------------------------------------------------------------
# 3. End-to-end via the showcase scenario
# ---------------------------------------------------------------------------


def test_showcase_scenario_telemetry_carries_per_step_and_run_id(
    tmp_path: Path,
) -> None:
    """Real run against the showcase: every event carries the right identifiers.

    Pin the headline regression a defender would catch on triage:
    pre-#147 ``telemetry.jsonl`` was anchor-by-file-location only.
    After the change, each row self-describes its scenario step + run.
    """
    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "src.run_scenario",
            "--scenario-file",
            "scenarios/enterprise_intrusion_chain.yaml",
            "--output-json",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    run_id = out["run_id"]
    run_dir = tmp_path / run_id
    telemetry_path = run_dir / "telemetry.jsonl"
    lines = [
        json.loads(line)
        for line in telemetry_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 12
    # Every event carries the run_id.
    assert all(ev["run_id"] == run_id for ev in lines), [
        ev.get("run_id") for ev in lines
    ]
    # Every event carries a non-empty step_id.
    assert all(ev["step_id"] for ev in lines), [ev.get("step_id") for ev in lines]
    # The set of step_ids matches the scenario's step ids exactly.
    seen_step_ids = sorted({ev["step_id"] for ev in lines})
    expected = sorted(
        [
            "stage-infrastructure",
            "target-recon",
            "phish-delivery",
            "loader-execution",
            "masquerade",
            "enumerate-files",
            "harvest-browser-creds",
            "lateral-to-fileshare",
            "stage-collected-data",
            "c2-channel",
            "exfil-over-c2",
            "ransomware-impact",
        ]
    )
    assert seen_step_ids == expected

from pathlib import Path

from src.core.models import ModuleResult
from src.core.reporting import build_risk_summary, write_markdown_report, write_risk_summary
from src.core.risk import score_module_result


def test_markdown_report_includes_runtime_warnings_and_counts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    result = ModuleResult(
        status="success",
        module="legacy_protocol_research",
        message="Protocol prepared in emulate mode.",
        techniques=["T1071.004"],
        artifacts={
            "legacy": {
                "pack": "c2_pack",
                "capability": "dns_tunneling",
                "mode": "emulate",
                "payload": {
                    "runtime_warning": "network path failed in emulate mode",
                },
            }
        },
        detection_hints={},
        telemetry=[],
    )
    detections = {
        "legacy_protocol_research": {
            "sigma": "output/detections/sigma/legacy_protocol_research.yml",
            "spl": "output/detections/spl/legacy_protocol_research.spl",
        }
    }

    report_path = write_markdown_report(
        run_dir,
        "Polish Scenario",
        {"legacy_protocol_research": result},
        detections,
    )
    content = report_path.read_text(encoding="utf-8")
    assert "ATT&CK techniques covered: T1071.004" in content
    assert "Detection artifacts generated: 2" in content
    assert "Runtime warning" in content
    assert "network path failed in emulate mode" in content
    assert "Risk summary:" in content
    assert "Average module risk score:" in content
    assert "Risk score: `" in content


def test_module_risk_scoring_for_legacy_warning() -> None:
    result = ModuleResult(
        status="success",
        module="legacy_stealth_research",
        message="Stealth prepared in emulate mode.",
        techniques=["T1562"],
        artifacts={
            "legacy": {
                "pack": "stealth_pack",
                "capability": "anti_detection_legacy",
                "mode": "emulate",
                "payload": {"runtime_warning": "evasion call failed"},
            }
        },
        detection_hints={},
        telemetry=[],
    )
    risk = score_module_result(result)
    assert risk["score"] >= 80
    assert risk["severity"] in {"high", "critical"}


def test_write_risk_summary_creates_machine_readable_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "execution:step-1": ModuleResult(
            status="success",
            module="execution",
            message="ok",
            techniques=["T1059"],
            artifacts={},
            detection_hints={},
            telemetry=[],
        ),
        "legacy_protocol_research:step-2": ModuleResult(
            status="success",
            module="legacy_protocol_research",
            message="Legacy protocol prepared.",
            techniques=["T1071.004"],
            artifacts={
                "legacy": {
                    "pack": "c2_pack",
                    "capability": "dns_tunneling",
                    "mode": "simulate",
                    "payload": {},
                }
            },
            detection_hints={},
            telemetry=[],
        ),
    }
    summary_path = write_risk_summary(run_dir, results)
    payload = summary_path.read_text(encoding="utf-8")
    assert '"risk_summary"' in payload
    assert '"module_count": 2' in payload
    assert '"module": "legacy_protocol_research:step-2"' in payload
    assert '"module_runtime": "legacy_protocol_research"' in payload

    summary = build_risk_summary(results)
    assert summary["module_count"] == 2
    assert summary["average_score"] >= 0
    assert any(item["module"] == "execution:step-1" for item in summary["modules"])


def test_risk_summary_includes_scenario_name_when_provided(tmp_path: Path) -> None:
    """`scenario` field is added to risk_summary.json when the runner passes it."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "execution:step-1": ModuleResult(
            status="success",
            module="execution",
            message="ok",
            techniques=["T1059"],
            artifacts={},
            detection_hints={},
            telemetry=[],
        ),
    }
    summary_path = write_risk_summary(run_dir, results, scenario_name="Demo Scenario")
    payload = summary_path.read_text(encoding="utf-8")
    assert '"scenario": "Demo Scenario"' in payload

    no_scenario = build_risk_summary(results)
    assert "scenario" not in no_scenario


def test_run_scenario_preserves_per_step_detection_paths(tmp_path: Path) -> None:
    """Two steps of the same module should each surface their own detections.

    Previously detection_summary was keyed on the bare module name, so a
    scenario running module X twice would only show the LAST step's
    detection paths in report.md. The runner now keys on `module:step_id`.
    """
    from src.core.bluefire_nexus import BlueFireNexus

    scenario_path = tmp_path / "two_step_scenario.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "id: two-step",
                "name: Two-step execution scenario",
                "objective: exercise per-step detection rendering",
                "attack_coverage: ['T1059']",
                "steps:",
                "  - id: first-cmd",
                "    name: First execution",
                "    module: execution",
                "    params:",
                "      command: echo first",
                "  - id: second-cmd",
                "    name: Second execution",
                "    module: execution",
                "    params:",
                "      command: echo second",
            ]
        ),
        encoding="utf-8",
    )
    nexus = BlueFireNexus(str(tmp_path / "config.yaml"))
    result = nexus.run_scenario_file(str(scenario_path))
    assert result["status"] in {"success", "partial_success"}
    report_md = Path(result["report_path"]).read_text(encoding="utf-8")
    # Both step IDs must appear under their own per-step detection section.
    assert "execution:first-cmd" in report_md
    assert "execution:second-cmd" in report_md


def test_markdown_report_renders_per_step_attack_coverage(tmp_path: Path) -> None:
    """Each declared technique should be mapped to the step(s) that emit it."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "execution:phish-step": ModuleResult(
            status="success",
            module="execution",
            message="ok",
            techniques=["T1059"],
            artifacts={},
            detection_hints={},
            telemetry=[],
        ),
        "initial_access:phish-step": ModuleResult(
            status="success",
            module="initial_access",
            message="ok",
            techniques=["T1566"],
            artifacts={},
            detection_hints={},
            telemetry=[],
        ),
    }
    report_path = write_markdown_report(run_dir, "Mapping", results, {})
    content = report_path.read_text(encoding="utf-8")
    assert "## ATT&CK Technique Coverage" in content
    assert "T1059 — `execution:phish-step`" in content
    assert "T1566 — `initial_access:phish-step`" in content

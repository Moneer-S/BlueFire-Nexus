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

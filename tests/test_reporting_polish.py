from pathlib import Path

from src.core.models import ModuleResult
from src.core.reporting import write_markdown_report
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

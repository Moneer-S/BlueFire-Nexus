from pathlib import Path

import yaml

from src.core.detections import write_detection_artifacts
from src.core.models import ModuleResult


def test_detection_artifacts_include_risk_and_legacy_subtype(tmp_path: Path) -> None:
    result = ModuleResult(
        status="success",
        module="legacy_protocol_research",
        message="Legacy protocol prepared.",
        techniques=["T1071.004"],
        artifacts={
            "legacy": {
                "pack": "c2_pack",
                "capability": "dns_tunneling",
                "mode": "emulate",
                "payload": {
                    "protocol": "dns_tunneling",
                    "transport": "dns",
                    "endpoint": "exfil.example.lab",
                    "legacy_subtype": "dns_tunneling",
                },
            }
        },
        detection_hints={
            "title": "Legacy protocol DNS",
            "mitre_technique": "T1071.004",
            "detection": {
                "selection": {
                    "network.transport": "dns",
                    "network.endpoint|contains": "example.lab",
                },
                "condition": "selection",
            },
        },
        telemetry=[],
    )

    artifacts = write_detection_artifacts(
        tmp_path,
        "run-risk-1",
        {"legacy_protocol_research": result},
    )
    assert artifacts["sigma"]
    assert artifacts["yara_l"]
    assert artifacts["spl"]

    sigma_path = Path(artifacts["sigma"][0])
    sigma_doc = yaml.safe_load(sigma_path.read_text(encoding="utf-8"))
    assert sigma_doc["level"] in {"medium", "high", "critical"}
    assert sigma_doc["x_bluefire_risk"]["score"] >= 45
    assert any(tag.startswith("bluefire.risk.") for tag in sigma_doc["tags"])

    yaral_path = Path(artifacts["yara_l"][0])
    yaral = yaral_path.read_text(encoding="utf-8")
    assert 'risk_score = "' in yaral
    assert 'risk_severity = "' in yaral

    spl_path = Path(artifacts["spl"][0])
    spl = spl_path.read_text(encoding="utf-8")
    assert 'risk_score="' in spl
    assert 'risk_severity="' in spl
    assert 'legacy_subtype="' in spl

    coverage = Path(tmp_path / "detections" / "coverage_run-risk-1.json").read_text(
        encoding="utf-8"
    )
    assert '"legacy_subtype": "dns_tunneling"' in coverage
    assert '"risk_score"' in coverage

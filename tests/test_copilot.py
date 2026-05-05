from pathlib import Path

from src.core.ai.copilot import AICopilot
from src.core.config import ConfigManager


def test_copilot_template_provider_generates_files(tmp_path: Path):
    config = ConfigManager().to_dict()
    config.setdefault("modules", {}).setdefault("ai", {})
    config["modules"]["ai"]["enabled"] = True
    config["modules"]["ai"]["provider"] = "template"
    config["modules"]["ai"]["model"] = "unit-test"

    copilot = AICopilot(config, tmp_path)
    narrative = copilot.narrate("run-test")
    detections = copilot.suggest_detections("run-test")

    assert Path(narrative["path"]).exists()
    assert Path(detections["path"]).exists()
    assert "TemplateProvider response" in narrative["content"]

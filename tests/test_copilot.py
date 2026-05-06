from pathlib import Path

from src.core.ai.copilot import AICopilot
from src.core.ai.providers import OpenAICompatibleProvider, TemplateProvider
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


def test_copilot_offline_default_uses_template_provider(tmp_path: Path) -> None:
    """Default config (no AI enabled) still constructs a TemplateProvider."""
    config = ConfigManager().to_dict()
    copilot = AICopilot(config, tmp_path)
    assert isinstance(copilot.provider, TemplateProvider)
    assert copilot.enabled is False


def test_copilot_consumes_resolved_ai_config_provider_settings(
    tmp_path: Path, monkeypatch
) -> None:
    """`ai_providers.<provider>` block flows through `get_ai_config`
    into the keyless stub so a future remote backend can read vendor-
    specific settings without re-plumbing the copilot.
    """
    monkeypatch.setenv("BLUEFIRE_COPILOT_KEY", "sk-copilot-test")
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "vendor-m",
                "api_base": "http://copilot.lab/v1",
                "api_key_env": "BLUEFIRE_COPILOT_KEY",
            }
        },
        "ai_providers": {
            "openai_compatible": {
                "organization": "org-copilot",
                "api_base": "http://copilot.lab/v1",
            }
        },
    }
    copilot = AICopilot(config, tmp_path)
    assert isinstance(copilot.provider, OpenAICompatibleProvider)
    assert copilot.provider.api_key == "sk-copilot-test"
    assert copilot.provider.endpoint == "http://copilot.lab/v1"
    assert copilot.provider.provider_settings.get("organization") == "org-copilot"

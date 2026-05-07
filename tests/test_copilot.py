from pathlib import Path

from src.core.ai.copilot import AICopilot
from src.core.ai.providers import TemplateProvider
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


def test_copilot_consumes_resolved_ai_config_provider_settings_anthropic_adapter(
    tmp_path: Path, monkeypatch
) -> None:
    """`ai_providers.<provider>` block flows through `get_ai_config`
    into the registered backend. After Phase 1/2 of the provider-
    specific adapters, every canonical name has a real backend; this
    test pins the flow-through against the Anthropic adapter."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.setenv("BLUEFIRE_COPILOT_KEY", "sk-copilot-test")
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "anthropic",
                "model": "vendor-m",
                "api_base": "https://api.anthropic.example",
                "api_key_env": "BLUEFIRE_COPILOT_KEY",
            }
        },
        "ai_providers": {
            "anthropic": {
                "anthropic_version": "2024-09-01",
                "headers": {"X-Operator": "lab"},
            }
        },
    }
    copilot = AICopilot(config, tmp_path)
    assert isinstance(copilot.provider, AnthropicMessagesBackend)
    assert copilot.provider.api_key == "sk-copilot-test"
    assert copilot.provider.endpoint == "https://api.anthropic.example"
    assert copilot.provider.provider_settings.get("anthropic_version") == "2024-09-01"


def test_copilot_consumes_resolved_ai_config_provider_settings_http_backend(
    tmp_path: Path, monkeypatch
) -> None:
    """Same flow-through reaches the Phase 2 HTTP backend for
    OpenAI-protocol-compatible canonical names."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    monkeypatch.setenv("BLUEFIRE_COPILOT_KEY_HTTP", "sk-http-copilot")
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "vendor-m",
                "api_base": "http://copilot.lab/v1",
                "api_key_env": "BLUEFIRE_COPILOT_KEY_HTTP",
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
    assert isinstance(copilot.provider, OpenAICompatibleHTTPBackend)
    assert copilot.provider.api_key == "sk-http-copilot"
    assert copilot.provider.endpoint == "http://copilot.lab/v1"
    assert copilot.provider.provider_settings.get("organization") == "org-copilot"

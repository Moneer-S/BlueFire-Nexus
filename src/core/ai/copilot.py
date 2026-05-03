"""AI copilot orchestration for planning, narration, and detection suggestions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from .providers import LLMProvider, ProviderFactory
from .rag import RAGIndex


class AICopilot:
    """Config-driven AI copilot with deterministic keyless fallback."""

    def __init__(self, config: Dict[str, Any], run_dir: Path) -> None:
        self.config = config
        self.run_dir = run_dir
        ai_cfg = config.get("modules", {}).get("ai", {})
        self.enabled = bool(ai_cfg.get("enabled", False))
        provider_name = str(ai_cfg.get("provider", "template"))
        model_name = str(ai_cfg.get("model", "default"))
        self.provider: LLMProvider = ProviderFactory.build(provider_name, model_name, ai_cfg)

        project_root = Path.cwd()
        self.rag = RAGIndex(
            [
                project_root / "README.md",
                project_root / "docs" / "ARCHITECTURE.md",
                run_dir / "report.md",
            ]
        )

    def _ask(self, prompt: str, extra_context: list[str] | None = None) -> str:
        context = self.rag.search(prompt, limit=5)
        if extra_context:
            context.extend(extra_context)
        return self.provider.complete(prompt, context)

    def plan(self, goal: str) -> Dict[str, str]:
        """Generate scenario YAML from natural language goal."""
        prompt = (
            "Generate a concise BlueFire scenario YAML with fields: "
            f"id, objective, mitre, steps[]. Goal: {goal}"
        )
        content = self._ask(prompt)
        output_path = self.run_dir / "copilot_plan.txt"
        output_path.write_text(content, encoding="utf-8")
        return {"path": str(output_path), "content": content}

    def narrate(self, run_id: str) -> Dict[str, str]:
        """Generate SOC-style run narrative."""
        prompt = (
            "Write a SOC incident narrative with timeline, findings, and "
            f"recommendations for run_id={run_id}."
        )
        content = self._ask(prompt)
        output_path = self.run_dir / "copilot_narrative.md"
        output_path.write_text(content, encoding="utf-8")
        return {"path": str(output_path), "content": content}

    def suggest_detections(
        self,
        run_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Dict[str, str]:
        """Generate detection strategy summary for current run."""
        prompt = (
            "Based on ATT&CK and emitted telemetry, provide concise detection suggestions "
            f"for run_id={run_id}, including Sigma, YARA-L, and SPL guidance."
        )
        content = self._ask(prompt, [f"metadata={dict(metadata or {})}"])
        output_path = self.run_dir / "copilot_detections.md"
        output_path.write_text(content, encoding="utf-8")
        return {"path": str(output_path), "content": content}

"""AI copilot orchestration for planning, narration, and detection suggestions.

Phase 3: every artifact written by the copilot now carries a
machine-readable metadata header (provider / model / generated_at /
network_disabled / fallback_used) and the dict returned by
:meth:`AICopilot.plan` / :meth:`AICopilot.narrate` /
:meth:`AICopilot.suggest_detections` includes the same metadata so
downstream report renderers and operators can attribute output and
spot degraded runs without re-parsing the file.

Fallback wiring: when ``modules.ai.fallback_provider`` is set to a
known canonical name different from the primary provider, the
copilot wraps the primary in a :class:`FallbackChainProvider` so a
primary failure transparently retries via the fallback. The
fallback marker (``fallback_used: true``) appears in both the file
header and the returned dict, plus the original primary error is
recorded in the response metadata.

No AI output ever triggers execution. Artifacts are text-only and
read by humans / report renderers; nothing in this module evals,
imports, or otherwise activates content produced by a provider.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ..configuration import get_ai_config
from .fallback import FallbackChainProvider
from .providers import LLMProvider, ProviderFactory
from .rag import RAGIndex
from .types import ProviderResponse


def _build_provider_chain(ai_cfg: Mapping[str, Any]) -> LLMProvider:
    """Build the primary provider, optionally wrapped with a fallback chain.

    Fallback is opt-in. It only fires when ``fallback_provider`` is
    set to a known canonical name AND the name differs from the
    primary provider (so configuring a fallback that points to the
    primary is a no-op rather than an infinite loop). The fallback
    provider is built with the same ``ai_config`` shape, with only
    the ``provider`` key swapped — operators who need a fallback
    with different credentials can express that via the
    ``ai_providers.<name>`` block which is already merged into the
    AI config by :func:`get_ai_config`.
    """
    primary = ProviderFactory.from_ai_config(ai_cfg)
    fallback_name = str(ai_cfg.get("fallback_provider") or "").strip()
    primary_name = str(ai_cfg.get("provider") or "template").strip()
    if not fallback_name or fallback_name == primary_name:
        return primary
    fallback_cfg = dict(ai_cfg)
    fallback_cfg["provider"] = fallback_name
    fallback = ProviderFactory.from_ai_config(fallback_cfg)
    return FallbackChainProvider(primary=primary, fallback=fallback)


def _utc_now_isoformat() -> str:
    """Return the current UTC timestamp in ``YYYY-MM-DDTHH:MM:SSZ`` form.

    Centralised so tests can monkey-patch a deterministic value
    without reaching into ``datetime`` directly.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_artifact_header(response: ProviderResponse, *, generated_at: str) -> str:
    """Build the YAML-front-matter-style metadata header.

    Format is intentionally readable both as Markdown frontmatter
    and as a plain-text preamble so the same header works for
    ``.md`` and ``.txt`` artifacts without a per-format renderer.
    """
    lines = [
        "---",
        f"provider: {response.provider}",
        f"model: {response.model}",
        f"generated_at: {generated_at}",
        f"network_disabled: {str(response.network_disabled).lower()}",
        f"fallback_used: {str(response.fallback_used).lower()}",
    ]
    if response.fallback_used:
        primary_name = response.metadata.get("primary_provider")
        if primary_name:
            lines.append(f"primary_provider: {primary_name}")
        primary_error = response.metadata.get("primary_error")
        if primary_error:
            # Single-line error blurb so the header stays parseable.
            lines.append(f"primary_error: {str(primary_error).splitlines()[0][:200]}")
    if response.error:
        lines.append(f"error: {str(response.error).splitlines()[0][:200]}")
    if response.finish_reason:
        lines.append(f"finish_reason: {response.finish_reason}")
    lines.append("---")
    lines.append("")  # blank line separating header from body
    return "\n".join(lines)


def _build_artifact_dict(
    *,
    output_path: Path,
    response: ProviderResponse,
    generated_at: str,
) -> Dict[str, Any]:
    """Return the dict shape published by every public copilot method.

    Keeps the legacy ``path`` / ``content`` keys (back-compat with
    callers that only consume those) and adds the per-response
    metadata. ``content`` is the BODY of the artifact (no header)
    so callers that wanted the raw model output keep getting it.
    """
    return {
        "path": str(output_path),
        "content": response.text,
        "provider": response.provider,
        "model": response.model,
        "generated_at": generated_at,
        "network_disabled": response.network_disabled,
        "fallback_used": response.fallback_used,
        "error": response.error,
    }


class AICopilot:
    """Config-driven AI copilot with deterministic keyless fallback."""

    def __init__(self, config: Dict[str, Any], run_dir: Path) -> None:
        self.config = config
        self.run_dir = run_dir
        # Route through the central helper so the copilot picks up the
        # documented AI-config shape (api_key_env / timeout / max_tokens
        # / provider_settings / temperature / fallback_provider) and
        # the `ai_providers.<name>` block flow-through without re-
        # implementing the merge here.
        ai_cfg = get_ai_config(config)
        self.ai_config: Dict[str, Any] = dict(ai_cfg)
        self.enabled = bool(ai_cfg.get("enabled", False))
        self.provider: LLMProvider = _build_provider_chain(ai_cfg)

        project_root = Path.cwd()
        self.rag = RAGIndex(
            [
                project_root / "README.md",
                project_root / "docs" / "ARCHITECTURE.md",
                run_dir / "report.md",
            ]
        )

    def _ask(self, prompt: str, extra_context: Optional[list[str]] = None) -> ProviderResponse:
        """Issue a single generation request and return the rich response.

        Returns the full :class:`ProviderResponse` (not just text) so
        callers can attribute output, render the metadata header, and
        spot fallback paths without re-querying the provider.
        """
        context = self.rag.search(prompt, limit=5)
        if extra_context:
            context.extend(extra_context)
        return self.provider.generate(prompt, context=context)

    def _write_artifact(self, response: ProviderResponse, output_path: Path) -> Dict[str, Any]:
        generated_at = _utc_now_isoformat()
        header = _format_artifact_header(response, generated_at=generated_at)
        # Body is the model text. When the provider returned an error
        # without text (e.g. transport failure with no fallback),
        # surface a clear placeholder so the artifact is still
        # informative for the operator.
        body = response.text or (
            "[no content returned by provider; see header for details]"
        )
        output_path.write_text(header + body, encoding="utf-8")
        return _build_artifact_dict(
            output_path=output_path,
            response=response,
            generated_at=generated_at,
        )

    def plan(self, goal: str) -> Dict[str, Any]:
        """Generate scenario YAML from natural language goal."""
        prompt = (
            "Generate a concise BlueFire scenario YAML with fields: "
            "id, objective, mitre, steps[]. "
            f"Goal: {goal}"
        )
        response = self._ask(prompt)
        output_path = self.run_dir / "copilot_plan.txt"
        return self._write_artifact(response, output_path)

    def narrate(self, run_id: str) -> Dict[str, Any]:
        """Generate SOC-style run narrative."""
        prompt = (
            "Write a SOC incident narrative with timeline, findings, and recommendations "
            f"for run_id={run_id}."
        )
        response = self._ask(prompt)
        output_path = self.run_dir / "copilot_narrative.md"
        return self._write_artifact(response, output_path)

    def suggest_detections(
        self,
        run_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Generate detection strategy summary for current run."""
        prompt = (
            "Based on ATT&CK and emitted telemetry, provide concise detection suggestions "
            f"for run_id={run_id}, including Sigma, YARA-L, and SPL guidance."
        )
        response = self._ask(prompt, [f"metadata={dict(metadata or {})}"])
        output_path = self.run_dir / "copilot_detections.md"
        return self._write_artifact(response, output_path)

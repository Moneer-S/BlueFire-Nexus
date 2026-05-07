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

import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ..configuration import get_ai_config
from .fallback import FallbackChainProvider
from .providers import LLMProvider, ProviderFactory
from .rag import RAGIndex
from .types import ProviderResponse


def _build_provider_chain(config: Mapping[str, Any]) -> LLMProvider:
    """Build the primary provider, optionally wrapped with a fallback chain.

    Fallback is opt-in. It only fires when ``fallback_provider`` is
    set to a known canonical name AND the canonicalised name
    differs from the canonicalised primary provider (so an alias
    pair like ``provider: claude`` + ``fallback_provider:
    anthropic`` is correctly recognised as a no-op rather than
    wrapping a single backend in a self-fallback chain).

    The fallback provider is rebuilt by re-running
    :func:`get_ai_config` against a copy of the FULL config with
    ``modules.ai.provider`` swapped to the fallback name. This
    triggers the ``ai_providers.<fallback>`` block merge so the
    fallback gets its own ``api_base``, ``model``, ``api_key_env``,
    and ``provider_settings`` instead of inheriting the primary's.

    Closes Codex P1 from PR #55: previous version cloned ``ai_cfg``
    and only changed ``provider``, so a config like ``provider:
    openai`` + ``fallback_provider: anthropic`` left the fallback
    instance configured with OpenAI's ``api_base`` / ``model`` /
    ``api_key`` instead of Anthropic's.

    Closes Codex P2 from PR #55: the no-op guard now compares
    canonical names, so alias pairs do not wrap an unnecessary
    fallback chain that would mark every degraded run with
    ``fallback_used`` for what is actually the same backend.
    """
    primary_ai_cfg = get_ai_config(config)
    primary = ProviderFactory.from_ai_config(primary_ai_cfg)

    fallback_name = str(primary_ai_cfg.get("fallback_provider") or "").strip()
    if not fallback_name:
        return primary

    primary_canonical = ProviderFactory.normalise_name(primary_ai_cfg.get("provider"))
    fallback_canonical = ProviderFactory.normalise_name(fallback_name)
    if not fallback_canonical or fallback_canonical == primary_canonical:
        return primary

    # Re-resolve the fallback through get_ai_config so the
    # `ai_providers.<fallback>` block is merged correctly. Working
    # from a deep copy of the original config keeps the primary's
    # resolved view untouched.
    #
    # Clear the primary-specific keys (`model` / `api_base` /
    # `api_key_env`) on the rebuilt `modules.ai`. Otherwise
    # `get_ai_config` would treat the primary's values as already-
    # set and the `ai_providers.<fallback>` block would not be able
    # to populate them — that was the original Codex P1 finding
    # (PR #55): the fallback inherited the primary's endpoint /
    # model / key instead of the fallback vendor's own settings.
    base = copy.deepcopy(dict(config) if isinstance(config, Mapping) else {})
    modules = base.setdefault("modules", {})
    if not isinstance(modules, dict):
        modules = {}
        base["modules"] = modules
    ai_section = modules.setdefault("ai", {})
    if not isinstance(ai_section, dict):
        ai_section = {}
        modules["ai"] = ai_section
    ai_section["provider"] = fallback_canonical
    # Drop primary-vendor identifiers so the fallback's
    # `ai_providers.<fallback>` block populates them.
    for primary_specific_key in ("model", "api_base", "api_key_env"):
        ai_section[primary_specific_key] = ""
    # The fallback should not itself trigger another fallback —
    # clear the field on the rebuilt config so a misconfigured
    # cycle (fallback_provider pointing at a chain) cannot recurse.
    ai_section["fallback_provider"] = ""

    fallback_ai_cfg = get_ai_config(base)
    fallback = ProviderFactory.from_ai_config(fallback_ai_cfg)
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
    body: str,
    generated_at: str,
) -> Dict[str, Any]:
    """Return the dict shape published by every public copilot method.

    Keeps the legacy ``path`` / ``content`` keys (back-compat with
    callers that only consume those) and adds the per-response
    metadata. ``content`` is the BODY actually written to disk
    (header excluded, but placeholder included when the provider
    returned empty text), so API consumers see exactly what the
    file contains without re-reading it.

    Closes Codex P2 from PR #55: previous version returned
    ``content=response.text`` (empty on failure) while the file
    contained the operator-facing placeholder, hiding failure
    details from callers that did not re-open the file.
    """
    return {
        "path": str(output_path),
        "content": body,
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
        # Pass the FULL config (not just ai_cfg) so the fallback
        # branch can re-resolve its own ai_providers.<fallback>
        # block. See _build_provider_chain for details.
        self.provider: LLMProvider = _build_provider_chain(config)

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
        # Pass `body` so the returned dict's `content` matches what is
        # actually on disk (placeholder included on error paths).
        return _build_artifact_dict(
            output_path=output_path,
            response=response,
            body=body,
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

"""Phase 3 copilot artifact metadata + fallback wiring.

The copilot now writes a YAML-front-matter-style metadata header
(provider / model / generated_at / network_disabled /
fallback_used) at the top of every artifact and exposes the same
metadata in the dict returned by ``plan`` / ``narrate`` /
``suggest_detections``. When ``modules.ai.fallback_provider`` is
set to a different known canonical name, the copilot wraps the
primary in a :class:`FallbackChainProvider` so a primary failure
falls back to the offline path automatically.

Pinned invariants:

1. **Header present in every artifact** with the documented keys.
2. **Returned dict matches header**: provider / model /
   generated_at / network_disabled / fallback_used / error are
   all in the dict.
3. **Body is the model output**: returned ``content`` is the model
   text, not the header + text. Callers that just want the body
   keep getting it.
4. **Default config (template provider)** writes a header that
   carries ``provider: template`` and ``network_disabled: true``.
5. **Fallback wiring**: when ``fallback_provider`` is set and the
   primary's response carries an error, the artifact's header
   shows ``fallback_used: true`` plus the primary attribution
   (``primary_provider``, ``primary_error``).
6. **Fallback unset = no fallback chain**: copilot's provider is
   the bare primary, not a FallbackChainProvider, when
   ``fallback_provider`` is empty.
7. **Fallback equal to primary = no chain** (avoids loops).
8. **No execution**: artifacts are text-only; no AI output is
   evaluated, parsed-as-code, or used to alter scenario behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.ai.copilot import AICopilot
from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.providers import TemplateProvider
from src.core.ai.types import ProviderResponse
from src.core.config import ConfigManager


# ---------------------------------------------------------------------------
# Header + dict shape (template provider — default config)
# ---------------------------------------------------------------------------


def _default_copilot(tmp_path: Path) -> AICopilot:
    config = ConfigManager().to_dict()
    return AICopilot(config, tmp_path)


def test_artifact_header_includes_required_metadata_keys(tmp_path: Path) -> None:
    copilot = _default_copilot(tmp_path)
    result = copilot.narrate("run-test")
    written = Path(result["path"]).read_text(encoding="utf-8")

    # Frontmatter delimiters.
    assert written.startswith("---\n"), f"missing frontmatter open: {written[:60]!r}"
    header, _, _body = written[4:].partition("---")  # skip leading "---\n"

    # Required keys present.
    for key in ("provider:", "model:", "generated_at:", "network_disabled:", "fallback_used:"):
        assert key in header, f"header missing {key!r}\n{header}"

    # Default config => template provider, offline.
    assert "provider: template" in header
    assert "network_disabled: true" in header
    assert "fallback_used: false" in header


def test_returned_dict_includes_metadata_alongside_path_and_content(tmp_path: Path) -> None:
    copilot = _default_copilot(tmp_path)
    result = copilot.narrate("run-test")
    assert result["provider"] == "template"
    assert isinstance(result["model"], str) and result["model"]
    assert result["network_disabled"] is True
    assert result["fallback_used"] is False
    assert result["error"] is None
    # generated_at is an ISO-like UTC timestamp.
    assert result["generated_at"].endswith("Z")
    # Legacy keys still present.
    assert "path" in result
    assert "content" in result


def test_returned_content_is_body_only_not_header(tmp_path: Path) -> None:
    copilot = _default_copilot(tmp_path)
    result = copilot.narrate("run-test")
    # Content must be the model body — not include the header.
    assert "TemplateProvider response" in result["content"]
    assert result["content"].lstrip().startswith("TemplateProvider response")
    # And the on-disk file has BOTH header + body.
    on_disk = Path(result["path"]).read_text(encoding="utf-8")
    assert on_disk.startswith("---\n")
    assert result["content"] in on_disk


def test_each_public_method_writes_a_metadata_artifact(tmp_path: Path) -> None:
    copilot = _default_copilot(tmp_path)
    plan = copilot.plan("a goal")
    narrate = copilot.narrate("run-1")
    detections = copilot.suggest_detections("run-1", metadata={"k": "v"})
    for result in (plan, narrate, detections):
        assert Path(result["path"]).exists()
        on_disk = Path(result["path"]).read_text(encoding="utf-8")
        assert on_disk.startswith("---\n")
        assert "provider: template" in on_disk
        assert result["provider"] == "template"
        assert result["fallback_used"] is False


# ---------------------------------------------------------------------------
# Fallback wiring (configured + invoked + unset)
# ---------------------------------------------------------------------------


def test_copilot_does_not_wrap_in_fallback_chain_when_unset(tmp_path: Path) -> None:
    """Default config has fallback_provider unset; provider must be
    the bare primary, not a FallbackChainProvider."""
    copilot = _default_copilot(tmp_path)
    assert not isinstance(copilot.provider, FallbackChainProvider)


def test_copilot_does_not_wrap_when_fallback_equals_primary(tmp_path: Path) -> None:
    """``provider: template`` + ``fallback_provider: template`` is a
    no-op: configuring a fallback that points to the primary must
    not produce an infinite loop wrapper."""
    config = ConfigManager().to_dict()
    config["modules"]["ai"]["fallback_provider"] = "template"
    copilot = AICopilot(config, tmp_path)
    assert not isinstance(copilot.provider, FallbackChainProvider)


def test_copilot_wraps_in_fallback_chain_when_configured(tmp_path: Path) -> None:
    """anthropic primary (keyless stub) + template fallback => the
    copilot's provider is a FallbackChainProvider."""
    config = ConfigManager().to_dict()
    config["modules"]["ai"]["enabled"] = True
    config["modules"]["ai"]["provider"] = "anthropic"
    config["modules"]["ai"]["fallback_provider"] = "template"
    copilot = AICopilot(config, tmp_path)
    assert isinstance(copilot.provider, FallbackChainProvider)


def test_artifact_header_shows_fallback_when_primary_fails(tmp_path: Path) -> None:
    """End-to-end fallback path: stub a primary that always errors,
    leave the template fallback in place, and verify the artifact
    header attributes the fallback path."""
    copilot = _default_copilot(tmp_path)

    class _AlwaysFails:
        name = "primary-mock"
        model = "mock-model"

        def complete(self, prompt, context=None):
            return self.generate(prompt, context=context).text

        def generate(self, prompt, *, context=None, options=None):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="upstream HTTP 503",
            )

    template_fallback = TemplateProvider(model="template-fallback")
    copilot.provider = FallbackChainProvider(
        primary=_AlwaysFails(),
        fallback=template_fallback,
    )

    result = copilot.narrate("run-fallback-test")
    on_disk = Path(result["path"]).read_text(encoding="utf-8")

    # Header reports the fallback path.
    assert "fallback_used: true" in on_disk
    assert "primary_provider: primary-mock" in on_disk
    assert "primary_error: upstream HTTP 503" in on_disk
    # Returned dict attributes the fallback's provider/model.
    assert result["fallback_used"] is True
    assert result["provider"] == "template"
    assert result["model"] == "template-fallback"


def test_artifact_header_shows_error_when_no_fallback(tmp_path: Path) -> None:
    """Primary error + no fallback => header carries ``error: ...``
    and content is a clear placeholder (not the empty string),
    so operators can see something happened without crashing the
    artifact pipeline."""
    copilot = _default_copilot(tmp_path)

    class _AlwaysFails:
        name = "primary-no-fallback"
        model = "mock-model"

        def complete(self, prompt, context=None):
            return self.generate(prompt, context=context).text

        def generate(self, prompt, *, context=None, options=None):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="ECONNREFUSED",
            )

    copilot.provider = _AlwaysFails()  # bare primary, no chain

    result = copilot.narrate("run-error-test")
    on_disk = Path(result["path"]).read_text(encoding="utf-8")

    assert "fallback_used: false" in on_disk
    assert "error: ECONNREFUSED" in on_disk
    # Body has a placeholder rather than being empty so the
    # artifact is informative.
    assert "[no content returned by provider" in on_disk
    assert result["error"] == "ECONNREFUSED"
    assert result["fallback_used"] is False

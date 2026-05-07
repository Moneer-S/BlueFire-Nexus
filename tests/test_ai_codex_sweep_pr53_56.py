"""Regression tests for Codex/Bugbot findings on PRs #53-#56.

Each test references the originating PR comment. Pinned invariants:

1. **PR #54 P1 — backend gate on `enabled`**:
   ``OpenAICompatibleHTTPBackend.generate()`` MUST short-circuit
   to an offline ``ProviderResponse(network_disabled=True, error=
   "AI module is disabled (modules.ai.enabled=false)...")`` when
   the runtime config says ``modules.ai.enabled: false``, even
   when the operator has set ``provider`` and ``api_base``. The
   transport must NEVER be invoked in this state.

2. **PR #54 P2 — explicit zero option overrides**:
   ``ProviderOptions(max_tokens=0)``, ``temperature=0.0``, and
   ``timeout=0`` are explicit operator choices and MUST reach the
   request body / transport timeout. ``None`` remains the
   "use the provider default" sentinel.

3. **PR #55 P1 — fallback config re-resolved**:
   With ``provider=openai`` and ``fallback_provider=anthropic``,
   the fallback provider built by the copilot MUST get its OWN
   ``api_base`` / ``model`` / ``api_key`` from
   ``ai_providers.anthropic.*`` rather than inheriting OpenAI's.

4. **PR #55 P2 — placeholder body in returned dict**:
   When the provider returns empty text (e.g. transport failure),
   the artifact dict's ``content`` MUST equal the body actually
   written to disk (the operator-facing placeholder, not the
   empty string).

5. **PR #55 P2 — canonical comparison for fallback no-op**:
   ``provider: claude`` + ``fallback_provider: anthropic`` is
   semantically the same backend (alias resolution maps both to
   ``anthropic``). The copilot MUST NOT wrap such a config in a
   ``FallbackChainProvider`` — that would mark every degraded
   run as ``fallback_used`` for what is actually the same backend.

6. **PR #56 P1 — docs gate accuracy**:
   The runtime gate is ``enabled AND api_base``, NOT ``api_base
   AND api_key_env``. This invariant is asserted operationally
   by the ``enabled`` gate test (#1) and the empty-key local-
   server tests in ``test_ai_provider_http_backend.py``; this
   file just confirms the canonical truth via an assertion that
   an empty ``api_key_env`` does not block dispatch when
   ``enabled=True`` and ``api_base`` is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List

import pytest

from src.core.ai.backends.openai_compatible import (
    OpenAICompatibleHTTPBackend,
    _backend_factory,
)
from src.core.ai.copilot import (
    AICopilot,
    _build_artifact_dict,
    _build_provider_chain,
)
from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.providers import OpenAICompatibleProvider, ProviderFactory
from src.core.ai.transport import HTTPResponse
from src.core.ai.types import ProviderOptions, ProviderResponse


# ---------------------------------------------------------------------------
# Shared test transport
# ---------------------------------------------------------------------------


@dataclass
class _RecordingTransport:
    responses: List[HTTPResponse] = field(default_factory=list)
    raise_on_call: Exception | None = None
    calls: list[dict] = field(default_factory=list)

    def post_json(self, url, *, headers, body, timeout):  # type: ignore[no-untyped-def]
        self.calls.append({"url": url, "headers": dict(headers), "body": dict(body), "timeout": timeout})
        if self.raise_on_call is not None:
            raise self.raise_on_call
        if not self.responses:
            return HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}',
            )
        return self.responses.pop(0)


# ---------------------------------------------------------------------------
# Finding #1 (PR #54 P1): backend gate on enabled
# ---------------------------------------------------------------------------


def test_codex_pr54_p1_backend_offline_when_enabled_false_even_with_api_base() -> None:
    """A config with `enabled: false` MUST keep the backend offline
    even if `api_base` is set. Closes the PR #54 P1 footgun where
    `enabled=false` + `provider: openai` + `api_base` would still
    issue an outbound request on `generate()` invocation."""
    transport = _RecordingTransport()
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="gpt-x",
        endpoint="https://api.openai.example/v1",
        api_key="sk-real",
        transport=transport,
        enabled=False,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and "AI module is disabled" in response.error
    # The transport MUST NOT have been called.
    assert transport.calls == []


def test_codex_pr54_p1_backend_factory_passes_enabled_through() -> None:
    """The auto-registered `_backend_factory` MUST forward the
    resolved `enabled` flag from the AI config to the backend
    instance, not default to True."""
    backend_disabled = _backend_factory(
        provider="openai",
        model="m",
        api_base="https://api.example/v1",
        api_key="sk",
        provider_settings={},
        ai_config={"enabled": False, "timeout": 30, "max_tokens": 1024, "temperature": None},
    )
    assert isinstance(backend_disabled, OpenAICompatibleHTTPBackend)
    assert backend_disabled.enabled is False

    backend_enabled = _backend_factory(
        provider="openai",
        model="m",
        api_base="https://api.example/v1",
        api_key="sk",
        provider_settings={},
        ai_config={"enabled": True, "timeout": 30, "max_tokens": 1024, "temperature": None},
    )
    assert backend_enabled.enabled is True


def test_codex_pr54_p1_from_ai_config_disabled_provider_does_not_call_transport() -> None:
    """End-to-end: `from_ai_config` builds a backend whose
    `generate()` never touches the transport when `enabled: false`,
    even with a complete remote config (api_base + api_key_env +
    env var populated). Defense in depth for the copilot path."""
    import os

    os.environ["BLUEFIRE_CODEX_SWEEP_TEST_KEY"] = "sk-test"
    try:
        ai_config = {
            "enabled": False,
            "provider": "openai",
            "model": "gpt-x",
            "api_base": "https://api.openai.example/v1",
            "api_key_env": "BLUEFIRE_CODEX_SWEEP_TEST_KEY",
        }
        provider = ProviderFactory.from_ai_config(ai_config)
        # Bind a recording transport so we can prove no call happens.
        transport = _RecordingTransport()
        provider.transport = transport  # type: ignore[attr-defined]
        response = provider.generate("hi")
        assert response.network_disabled is True
        assert response.error and "disabled" in response.error
        assert transport.calls == []
    finally:
        os.environ.pop("BLUEFIRE_CODEX_SWEEP_TEST_KEY", None)


# ---------------------------------------------------------------------------
# Finding #2 (PR #54 P2): explicit-zero option overrides
# ---------------------------------------------------------------------------


def test_codex_pr54_p2_explicit_zero_max_tokens_reaches_request_body() -> None:
    """`ProviderOptions(max_tokens=0)` is an explicit operator
    choice and MUST reach the request body, not be dropped by a
    truthy check."""
    transport = _RecordingTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}',
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        max_tokens=512,  # instance default — must be overridden by options
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(max_tokens=0))
    assert transport.calls[0]["body"]["max_tokens"] == 0


def test_codex_pr54_p2_explicit_zero_temperature_reaches_request_body() -> None:
    """Same for temperature=0.0 (deterministic sampling)."""
    transport = _RecordingTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}',
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        temperature=0.7,  # instance default — must be overridden
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(temperature=0.0))
    assert transport.calls[0]["body"]["temperature"] == 0.0


def test_codex_pr54_p2_explicit_zero_timeout_reaches_transport() -> None:
    """`timeout=0` is an explicit operator choice (e.g. a
    very-short test timeout) and must reach the transport, not
    fall back to the instance default."""
    transport = _RecordingTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}',
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        timeout=42,  # instance default
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(timeout=0))
    assert transport.calls[0]["timeout"] == 0


def test_codex_pr54_p2_none_options_still_use_instance_defaults() -> None:
    """`ProviderOptions(max_tokens=None)` (or omitted entirely) MUST
    fall back to the instance default. None remains the sentinel."""
    transport = _RecordingTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}',
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        max_tokens=256,
        temperature=0.5,
        timeout=30,
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions())
    body = transport.calls[0]["body"]
    assert body["max_tokens"] == 256
    assert body["temperature"] == 0.5
    assert transport.calls[0]["timeout"] == 30


# ---------------------------------------------------------------------------
# Finding #3 (PR #55 P1): fallback re-resolves through get_ai_config
# ---------------------------------------------------------------------------


def test_codex_pr55_p1_fallback_provider_uses_its_own_ai_providers_block(
    monkeypatch,
) -> None:
    """`provider: openai` + `fallback_provider: anthropic` MUST give
    the fallback its own api_base/model/api_key from
    `ai_providers.anthropic.*` rather than inheriting OpenAI's.

    Anthropic now resolves to its dedicated Messages-API adapter
    (Phase 1 of provider-specific backends); the fallback chain
    must still route to it correctly with the per-provider config
    properly merged."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.setenv("BLUEFIRE_TEST_OPENAI_KEY", "sk-openai")
    monkeypatch.setenv("BLUEFIRE_TEST_ANTHROPIC_KEY", "sk-anthropic")

    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai",
                "model": "gpt-4o",
                "api_base": "https://api.openai.example/v1",
                "api_key_env": "BLUEFIRE_TEST_OPENAI_KEY",
                "fallback_provider": "anthropic",
            }
        },
        "ai_providers": {
            "anthropic": {
                "model": "claude-3-opus",
                "api_base": "https://api.anthropic.example/v1",
                "api_key_env": "BLUEFIRE_TEST_ANTHROPIC_KEY",
            }
        },
    }
    chain = _build_provider_chain(config)
    assert isinstance(chain, FallbackChainProvider)
    fallback = chain.fallback
    # The fallback's identity comes from the anthropic block, not openai's.
    assert isinstance(fallback, AnthropicMessagesBackend)
    assert fallback.name == "anthropic"
    assert fallback.model == "claude-3-opus"
    assert fallback.endpoint == "https://api.anthropic.example/v1"
    assert fallback.api_key == "sk-anthropic"


def test_codex_pr55_p1_fallback_does_not_inherit_primary_api_key(monkeypatch) -> None:
    """Defense in depth: even when the fallback's `ai_providers`
    block omits `api_key_env`, the fallback MUST NOT carry the
    primary's resolved key — that would leak credentials across
    vendors."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.setenv("BLUEFIRE_TEST_OPENAI_KEY", "sk-openai-secret")

    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai",
                "api_base": "https://api.openai.example/v1",
                "api_key_env": "BLUEFIRE_TEST_OPENAI_KEY",
                "fallback_provider": "anthropic",
            }
        },
        "ai_providers": {
            "anthropic": {
                "api_base": "https://api.anthropic.example/v1",
                # No api_key_env -> fallback gets empty key, not the OpenAI one.
            }
        },
    }
    chain = _build_provider_chain(config)
    assert isinstance(chain, FallbackChainProvider)
    fallback = chain.fallback
    assert isinstance(fallback, AnthropicMessagesBackend)
    assert fallback.api_key == ""
    assert fallback.api_key != "sk-openai-secret"


def test_codex_pr55_p1_fallback_chain_does_not_recurse() -> None:
    """The rebuilt fallback config explicitly clears
    `fallback_provider` so a chain pointing at another fallback
    cannot recurse / loop infinitely."""
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai",
                "api_base": "https://api.openai.example/v1",
                "fallback_provider": "anthropic",
            }
        },
        "ai_providers": {
            "anthropic": {
                "api_base": "https://api.anthropic.example/v1",
                "fallback_provider": "openai",  # would cycle if honoured
            }
        },
    }
    chain = _build_provider_chain(config)
    assert isinstance(chain, FallbackChainProvider)
    # Fallback must NOT itself be a FallbackChainProvider.
    assert not isinstance(chain.fallback, FallbackChainProvider)


# ---------------------------------------------------------------------------
# Finding #4 (PR #55 P2): dict.content matches body written to disk
# ---------------------------------------------------------------------------


def test_codex_pr55_p2_dict_content_matches_placeholder_body_on_error(
    tmp_path: Path,
) -> None:
    """When the provider returned empty text and the writer wrote
    the operator-facing placeholder body to disk, the returned
    dict's `content` MUST equal that placeholder — not the empty
    string. Closes the inconsistency where API consumers reading
    `result["content"]` saw a blank artifact while the file
    contained the placeholder."""
    config = {
        "modules": {
            "ai": {"enabled": True, "provider": "template", "model": "t"}
        }
    }
    copilot = AICopilot(config, tmp_path)

    class _AlwaysEmpty:
        name = "openai"
        model = "gpt-x"

        def complete(self, prompt, context=None):
            return self.generate(prompt, context=context).text

        def generate(self, prompt, *, context=None, options=None):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="upstream returned no content",
            )

    copilot.provider = _AlwaysEmpty()
    result = copilot.narrate("run-id")

    on_disk = Path(result["path"]).read_text(encoding="utf-8")
    assert "[no content returned by provider" in on_disk
    # The dict must report the SAME body the file contains.
    assert result["content"] in on_disk
    assert "[no content returned by provider" in result["content"]
    assert result["content"] != ""


def test_codex_pr55_p2_dict_content_matches_body_when_text_present(
    tmp_path: Path,
) -> None:
    """Sanity for the success path: when the provider returns
    real text, dict.content equals that text and the file body is
    that same text (no placeholder mismatch)."""
    config = {
        "modules": {
            "ai": {"enabled": True, "provider": "template", "model": "t"}
        }
    }
    copilot = AICopilot(config, tmp_path)
    result = copilot.narrate("run-success")
    on_disk = Path(result["path"]).read_text(encoding="utf-8")
    assert result["content"] in on_disk
    assert "[no content returned by provider" not in result["content"]


def test_codex_pr55_p2_build_artifact_dict_carries_explicit_body(
    tmp_path: Path,
) -> None:
    """Direct unit test of the helper's new contract: dict.content
    is exactly the body argument, not derived from response.text."""
    response = ProviderResponse(
        text="",
        provider="openai",
        model="gpt-x",
        error="some error",
    )
    output_path = tmp_path / "x.md"
    body = "operator-facing placeholder text"
    result = _build_artifact_dict(
        output_path=output_path,
        response=response,
        body=body,
        generated_at="2026-05-06T00:00:00Z",
    )
    assert result["content"] == body
    assert result["content"] != response.text


# ---------------------------------------------------------------------------
# Finding #5 (PR #55 P2): canonical comparison for fallback no-op
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "primary,fallback",
    [
        ("claude", "anthropic"),
        ("anthropic", "claude"),
        ("xai", "grok"),
        ("grok", "x.ai"),
        ("google", "gemini"),
        ("gemini", "google_gemini"),
        # Whitespace + case noise — both sides normalise.
        ("  Anthropic ", "claude"),
    ],
)
def test_codex_pr55_p2_alias_pair_does_not_wrap_fallback_chain(
    primary: str, fallback: str
) -> None:
    """Alias and canonical pairs that resolve to the same backend
    MUST NOT wrap a FallbackChainProvider — that would mark every
    degraded run as `fallback_used` for what is actually a single
    backend."""
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": primary,
                "fallback_provider": fallback,
            }
        }
    }
    chain = _build_provider_chain(config)
    assert not isinstance(chain, FallbackChainProvider), (
        f"expected no fallback wrapper for {primary!r} + {fallback!r} "
        f"(both canonicalise to the same backend); got {type(chain).__name__}"
    )


def test_codex_pr55_p2_distinct_canonical_pair_does_wrap_fallback_chain() -> None:
    """Sanity: a genuinely different fallback DOES still wrap."""
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai",
                "fallback_provider": "anthropic",
            }
        }
    }
    chain = _build_provider_chain(config)
    assert isinstance(chain, FallbackChainProvider)


# ---------------------------------------------------------------------------
# Finding #6 (PR #56 P1): docs gate accuracy operationally verified
# ---------------------------------------------------------------------------


def test_codex_pr56_p1_empty_api_key_env_does_not_block_dispatch() -> None:
    """The runtime gate is `enabled AND api_base`, NOT
    `api_base AND api_key_env`. An empty `api_key_env` (e.g. local
    Ollama / llama.cpp) MUST NOT short-circuit the call when the
    other gates pass — otherwise local-server users would be
    forced to invent a bogus API key. The previous docs claimed
    `api_key_env` was a gate; the runtime never enforced it."""
    transport = _RecordingTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body='{"choices":[{"message":{"content":"local-ollama-ok"},"finish_reason":"stop"}]}',
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="ollama",
        model="llama3",
        endpoint="http://localhost:11434/v1",
        api_key="",  # explicitly empty — local server, no auth
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error is None
    assert response.text == "local-ollama-ok"
    assert response.network_disabled is False
    # Confirms NO Authorization header was sent (the empty-key path).
    assert "Authorization" not in transport.calls[0]["headers"]
    # Transport WAS called — the empty key did not gate dispatch.
    assert len(transport.calls) == 1


def test_codex_pr56_p1_only_actual_gates_block_dispatch() -> None:
    """The two real gates: `enabled=False` blocks; empty
    `api_base` blocks. Nothing else."""
    transport = _RecordingTransport()

    # Gate A: enabled=False blocks (covered by #1 test) — sanity here.
    backend_disabled = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="https://api.example/v1",
        api_key="sk",
        transport=transport,
        enabled=False,
    )
    backend_disabled.generate("hi")
    assert transport.calls == []

    # Gate B: empty api_base blocks even with enabled=True.
    backend_no_base = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend_no_base.generate("hi")
    assert transport.calls == []

    # Both gates passed: dispatch happens.
    backend_ok = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="https://api.example/v1",
        api_key="sk",
        transport=_RecordingTransport(
            responses=[
                HTTPResponse(
                    status_code=200,
                    body='{"choices":[{"message":{"content":"ok"}}]}',
                )
            ]
        ),
        enabled=True,
    )
    backend_ok.generate("hi")
    # Verified by the inner transport's recorded call (we trust the
    # other tests for transport-shape assertions; this only proves
    # the gate combo lets dispatch through).
    assert backend_ok.transport.calls != []  # type: ignore[attr-defined]

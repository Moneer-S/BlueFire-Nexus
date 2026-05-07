# BlueFire Nexus — usage guidelines

Complement to [README.md](../README.md). Covers operator workflows, the
broader CLI surface, scenario authoring, and legacy capability-pack
enablement.

## 1. Authorization and scope

- **Always** obtain explicit, written authorization before exercising any
  technique against any system or network.
- **Always** operate inside isolated lab / purple-team environments.
- Strictly adhere to the authorized scope of testing.
- Review [legal/ethical_guidelines.md](../legal/ethical_guidelines.md).

## 2. Install and configure

See the [README quickstart](../README.md#quickstart). Key files:

- `config.yaml` — runtime configuration. `general.dry_run: true` by default.
- `config/config.example.yaml` — annotated template you can copy.
- `.env` — secrets and provider keys (never commit). Template is
  `.env.example`.
- `general.safeties` — `allowed_subnets`, `max_runtime`. Honour them.

The shipped `config.yaml` enables the legacy capability packs in
`simulate` mode at the per-capability level. The master
`enable_all_lab_capabilities: false` keeps `emulate` mode gated. This is
the right default for purple-team work; tighten or loosen per environment.

### Configuration model

BlueFire-Nexus is designed to support both a simple toggle workflow
and granular advanced configuration. The runtime resolves settings
from multiple sources with the following documented precedence:

1. **CLI flag** — operator's most-specific request (e.g.
   `--legacy-preset full-simulate`).
2. **Scenario step param** — per-step overrides in scenario YAML
   (e.g. `target_from_step: enumerate-files`).
3. **Config file** — `general.*` and `modules.*` keys in
   `config.yaml`.
4. **Environment variable** — for ambient runtime control (test
   isolation, container deployments, e.g. `BLUEFIRE_OUTPUT_ROOT`).
5. **Default** — the local-first, simulate-only baseline.

The single intentional deviation is the runtime output root: there
is no CLI flag or scenario step that overrides it, so the order
simplifies to **config (`general.output_root`) > env
(`BLUEFIRE_OUTPUT_ROOT`) > default (`output`)**.

A small set of helpers in `src/core/configuration.py` exposes the
resolved values for the most common reads:

| Helper | Returns |
|---|---|
| `resolve_output_root(config)` | `Path` for the runtime output root. |
| `get_safety_config(config)` | `dict` with `dry_run`, `auto_wipe`, `max_runtime`, `allowed_subnets`, `allowed_domains`. |
| `get_ai_config(config)` | `dict` with `enabled`, `provider`, `model`, `api_base`, `api_key_env`, `timeout`, `max_tokens`, `temperature`, `fallback_provider`, `provider_settings`, `known_providers`. |
| `get_mutation_config(config)` | `dict` with `enabled`, `default_strategy`, `allowed_strategies`. |
| `is_legacy_capability_enabled(config, pack, capability)` | `bool`. Thin wrapper over `evaluate_legacy_capability`. |
| `is_offline_ai(config)` | `bool` — `True` for the local-first baseline. |
| `resolve_setting(*, cli, scenario, config, env, default)` | Generic precedence helper for scattered settings. |

Helpers always return documented defaults when keys are absent and
tolerate malformed (non-mapping) input rather than raising.

<a id="ai-provider-configuration"></a>

### AI provider configuration

The AI layer is **provider-agnostic and offline by default**. The
shipped baseline ships a deterministic `TemplateProvider` that
produces structured copilot artifacts without any network call or
API key. **No vendor is privileged as the default**: `openai`,
`anthropic`, `gemini`, `grok`, `ollama`, `openai_compatible`,
`llama.cpp`, and `lm-studio` are equal optional opt-in targets.
Aliases (`google → gemini`, `xai → grok`, `claude → anthropic`)
are normalised at factory time so docs and configs can use
vendor-friendly names without changing routing.

**Default behaviour (no config changes required):**

```yaml
modules:
  ai:
    enabled: false              # opt-in copilot artifacts
    provider: template          # deterministic, offline, no network
    model: default
    api_base: ""                # endpoint URL (when applicable)
    api_key_env: ""             # name of env var holding the API key
    timeout: 30                 # per-request timeout in seconds
    max_tokens: 1024            # length cap
    temperature: null           # null = use the provider's default
    fallback_provider: ""       # "" = no fallback; "template" = degrade to offline on error
```

`get_ai_config` populates `modules.ai.api_base` / `model` from a
matching `ai_providers.<provider>` block when the top-level value
is empty, so operators can stash provider settings in one place
without forcing every key into `modules.ai`.

**API keys are read from environment variables only.** Set
`api_key_env` to the env var that holds the key. The runtime
never reads the key from disk and the key never appears in the
config file. A missing env var becomes an empty `api_key` and the
backend handles it gracefully (per-backend rules below) rather
than raising.

**HTTP transport security**: the shipped HTTP backend uses an
injectable transport. The default `UrllibTransport` rejects any
`api_base` whose scheme is not `http://` or `https://` *before*
issuing the call, so a misconfigured `api_base: file:///etc/...`
or `ftp://...` raises a `ValueError` at the transport boundary
rather than touching the network or local filesystem.

#### Example configs per provider target

The OpenAI-compatible HTTP backend already serves these canonical
names. The actual gate before any outbound call is:

1. `modules.ai.enabled: true` (the runtime gate; the backend
   short-circuits to offline when this is false, regardless of
   `api_base`).
2. `modules.ai.api_base` set to a non-empty `http://` or
   `https://` URL (the transport scheme guard rejects anything
   else before dispatch).

`api_key_env` is **not** required for an outbound call — local
servers (Ollama, llama.cpp, LM Studio) typically run without an
`Authorization` header, so the backend omits the header when the
resolved key is empty rather than refusing to send. Vendors that
require auth respond with `401`, which surfaces as a structured
`ProviderResponse(error="http 401: ...")`. Each example below
assumes an explicit operator decision; nothing here is a default.

**Generic OpenAI-compatible endpoint** (most flexible):

```yaml
modules:
  ai:
    enabled: true
    provider: openai_compatible
    model: my-vendor-model
    api_base: "https://my-vendor.example/v1"
    api_key_env: "MY_VENDOR_API_KEY"
    fallback_provider: template
```

**OpenAI**:

```yaml
modules:
  ai:
    enabled: true
    provider: openai
    model: gpt-4o-mini
    api_base: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"
    fallback_provider: template

ai_providers:
  openai:
    headers:
      OpenAI-Organization: "${OPENAI_ORG_ID}"
```

**xAI / Grok** (uses the OpenAI-compatible shape):

```yaml
modules:
  ai:
    enabled: true
    provider: grok                 # alias `xai` also accepted
    model: grok-2
    api_base: "https://api.x.ai/v1"
    api_key_env: "XAI_API_KEY"
    fallback_provider: template
```

**Local Ollama** (OpenAI-compatible mount; runs entirely on your
host with no API key needed):

```yaml
modules:
  ai:
    enabled: true
    provider: ollama
    model: llama3.1
    api_base: "http://localhost:11434/v1"
    api_key_env: ""                # Ollama needs no auth header
    fallback_provider: template
```

**Local llama.cpp / LM Studio** (any OpenAI-compatible local
server):

```yaml
modules:
  ai:
    enabled: true
    provider: llama.cpp            # or `lm-studio`
    model: my-local-model
    api_base: "http://localhost:8080/v1"
    api_key_env: ""
    fallback_provider: template
```

**Anthropic / Claude** (Messages API):

Anthropic uses the Messages API rather than the OpenAI chat-
completions shape, so it has its own dedicated adapter (the
`AnthropicMessagesBackend`). The config shape is the same as
every other provider; the adapter handles the differences
(`x-api-key` header, `anthropic-version` header, top-level
`system` field, `content[].text` blocks, `input_tokens` /
`output_tokens` normalised to the shared usage keys).

```yaml
modules:
  ai:
    enabled: true
    provider: anthropic              # alias `claude` also accepted
    model: claude-3-5-sonnet-20241022
    api_base: "https://api.anthropic.com"
    api_key_env: "ANTHROPIC_API_KEY"
    fallback_provider: template
    # max_tokens is REQUIRED by the Messages API. The adapter
    # defaults to 1024 when neither config nor per-call options
    # set a value; uncomment to override.
    # max_tokens: 4096

ai_providers:
  anthropic:
    # Optional: pin a specific Messages-API version. Default is
    # "2023-06-01" if unset.
    # anthropic_version: "2024-09-01"
    # Optional: add vendor-specific headers (beta flags, etc.).
    # headers:
    #   anthropic-beta: "messages-2024-01-01"
```

Anthropic-specific gate: the adapter requires both `api_base`
AND a non-empty `api_key` before issuing a network call. With
no key the adapter returns a clear
`ProviderResponse(error="anthropic api_key is required; set
modules.ai.api_key_env (or ai_providers.anthropic.api_key_env)
to the env var holding the key")` rather than dispatching and
waiting for a 401. This is intentionally stricter than the
OpenAI-compatible backend (which permits empty keys for local
servers like Ollama / llama.cpp) because Anthropic has no
local-server analog. The `enabled: true` gate still applies on
top: an `enabled: false` config never dispatches regardless of
key state.

**Gemini** (Google GenerateContent API):

Gemini uses Google's GenerateContent API, which has its own
request/response shape (URL contains the model in the path,
`x-goog-api-key` header, `contents` array with `parts`,
top-level `systemInstruction`, `generationConfig` block for
`maxOutputTokens` / `temperature`, `usageMetadata` for token
counts). The dedicated `GeminiGenerateContentBackend` adapter
handles all of that; the config shape is the same as every
other provider.

```yaml
modules:
  ai:
    enabled: true
    provider: gemini                 # aliases `google` and `google_gemini` accepted
    model: gemini-1.5-flash
    api_base: "https://generativelanguage.googleapis.com"
    api_key_env: "GOOGLE_AI_STUDIO_API_KEY"
    fallback_provider: template
    # max_tokens maps to generationConfig.maxOutputTokens.
    # max_tokens: 4096

ai_providers:
  gemini:
    # Optional: pin a different REST API segment. Default is
    # "v1beta" if unset; valid values include "v1".
    # api_version: "v1"
    # Optional: vendor-specific request headers (project labels,
    # billing tags, etc.).
    # headers:
    #   X-Goog-User-Project: "my-gcp-project-id"
```

Same gate semantics as the Anthropic adapter: the backend
requires `enabled=true` AND non-empty `api_base` AND a non-empty
`api_key` before issuing a network call. Empty key returns a
clear `ProviderResponse(error="gemini api_key is required;
set modules.ai.api_key_env (or ai_providers.gemini.api_key_env)
to the env var holding the key")`. The auth header is
`x-goog-api-key` (not Bearer); the `?key=...` query-string
variant is intentionally avoided because it leaks credentials
into server access logs.

**MCP / connectors**: a future option, not a current requirement.
Nothing in the shipped baseline depends on them.

#### Fallback chain

`modules.ai.fallback_provider` opts into the
`FallbackChainProvider` wrapper. When set to a known canonical
name different from the primary, primary failures (transport
errors, non-2xx responses, malformed payloads) transparently
retry via the fallback. Setting `fallback_provider: template` is
the safest choice — the template provider never fails and never
makes network calls, so any primary outage degrades gracefully to
deterministic offline output. The fallback marker
(`fallback_used: true`, plus `primary_provider` / `primary_error`)
appears in the artifact metadata header so operators can see when
a degraded run happened.

#### Artifact metadata header

Every copilot artifact (`copilot_plan.txt`,
`copilot_narrative.md`, `copilot_detections.md`) starts with a
YAML-front-matter-style metadata block:

```
---
provider: openai
model: gpt-4o-mini
generated_at: 2026-05-06T23:50:12Z
network_disabled: false
fallback_used: false
finish_reason: stop
---

[the actual artifact content here]
```

When a fallback fired, the header also carries `primary_provider`
and `primary_error`. When the primary failed and no fallback was
configured, the header carries `error: ...` and the body contains
a clear `[no content returned by provider; see header for
details]` placeholder rather than being empty. The same metadata
is exposed in the dict returned by every public copilot method
(`plan`, `narrate`, `suggest_detections`).

### Simple-mode presets (cross-cutting)

Operators who want to switch posture in one action — rather than
editing scattered `general.*`, `modules.legacy.*`, and `modules.ai.*`
fields — can apply a simple-mode preset:

```bash
python -m src.core.cli simple-presets
python -m src.core.cli apply-simple-preset local_safe --config config.yaml
python -m src.core.cli apply-simple-preset lab_legacy_enabled --config config.yaml --preview-only
```

| Preset | Effect |
|---|---|
| `local_safe` | dry_run on, no legacy packs, AI in offline template mode. The most conservative baseline. |
| `lab_legacy_enabled` | All approved legacy capability packs enabled in `simulate` mode. Emulate mode stays gated until lab acknowledgement is added explicitly. AI stays offline. |
| `ai_enabled` | Enable the offline copilot template provider so scenario runs produce plan / narrative / detection-suggestion artifacts. No network calls. |
| `ai_disabled` | Explicitly disable the AI copilot artifact layer. |
| `strict_local` | Hardest local-first posture — dry_run on, no legacy, no AI, safety gates restricted to loopback only. |

Simple-mode presets are additive on top of the existing
**legacy-only** preset profiles (`safe-baseline`, `full-simulate`,
`full-emulate`, `actor-simulate`, `c2-simulate`, `stealth-simulate`)
exposed via `python -m src.core.cli legacy-presets`. The legacy
presets touch only `modules.legacy.*`; the simple-mode presets touch
`general.*`, `modules.ai.*`, and `modules.legacy.*` together. You
can apply one simple preset and then layer a legacy preset for
finer control.

The `--preview-only` flag prints the dot-path overrides without
writing the config file — useful for inspecting what a preset
would change before committing to it.

## 3. Run a scenario

Two entry points to the same runtime:

```bash
# Module form (the supported way)
python -m src.run_scenario --profile apt29_credential_access --output-json
python -m src.run_scenario --scenario-file scenarios/insider_exfil_dns.yaml --output-json

# Shell wrapper (thin convenience layer)
./scripts/bluefire.sh --profile apt29_credential_access --output-json
```

Common flags on `run_scenario`:

- `--profile <name>` — load a built-in profile.
- `--scenario-file <path>` — load a scenario YAML.
- `--output-json` — emit machine-readable summary on stdout.
- `--run-id <id>` — pin the run id for stable output paths.
- `--legacy-preset <name>` — apply a legacy capability preset for this run only.
- `--legacy-guided` — auto-apply the recommended preset based on the scenario objective.
- `--legacy-pack <pack> --legacy-capability <cap>` — granular per-capability override.

## 4. CLI surface

The Typer-based CLI in `src/core/cli.py` exposes operator workflows:

```bash
# Run a scenario or natural-language plan
python -m src.core.cli run-scenario scenarios/insider_exfil_dns.yaml
python -m src.core.cli plan "Emulate APT29 credential access chain"
python -m src.core.cli suggest-detections <run-id>

# Inspect legacy capability presets
python -m src.core.cli legacy-presets
python -m src.core.cli legacy-guided-presets
python -m src.core.cli legacy-recommend-preset detection --apply
python -m src.core.cli legacy-scenario-recommendation scenarios/legacy_c2_protocols.yaml --apply
python -m src.core.cli legacy-risk-ladder
python -m src.core.cli legacy-risk-posture --config config.yaml
python -m src.core.cli legacy-operator-guide

# Apply a preset to config
python -m src.core.cli legacy-apply-preset c2-sim --config config.yaml
python -m src.core.cli legacy-apply-preset full-simulate --config config.yaml --preview-only

# Inspect a previous run
python -m src.core.cli show-risk-summary output/<run-id>/risk_summary.json --top 10
```

Preset shorthand mappings (accepted by both `legacy-apply-preset` and `--legacy-preset`):

| Preset | Effect |
|---|---|
| `safe-baseline` | All packs disabled. |
| `full-simulate` | All packs enabled in simulate mode. |
| `full-emulate` | All packs enabled in emulate mode with lab confirmation. |
| `actor-simulate` | Actor pack only. |
| `c2-simulate` | C2/protocol pack only. |
| `stealth-simulate` | Stealth pack only. |

Aliases: `simulate-all` → `full-simulate`, `actor-sim` → `actor-simulate`, etc.

## 5. Legacy capability packs

Three opt-in research packs preserve the offensive code paths. All ship
**disabled by default**.

### Master (global) lab toggle

```yaml
modules:
  legacy:
    enable_all_lab_capabilities: true
    lab_confirmation: true
    global_mode: simulate         # or emulate
```

### Granular per-pack / per-capability

```yaml
modules:
  legacy:
    actor_pack:
      enabled: true
      mode: simulate
      capabilities:
        apt29:
          enabled: true
        apt28:
          enabled: false
    c2_pack:
      enabled: false
      capabilities:
        dns_tunneling:
          enabled: true
    stealth_pack:
      enabled: true
      mode: simulate
      capabilities:
        anti_forensic:
          enabled: true
    tactic_pack:
      enabled: true
      mode: simulate
      lab_confirmation: false        # only required for emulate mode
      capabilities:
        credential_access:
          enabled: true
        lateral_movement:
          enabled: false
        privilege_escalation:
          enabled: false
        impact:
          enabled: false
        collection:
          enabled: false
```

The `tactic_pack` capabilities map to explicit modules — scenarios use
`module: legacy_credential_access`, `module: legacy_lateral_movement`,
`module: legacy_privilege_escalation`, `module: legacy_impact`, or
`module: legacy_collection`. The simulate-only standard tactic
modules (`module: credential_access`, etc.) are unchanged and are
NOT routed through the legacy adapters.

### Capability aliases (accepted in YAML and CLI flags)

| Alias | Resolves to |
|---|---|
| `quic_c2`, `quic` | `websocket_quic` |
| `network_obfuscator` | `network_obfuscator_legacy` |
| `anti_detection` | `anti_detection_legacy` |
| `dns`, `dns_tunnel` | `dns_tunneling` |

### Backward-compatible config keys

| Old | New |
|---|---|
| `lab_mode` | `global_mode` |
| `lab_acknowledged` | `global_lab_acknowledged` (and per-pack `lab_confirmation`) |
| capability `emulate_enabled: true` | resolves to `mode=emulate` + `lab_confirmation=true` |

### Step-to-step propagation in scenario YAML

Scenario steps can optionally consume an upstream step's output
without re-declaring it. The runtime threads a read-only
`previous_step_results` mapping into every step's context; modules
opt into reading from it by accepting a small set of `*_from_step`
params.

The standard modules that currently consume this are
`credential_access`, `exfiltration`, `lateral_movement`, and
`impact`. They use the same `target_from_step` opt-in;
`lateral_movement` additionally exposes a `source_from_step`
slot for the attacker pivot host. The `impact` module reads
`target_from_step` so a downstream destruction / encryption
step can target the same host an upstream collection step
staged data on:

```yaml
steps:
  - id: enumerate-files
    name: Enumerate sensitive files
    module: discovery
    params:
      discovery_type: files
      targets: ['finance-analyst-laptop']
      network_touch: false

  - id: harvest-browser-creds
    name: Harvest stored browser credentials
    module: credential_access
    params:
      technique: browser_credentials
      # `target` not declared here; the module pulls it from
      # `previous_step_results['enumerate-files'].artifacts.targets[0]`.
      # An explicit `target:` would still win if added.
      target_from_step: enumerate-files
      network_touch: false

  - id: lateral-to-fileshare
    name: Lateral movement to fileshare via PsExec
    module: lateral_movement
    params:
      technique: psexec
      # Pivot host (`source`) is propagated from the upstream
      # credential-access step. `target` stays explicit because no
      # upstream step has enumerated `corp-fileshare`. Both axes are
      # independent: the lateral_movement module supports
      # `source_from_step` AND `target_from_step` in the same step.
      source_from_step: harvest-browser-creds
      target: corp-fileshare
      network_touch: false

  - id: stage-collected-data
    name: Stage collected files for exfiltration
    module: collection
    params:
      technique: file_staging
      target: corp-fileshare
      network_touch: false

  - id: exfil-over-c2
    name: Exfiltrate staged data over C2
    module: exfiltration
    params:
      method: via_c2
      # Source host is propagated from the upstream collection step:
      # `previous_step_results['stage-collected-data'].artifacts.target`.
      target_from_step: stage-collected-data
      network_touch: false
```

When propagation happens, the downstream module's result records
the upstream step id under `target_propagated_from_step` (and/or
`source_propagated_from_step` for lateral_movement) in `artifacts`,
`detection_hints`, and the telemetry event's `details`, so
downstream consumers (report tables, SIEM searches) can see which
step provided each value.

Resolution order (first non-empty wins, evaluated per axis):
1. Explicit `target` / `source` param.
2. `target_from_step` / `source_from_step` → upstream step's
   `artifacts.target` (single) or first entry of `artifacts.targets`
   (multi).
3. The module's documented default. Today:
   - credential_access: `target` defaults to `lab-host`.
   - exfiltration: `target` defaults to `lab-host`.
   - lateral_movement: `target` defaults to `lab-host`,
     `source` defaults to `lab-attacker`.
   - impact: `target` defaults to `lab-host`.

This is opt-in per module and per scenario step. The runtime never
auto-injects values into params; modules that don't read
`previous_step_results` are unaffected. See
`scenarios/enterprise_intrusion_chain.yaml` for all four worked
examples (`harvest-browser-creds`, `lateral-to-fileshare`,
`exfil-over-c2`, and `ransomware-impact`).

## 6. Programmatic usage

```python
from src.core.bluefire_nexus import BlueFireNexus

nexus = BlueFireNexus("config.yaml")
result = nexus.execute_operation(
    "execution",
    {"command": "echo hello", "network_touch": False},
)
print(result["status"], result["run_id"])
```

For repeated runs with optional jitter:

```python
from src.core.experiments import run_experiment_series

summary = run_experiment_series("scenarios/apt29_credential_access.yaml", iterations=3, jitter=False)
```

## 7. Monitoring a run

Every run writes a complete local bundle under `output/<run_id>/`. Pick the format that matches your workflow:

- **Static HTML dashboard:** open `output/<run_id>/index.html` with `file://` in any browser. No server, no external assets, no network calls. Renders the scenario timeline, propagation graph, ATT&CK coverage, telemetry counts, detection drafts, risk summary, and AI provider attribution.
- **Manifest:** `output/<run_id>/manifest.json` is the machine-readable index of every artifact below. External tooling can read it without walking the directory.
- **Telemetry stream:** `output/<run_id>/telemetry.jsonl` for events emitted by each module step (one JSON object per line).
- **Purple-team narrative:** `output/<run_id>/report.md` (also `report.json` for structured consumers).
- **Detection drafts:** `output/<run_id>/detections/{sigma,yara_l,spl}/` for ATT&CK-mapped rule drafts.
- **Risk posture:** `output/<run_id>/risk_summary.json`.
- **Application logs:** default to `logs/bluefire.log` (path configurable in `config.yaml`).

### CLI: list, inspect, and regenerate views for prior runs

```bash
# Newest first; honours general.output_root / BLUEFIRE_OUTPUT_ROOT.
python -m src.core.cli list-runs

# Single-run detail by run_id.
python -m src.core.cli show-run <run_id>

# Most recent run shortcut.
python -m src.core.cli latest-run

# Regenerate index.html from manifest.json (useful when the
# manifest was edited or the orchestrator's viewer step failed).
python -m src.core.cli build-report-view <run_id>
```

All four commands accept `--output-root <path>` to override discovery for ad-hoc inspection. None starts a server. None auto-opens a browser — operators choose how to open the static `index.html` via OS-native helpers (e.g. `open`, `xdg-open`, `start`).

The viewer is fully self-contained: a single `<style>` block holds the entire CSS, every value is HTML-escaped before rendering, and every artifact link is run-dir-relative so the run directory can be moved without breaking the page.

## 8. ATT&CK mapping notes

BlueFire emulates techniques mapped to MITRE ATT&CK. Examples currently
covered:

- **Process Injection** — T1055.002 (Process Doppelgänging / Reflective DLL Injection) via legacy stealth research.
- **DNS Exfiltration** — T1041 (Exfiltration Over C2 Channel) and T1071.004 (DNS application-layer protocol).
- **TLS Channel Mimicry** — T1573.002 (Encrypted Channel) via legacy TLS fast-flux research.
- **Discovery family** — T1046, T1018, T1082, T1057, T1007, T1087, T1069, T1083 via the standard `discovery` module's per-input fan-out.

Per-module / per-pack detail: [reports/capability_inventory.md](reports/capability_inventory.md).

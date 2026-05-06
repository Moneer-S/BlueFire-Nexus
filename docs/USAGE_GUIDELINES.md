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
| `get_ai_config(config)` | `dict` with `enabled`, `provider`, `model`, `api_base`, `api_key_env`, `timeout`, `max_tokens`, `provider_settings`, `known_providers`. |
| `get_mutation_config(config)` | `dict` with `enabled`, `default_strategy`, `allowed_strategies`. |
| `is_legacy_capability_enabled(config, pack, capability)` | `bool`. Thin wrapper over `evaluate_legacy_capability`. |
| `is_offline_ai(config)` | `bool` — `True` for the local-first baseline. |
| `resolve_setting(*, cli, scenario, config, env, default)` | Generic precedence helper for scattered settings. |

Helpers always return documented defaults when keys are absent and
tolerate malformed (non-mapping) input rather than raising.

### AI provider config shape (preparation only — local-first today)

The default AI layer remains the deterministic offline
`TemplateProvider`. There is no remote provider implementation in the
shipped baseline; the runtime never makes network calls under default
config. The config shape below is documented so plug-and-play
provider implementations can be wired in later without re-shaping
config:

```yaml
modules:
  ai:
    enabled: false              # opt-in copilot artifacts
    provider: template          # default: deterministic, offline
    model: default
    api_base: ""                # OpenAI-compatible endpoint URL
    api_key_env: ""             # name of env var holding the API key
    timeout: 30                 # seconds (no effect on template)
    max_tokens: 1024            # length cap (no effect on template)

ai_providers:
  openai_compatible:
    api_base: "{{ env OPENAI_COMPATIBLE_BASE_URL }}"
    model: "model-name"
  # other vendor-specific blocks are tolerated; the runtime does not
  # dial out under any default config.
```

`get_ai_config` populates `modules.ai.api_base` / `model` from the
matching `ai_providers.<provider>` block when the top-level value is
empty, so operators can stash provider settings in one place. The
default provider remains `template`. **Ollama is NOT a default**;
it can be reached as an OpenAI-compatible endpoint by setting
`provider: openai_compatible` and pointing `api_base` at the local
Ollama server, but it is not privileged over any other provider.

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

The `credential_access` standard module is the first to support this:

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
```

When propagation happens, the credential-access result records the
upstream step id under `target_propagated_from_step` in
`artifacts`, `detection_hints`, and the telemetry event's `details`,
so downstream consumers (report tables, SIEM searches) can see
which step provided the target.

Resolution order (first non-empty wins):
1. Explicit `target` param.
2. `target_from_step` → upstream step's `artifacts.target` (single)
   or first entry of `artifacts.targets` (multi).
3. The module's documented default (`lab-host` for credential-access).

This is opt-in per module and per scenario step. The runtime never
auto-injects values into params; modules that don't read
`previous_step_results` are unaffected. See
`scenarios/enterprise_intrusion_chain.yaml` for a working example.

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

- Inspect `output/<run_id>/telemetry.jsonl` for events emitted by each module step.
- Inspect `output/<run_id>/report.md` for the purple-team narrative.
- Inspect `output/<run_id>/detections/{sigma,yara_l,spl}/` for ATT&CK-mapped detection drafts.
- Inspect `output/<run_id>/risk_summary.json` for the run risk posture.
- Application logs default to `logs/bluefire.log` (path configurable in `config.yaml`).

## 8. ATT&CK mapping notes

BlueFire emulates techniques mapped to MITRE ATT&CK. Examples currently
covered:

- **Process Injection** — T1055.002 (Process Doppelgänging / Reflective DLL Injection) via legacy stealth research.
- **DNS Exfiltration** — T1041 (Exfiltration Over C2 Channel) and T1071.004 (DNS application-layer protocol).
- **TLS Channel Mimicry** — T1573.002 (Encrypted Channel) via legacy TLS fast-flux research.
- **Discovery family** — T1046, T1018, T1082, T1057, T1007, T1087, T1069, T1083 via the standard `discovery` module's per-input fan-out.

Per-module / per-pack detail: [reports/capability_inventory.md](reports/capability_inventory.md).

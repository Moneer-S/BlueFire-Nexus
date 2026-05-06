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

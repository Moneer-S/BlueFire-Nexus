# BlueFire Nexus scenario coverage

Reference for the scenarios shipped under `scenarios/` and the artifacts
each one produces. Every scenario passes dry-run/simulate execution out
of the box; this document maps each one to its modules, ATT&CK
coverage, and artifact output.

## Running a scenario

```bash
python -m src.run_scenario --scenario-file scenarios/<name>.yaml --output-json
```

Each run produces a structured directory under `output/<run_id>/`:

```
output/<run_id>/
├── telemetry.jsonl              # one JSON event per module step
├── report.md                    # purple-team narrative
├── report.json                  # structured per-step result
├── risk_summary.json            # per-run risk posture
└── detections/
    ├── sigma/*.yml
    ├── yara_l/*.yaral
    ├── spl/*.spl
    └── coverage_<run_id>.json
```

## Shipped scenarios

| Scenario | Steps | ATT&CK coverage | Theme |
|---|---:|---|---|
| `apt29_credential_access` | 5 | T1566 / T1059 / T1027 / T1555 / T1041 | APT29-style credential access chain. |
| `fin7_initial_access_to_c2` | 3 | T1566 / T1059 / T1071.001 | FIN7-style initial access to C2 chain. |
| `healthcare_ransomware` | 5 | T1566 / T1059 / T1053 / T1041 / T1486 | Healthcare ransomware end-to-end chain (precursor → impact). |
| `insider_exfil_dns` | 4 | T1083 / T1041 / T1071.004 / T1572 | Insider DNS-based data exfiltration. |
| `legacy_actor_apt29` | 5 | T1589 / T1566 / T1059 / T1036 | APT29 research pack via legacy adapters. |
| `legacy_actor_family_full` | 8 | T1059 / T1071 / T1589 / T1561 / T1566 | Smoke-test for every actor adapter (APT29/28/32/38/41). |
| `legacy_c2_protocols` | 6 | T1071.004 / T1572 / T1090 | Legacy C2 protocol research (DNS/TLS/QUIC/RPC). |
| `legacy_flagship_blended` | 5 | T1589 / T1566 / T1071.004 / T1070 | Blended actor + protocol + stealth research. |
| `legacy_stealth_research` | 5 | T1497 / T1562 / T1070 / T1027 | Anti-forensic / anti-sandbox / anti-detection research. |

## Per-scenario notes

### `apt29_credential_access`
Five-step actor-aligned chain (initial access → execution →
anti-detection → credential extraction → exfiltration). The
credential-extraction step uses the `credential_access` standard
module with `technique: browser_credentials` to surface T1555.003
telemetry, satisfying the parent T1555 declared in `attack_coverage`.

### `fin7_initial_access_to_c2`
Three-step chain demonstrating phish → loader execution → C2 beacon. The
encoded PowerShell payload in step 2 is a synthetic example; the C2 URL
in step 3 (`https://example.lab/c2`) sits inside the lab allowlist.

### `healthcare_ransomware`
Five-step ransomware end-to-end chain (initial access → execution →
persistence → exfiltration → encryption-impact). The final `impact`
step uses `technique: data_encryption` to surface T1486 telemetry.
The `impact` standard module never writes destructive payloads under
any input — telemetry is purely synthesised.

### `insider_exfil_dns`
Four-step insider DNS-exfil chain (file discovery → exfiltration via
DNS tunnel → DNS-channel C2 metadata → network obfuscation). Step 1
uses `discovery_type: files` (T1083) and `network_touch: true`. The
DNS-channel C2 step (`command_control` with `channel: dns`) emits
T1071.004 alongside the obfuscation step's T1572.

### `legacy_actor_apt29`
Five-step legacy-adapter showcase exercising APT29-specific phishing and
PowerShell tradecraft via `legacy_apt29_research`.

### `legacy_actor_family_full`
Eight-step coverage smoke test exercising every actor adapter (APT29 +
APT28 + APT32 + APT38 + APT41). Useful for verifying that all five actor
adapters import and dispatch cleanly.

### `legacy_c2_protocols`
Six-step protocol research pack exercising every C2 protocol adapter
(DNS tunneling, TLS fast-flux, WebSocket-QUIC, Solana RPC, network
obfuscation). Each step produces protocol-specific telemetry and
detection drafts.

### `legacy_flagship_blended`
Five-step blended showcase combining actor + protocol + stealth research.
Demonstrates that the legacy capability packs can be enabled in the same
run.

### `legacy_stealth_research`
Five-step stealth research chain exercising anti-forensic, anti-sandbox,
anti-detection, and dynamic API research adapters.

## Authoring scenarios

A scenario is a YAML file under `scenarios/`:

```yaml
id: my_scenario
name: My scenario
objective: Brief description of the adversary chain being modeled.
attack_coverage:
  - T1566
  - T1059
fail_fast: false
steps:
  - id: step_one
    name: Initial access
    module: initial_access
    params:
      vector: phishing_email
      target: lab-user
  - id: step_two
    name: Execute payload
    module: execution
    params:
      command: "echo simulated"
expected_detections:
  - Suspicious office process spawning script interpreter
blue_team_guidance:
  - Correlate parent-child process chains from office apps to script engines.
```

`module` must reference a name in the registry (see
[capability_inventory.md](capability_inventory.md)). `params` are
passed through to the module's `execute()`. Most modules expose a
per-input fan-out (`technique`, `discovery_type`, `channel`,
`protocol`, etc.) so every step can produce distinct telemetry and
detection drafts.

Apply mutation strategies at run time with `--mutate <strategy>` (see
[USAGE_GUIDELINES.md](../USAGE_GUIDELINES.md)). The mutation strategy is
recorded in the run summary so it is never silent.

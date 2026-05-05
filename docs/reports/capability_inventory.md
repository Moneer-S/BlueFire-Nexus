# BlueFire Nexus capability inventory

Reference for the modules registered with the orchestrator and the
ATT&CK techniques each module covers. Updated alongside the codebase;
generated content can be regenerated from `build_runtime_modules()` and
the per-module profile catalogs in
`src/core/modules/impl/standard_modules.py`.

## Registry

`src/core/modules/registry.py:BUILTIN_MODULE_CLASSES` is the single
source of truth. The runtime currently registers **17 standard modules**
plus **8 legacy capability adapters** for a total of **25 modules**.

### Standard modules (17)

| Module | Catalog | MITRE techniques | Default key |
|---|---:|---|---|
| `initial_access` | 1 | T1566 | (single shape) |
| `execution` | 1 | T1059 | (single shape) |
| `persistence` | 10 | T1053.{003,005} / T1543.{001,003,004} / T1546.{003,004} / T1547.001 / T1542.003 | `scheduled_task` |
| `defense_evasion` | 8 | T1036 / T1027 / T1070.{001,006} / T1218 / T1564.{001,010} / T1562.001 | `argument_spoofing` |
| `discovery` | 10 | T1046 / T1018 / T1082 / T1057 / T1007 / T1087 / T1069 / T1083 | `network_scan` |
| `credential_access` | 9 | T1003.{001,002,003} / T1555.{001,003} / T1552.004 / T1056.001 / T1115 / T1113 | `lsass_dump` |
| `lateral_movement` | 8 | T1021.{002,004,006} / T1047 / T1570 / T1543.003 | `psexec` |
| `privilege_escalation` | 9 | T1134.{001,003} / T1055 / T1055.012 / T1036.005 / T1543.003 / T1548.002 | `token_impersonation` |
| `command_control` | 8 | T1071.{001,003,004} / T1095 / T1102 | `http` |
| `exfiltration` | 1 | T1041 (lab-acknowledgment gated) | (single shape) |
| `impact` | 10 | T1486 / T1485 / T1565 / T1489 / T1529 / T1499 / T1496 | `data_encryption` |
| `collection` | 10 | T1074.001 / T1560.{001,002} / T1056.001 / T1115 / T1113 / T1123 / T1114.001 | `file_staging` |
| `network_obfuscator` | 8 | T1572 / T1090.{001,002,003,004} / T1001.003 | `dns` |
| `intelligence` | 7 | T1591 / T1591.002 / T1592.002 / T1588.006 / T1589.001 / T1590 / T1590.005 | `actor_research` |
| `reconnaissance` | 10 | T1593 / T1593.{001,002,003} / T1590.{001,002} / T1589.002 / T1595.{001,002} | `osint` |
| `resource_development` | 10 | T1583.{001,003,006} / T1585.{001,002} / T1588.{001,003,005,006} / T1584.001 | `domain` |
| `anti_detection` | 1 | T1027 | (single shape) |

Per-input fan-out modules (every module above with a catalog of 7+
entries) emit a distinct telemetry `event_type`, MITRE sub-technique,
sigma-style logsource, and detection-selection field per input value.
Unknown values fall back to the documented default and surface the
rejected value as `detection_hints["unrecognized_*"]` for operator
visibility.

### Legacy capability adapters (8)

| Adapter | Pack | Notes |
|---|---|---|
| `legacy_capability_summary` | (meta) | Reports active legacy enablement state. |
| `legacy_actor_profile` | actor_pack | Loads APT actor profile (apt29 / apt28 / apt32 / apt38 / apt41). |
| `legacy_apt29_research` | actor_pack | Per-technique adapter for APT29 research code. |
| `legacy_apt28_research` | actor_pack | Generic actor adapter for APT28. |
| `legacy_apt32_research` | actor_pack | Generic actor adapter for APT32. |
| `legacy_apt38_research` | actor_pack | Generic actor adapter for APT38. |
| `legacy_apt41_research` | actor_pack | Generic actor adapter for APT41. |
| `legacy_protocol_research` | c2_pack | DNS tunneling / TLS fast-flux / WebSocket-QUIC / Solana RPC / network obfuscation. |
| `legacy_stealth_research` | stealth_pack | Anti-forensic / anti-sandbox / anti-detection / dynamic API resolution. |

All legacy packs ship **disabled by default**. Enable globally with the
master lab toggle or per-pack/per-capability with explicit opt-in. See
[USAGE_GUIDELINES.md](../USAGE_GUIDELINES.md) for enablement examples.

## Mode model

Every module honors three orthogonal mode controls:

- **`general.dry_run`** (default `true`) — no real subprocess / socket /
  HTTP primitives. Enforced by `tests/test_module_safety.py`.
- **Legacy capability `mode`** — `simulate` (default for any enabled
  capability) synthesises telemetry and detection hints locally;
  `emulate` invokes the real research code path and requires
  `lab_confirmation: true`.
- **`ExecutionModule.allow_real_execution`** (default `false`) — real
  `subprocess.run` requires both `dry_run=False` AND
  `allow_real_execution=true`.

## ModuleResult contract

Every `execute()` returns a `ModuleResult`
([src/core/models.py](../../src/core/models.py)) with:

| Field | Type | Notes |
|---|---|---|
| `status` | Literal | `success` / `failure` / `blocked` / `skipped` / `partial_success` |
| `module` | str | Equals the registry key |
| `message` | str | Human-readable summary |
| `techniques` | list[str] | ATT&CK technique IDs |
| `artifacts` | dict[str, Any] | On-disk paths must resolve under `context["output_dir"]` |
| `telemetry` | list[TelemetryEvent] | Each event's `module` matches the result module |
| `detection_hints` | dict[str, Any] | Drives Sigma / YARA-L / SPL artifact generation |
| `error` | Optional[str] | Short error summary on failure |
| `timestamp` | str (UTC ISO-8601) | Auto-populated |

Conformance is enforced for every registered module by
[`tests/test_module_contract.py`](../../tests/test_module_contract.py).

## Detection-output story

Each module attaches `detection_hints` to its result. The detection
engine ([src/core/detections/engine.py](../../src/core/detections/engine.py))
consumes those hints to emit per-run artifact files:

- **Sigma** — `output/<run_id>/detections/sigma/*.yml`
- **YARA-L** — `output/<run_id>/detections/yara_l/*.yaral`
- **Splunk SPL** — `output/<run_id>/detections/spl/*.spl`. Local
  detection-rule output format only; **not** a Splunk exporter or SIEM
  connector.

Common hint keys: `title`, `logsource`, `detection`, `condition`,
`mitre_technique`, plus topic-specific fields like `network_protocol`,
`network_url`, `process_command_line`.

## Legacy code preservation

Several substantial offensive-research files are preserved in
`src/core/<tactic>/*.py` but not yet wired through the standard module
layer. The standard adapters for `credential_access`, `lateral_movement`,
`privilege_escalation`, `impact`, and `collection` are simulate-only;
emulate-mode wiring to the legacy implementations remains future work.
The legacy code is intentionally retained as the source of truth for
technique coverage when the emulate-mode bridges are added.

# Case Study: Legacy Stealth Pack (Anti-Forensic / Anti-Sandbox / Anti-Detection / Dynamic API)

## Objective

Demonstrate how the legacy stealth research family is integrated as a first-class
pack in BlueFire-Nexus while remaining safe by default.

## Scope

The scenario `scenarios/legacy_stealth_research.yaml` exercises:

- `anti_forensic` research controls
- `anti_sandbox` environment checks
- `anti_detection_legacy` anti-analysis behavior
- `dynamic_api` API-resolution research

All outputs flow through `ModuleResult -> TelemetryEvent -> detections/reporting`
like standard modules.

## ATT&CK coverage

- T1070 (Indicator Removal on Host)
- T1497 (Virtualization/Sandbox Evasion)
- T1562 (Impair Defenses)
- T1027 (Obfuscated/Compressed Files and Information)

## What blue teams can validate

1. Stealth capability usage is visible in telemetry with mode (`simulate` or `emulate`).
2. Detection drafts include capability-specific selectors and ATT&CK IDs.
3. Reports call out pack/capability usage and summarize safety gating.

## Safety and enablement

- Disabled by default.
- `simulate` is the default behavior.
- `emulate` requires explicit lab confirmation.
- Both master-toggle and per-capability toggles are supported.

## Why this matters for the portfolio

The stealth pack keeps advanced research functionality visible, but within a
controlled runtime that is suitable for purple-team workflows and detection
engineering demonstrations.

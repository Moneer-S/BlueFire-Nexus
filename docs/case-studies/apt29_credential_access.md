# Case Study: APT29 Credential Access and Legacy Research Blend

## Objective

Exercise an ATT&CK-aligned APT29-style chain that now spans both the standard
runtime modules and the legacy capability pack layer. The goal is to show how
BlueFire-Nexus can preserve bleeding-edge legacy research while still producing
normalized telemetry, detections, and reporting artifacts.

## What this scenario demonstrates

- A legacy actor profile can be enabled as a first-class runtime module.
- Legacy research techniques can remain disabled by default yet still be easy to
  enable through either:
  - one master lab toggle, or
  - granular per-pack/per-capability toggles.
- The resulting activity is surfaced through the same reporting and detection
  paths as modern built-in modules.

## ATT&CK coverage

- T1566 (Phishing)
- T1059 (Command and Scripting Interpreter)
- T1036 (Masquerading / process-hollowing-style research indicators)
- T1071.004 (DNS)

## Blue-team value

This scenario is useful because it links a recognizable threat actor profile to
concrete telemetry and draft detections. Instead of documenting “APT29-like
behavior” abstractly, the run produces:

1. actor-profile telemetry,
2. legacy technique metadata,
3. Sigma / YARA-L / SPL drafts,
4. a run report that explains whether the capability was executed in
   `simulate` or `emulate` mode.

When run in `emulate`, the adapter now attempts to execute the corresponding
legacy actor routine and captures runtime outcomes and extracted indicators in
the same normalized payload used by the detection engine.

## Safety model

The legacy APT29 research path is:

- off by default,
- visible in config and CLI summaries,
- easy to enable for a lab via the master toggle,
- still available one capability at a time for granular validation.

That gives the project a better portfolio story: advanced capability is present,
but it is controlled and deliberate rather than hidden or accidental.
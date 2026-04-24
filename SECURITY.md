# Security Policy

## Supported Versions


| Version | Supported |
| ------- | --------- |
| 2.x     | yes       |
| 1.x     | no        |


## Scope and threat model

BlueFire-Nexus is designed for authorized adversary-emulation labs only. The primary
security goals are:

- prevent accidental real-world impact,
- prevent secret leakage,
- prevent implicit third-party data exfiltration,
- keep unsafe functionality explicitly gated.

Out of scope:

- unsupported forks,
- intentionally unsafe local modifications,
- running against unauthorized targets.

## Safe defaults

- `general.dry_run` defaults to `true`.
- Network egress features are opt-in.
- Telemetry defaults to local JSONL output.
- AI providers are opt-in and require user-supplied configuration.
- No API keys are bundled in source.

## Reporting a vulnerability

Use GitHub security advisories (preferred) or open an issue with minimal exploit detail.
Please include:

- affected file path(s),
- commit hash or branch,
- reproduction steps,
- impact,
- suggested fix (if available).

Do not include live credentials or sensitive customer data in reports.

## Secure development controls

CI and local hooks enforce:

- `ruff`, `black --check`, `mypy`,
- `bandit`, `pip-audit`,
- secret detection via `gitleaks` and `detect-secrets`.

## Sensitive data handling

- Keep secrets in `.env` (never commit it).
- Use `.env.example` for variable names only.
- Do not commit customer identifiers, internal hostnames, private IP inventories, or personal data.

## Contact

Open a GitHub Security Advisory or issue tagged `security`.
# BlueFire-Nexus

[![tests](https://img.shields.io/badge/tests-pytest-blue)](#testing)
[![security](https://img.shields.io/badge/security-bandit%2Bgitleaks-green)](#security-first-defaults)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](#quickstart)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

BlueFire-Nexus is a **config-driven purple-team adversary emulation platform** built to bridge automated detection engineering with human-led investigation.

Each run can produce:
- ATT&CK-mapped module telemetry
- Detection drafts (**Sigma**, **YARA-L**, **Splunk SPL**)
- SOC-oriented narrative artifacts via an optional AI copilot (template fallback available offline)

## Security-first defaults

- Dry-run enabled by default (`general.dry_run: true`)
- No implicit egress to SIEM, AI, or C2 endpoints
- Deny-by-default safety gates (`allowed_subnets`, `max_runtime`)
- Optional destructive behavior requires explicit acknowledgment flag
- Secret scanning and security checks in CI (`gitleaks`, `detect-secrets`, `bandit`, `pip-audit`)

Read:
- `SECURITY.md`
- `legal/ethical_guidelines.md`
- `.env.example`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python -m src.run_scenario --profile apt29_credential_access --output-json
```

Or use the shell wrapper:

```bash
./scripts/bluefire.sh --profile apt29_credential_access --output-json
```

## Core workflows

### Run a scenario file
```bash
python -m src.run_scenario --scenario-file scenarios/healthcare_ransomware.yaml --output-json
```

### Run via Rich/Typer CLI
```bash
python -m src.core.cli run-scenario scenarios/insider_exfil_dns.yaml
python -m src.core.cli plan "Emulate APT29 credential access chain"
python -m src.core.cli suggest-detections run-20260101010101-abcd1234
```

### Programmatic usage
```python
from src.core.bluefire_nexus import BlueFireNexus

nexus = BlueFireNexus("config.yaml")
result = nexus.execute_operation(
    "execution",
    {"command": "echo hello", "network_touch": False},
)
print(result["status"], result["run_id"])
```

## Architecture (current)

```mermaid
flowchart LR
    cliRunner["CLI (scripts/bluefire.sh + src/run_scenario.py + src/core/cli.py)"] --> orchestrator["BlueFireNexus"]
    scenarioFiles["scenarios/*.yaml"] --> orchestrator
    configYaml["config.yaml + .env"] --> orchestrator
    orchestrator --> moduleRegistry["ModuleRegistry (BaseModule + built-ins + plugins)"]
    orchestrator --> safetyGate["SafetyGate"]
    orchestrator --> telemetryBus["TelemetryBus (JSONL default; OpenSearch/Elasticsearch/NGSIEM/Splunk opt-in)"]
    orchestrator --> detectionGen["DetectionEngine (Sigma/YARA-L/SPL)"]
    orchestrator --> aiCopilot["AICopilot (provider-selected, template fallback)"]
    orchestrator --> runArtifacts["output/run_id/* (report, detections, copilot output)"]
```

## Scenario library

- `scenarios/apt29_credential_access.yaml`
- `scenarios/fin7_initial_access_to_c2.yaml`
- `scenarios/healthcare_ransomware.yaml`
- `scenarios/insider_exfil_dns.yaml`

## AI provider strategy

User-selected, config-driven provider selection with zero lock-in:
- `template` / `none` (offline deterministic fallback)
- `openai`, `anthropic`, `google`
- `ollama`, `llama.cpp`, `lm-studio`
- `openai_compatible`

By default, provider implementations are safety-preserving and do not force live external calls.

## SIEM connector priorities

Telemetry sink order and support:
1. OpenSearch
2. Elasticsearch
3. NGSIEM (HEC-style)
4. Splunk HEC
5. JSONL (always available default sink)

## Testing

```bash
pytest -q
python -m compileall -q src
```

## Development quality gates

- `pyproject.toml`: pytest, black, ruff, mypy, bandit config
- `.pre-commit-config.yaml`: ruff, bandit, detect-secrets, gitleaks
- `.github/workflows/tests.yml`
- `.github/workflows/analysis.yml`

## Case studies

- `docs/case-studies/apt29_credential_access.md`
- `docs/case-studies/healthcare_ransomware.md`

## Optional local lab

`docker-compose.lab.yml` provides a simple local stack with OpenSearch + Dashboards + a BlueFire container profile.

## License

MIT. See `LICENSE`.

## Disclaimer

Use only in authorized, isolated environments for defensive testing and research.
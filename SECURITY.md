# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.x     | yes       |
| 1.x     | no        |

## Scope and threat model

BlueFire-Nexus is a high-fidelity adversary emulation framework intended for
authorized purple-team labs and security research. It is dual-use by design:
it preserves realistic offensive tradecraft (APT actor packs, credential
access, lateral movement, C2 protocol research, evasion, exfiltration) and
gates that capability behind explicit configuration, lab confirmation, and
default-safe behaviour.

The primary security goals are:

- prevent accidental real-world impact,
- prevent secret leakage,
- prevent implicit third-party data exfiltration,
- keep advanced/offensive functionality explicitly gated rather than removed.

Out of scope:

- unsupported forks,
- intentionally unsafe local modifications,
- running against unauthorized targets.

## Safe defaults

These defaults are baked into the shipped configs and enforced by registry-wide
tests; they are not best-effort guidance.

- **Dry-run is on by default** (`general.dry_run: true`).
  `tests/test_module_safety.py` parametrizes over every registered module
  and asserts that no module invokes `subprocess.{run, Popen, call,
  check_call, check_output, getoutput, getstatusoutput}`, `os.{system,
  popen}`, `socket.{socket, create_connection}`,
  `requests.{get, post, put, delete, patch, head, options, request,
  Session}`, `urllib.request.urlopen`, or `aiohttp.ClientSession` while
  `dry_run=True`. This holds in both lab-off and lab-simulate modes.
  Modules synthesise telemetry and artifacts in dry-run instead of calling
  real primitives.

- **Telemetry is local-first.** No outbound SIEM exporters
  (Splunk HEC, OpenSearch, Elasticsearch, NGSIEM, generic HTTP bulk) ship
  in the baseline. Each run writes a JSON Lines artifact to
  `output/<run_id>/telemetry.jsonl`. Legacy `telemetry.sinks` config
  entries naming any of those remote types are warned-and-ignored at load
  time so old configs do not crash and do not silently regain network
  egress.

- **Artifact writes are constrained to the run output directory.**
  `tests/test_module_artifact_paths.py` parametrizes over every module and
  asserts that no new files appear outside `context["output_dir"]` after
  `execute()` returns, and that every artifact-referenced on-disk path
  resolves under that directory.

- **Module results conform to a single contract.**
  `tests/test_module_contract.py` parametrizes over every module and
  asserts the result is a `ModuleResult` with correct types and a status
  from `success | failure | blocked | skipped | partial_success`. A
  registry-level test asserts no duplicate names and that
  `instance.name == registry_key`.

- **Allowed-subnet and runtime controls** (`general.safeties.allowed_subnets`,
  `general.safeties.max_runtime`) are honoured by the orchestrator's
  `SafetyGate` before module dispatch.

- **Legacy capability packs are disabled by default.** Actor / C2 / stealth
  packs require either:
  - the master lab toggle (`modules.legacy.enable_all_lab_capabilities: true`
    plus `lab_confirmation: true`), or
  - per-pack and per-capability enablement in `config.yaml`.
  `simulate` mode is the default for any enabled legacy capability;
  `emulate` requires explicit `lab_confirmation: true` at the pack or
  capability level.

- **Destructive behaviour requires explicit acknowledgment.** For example,
  the exfiltration module rejects `destructive=true` unless the same call
  also passes `i_understand_this_is_a_lab=true`.

- **Real `ExecutionModule` invocations require `dry_run=False` AND
  `allow_real_execution=true`.** Both must be set explicitly; either
  default leaves execution simulated.

- **AI providers are opt-in** and require user-supplied configuration.
  No API keys are bundled in source. The default `template` provider is
  fully offline.

- **Optional remote integrations are explicit opt-ins.** No remote
  observability collector is present in the baseline. (See
  `docs/ARCHITECTURE.md` for the future-roadmap notes; nothing in that
  section is currently active code.)

## Reporting a vulnerability

Use GitHub security advisories (preferred) or open an issue with minimal
exploit detail. Please include:

- affected file path(s),
- commit hash or branch,
- reproduction steps,
- impact,
- suggested fix (if available).

Do not include live credentials or sensitive customer data in reports.

## Secure development controls

CI and local hooks enforce:

- `ruff`, `black --check`, `mypy`,
- `bandit` (medium-and-higher; tuned for a dual-use adversary-emulation
  repo with narrow `nosec` justifications instead of mass exclusions),
- `pip-audit`,
- secret detection via `gitleaks` and `detect-secrets`. Secret scanners
  run **before** Bandit so expected dual-use offensive-code findings cannot
  fail the workflow before secret scanning is checked.

## Sensitive data handling

- Keep secrets in `.env` (never commit it).
- Use `.env.example` for variable names only.
- Do not commit customer identifiers, internal hostnames, private IP
  inventories, or personal data.

## Contact

Open a GitHub Security Advisory or an issue tagged `security`.

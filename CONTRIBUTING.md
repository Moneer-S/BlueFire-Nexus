# Contributing to BlueFire-Nexus

Thank you for your interest in contributing. This document covers
the local development loop, the test gates every PR has to pass,
and the code-style choices the project enforces.

If you are reporting a security issue, please follow
[`SECURITY.md`](SECURITY.md) instead — do not open a public issue.

## Code of Conduct

By participating you agree to abide by
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/<your-fork>/BlueFire-Nexus.git
cd BlueFire-Nexus
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
cp .env.example .env
```

Run the canonical scenario to verify the install:

```bash
python -m src.run_scenario --profile apt29_credential_access --output-json
```

Output lands under `output/<run_id>/`; open `index.html` with
`file://` to see the static dashboard.

## CI gates

Every PR must pass these locally before review:

```bash
python -m pytest tests/                  # 1300+ tests, ~3 min wallclock
python -m bandit -r src -ll              # 0 medium / 0 high
python -m compileall -q src tests        # clean

# Lint + format
ruff check src tests
black --check src tests
```

Type-checking with `mypy` is configured in `pyproject.toml` but
not yet a CI gate; running it locally is encouraged when changing
public interfaces.

## Code style

- **Formatter:** `black` (line length 100).
- **Linter:** `ruff` (rules `E`, `F`, `I`, `W`, `B`).
- **Comments / docstrings:** focus on *why* and on subtle
  invariants. Don't restate what well-named identifiers already
  say.
- **No mass-formatting commits.** Reformat as part of the
  change you are making.
- **Bandit:** dual-use offensive code paths carry narrow
  per-line `# nosec BXXX — <reason>` justifications. New
  unjustified findings will fail review.

## Testing

- New behaviour must come with tests. Pin invariants, not
  implementation details.
- Tests must not require network access, real API keys, or
  external services. Provider tests use mocked HTTP transports.
- Tests must not pollute the project's `output/` directory.
  The pytest conftest scopes runs to a session tmp dir via
  `BLUEFIRE_OUTPUT_ROOT`.
- Three registry-wide tests run on every module:
  - [`tests/test_module_contract.py`](tests/test_module_contract.py)
    — every module returns a conformant `ModuleResult`.
  - [`tests/test_module_safety.py`](tests/test_module_safety.py)
    — no module invokes `subprocess` / `socket` / `requests` /
    `urllib` while `dry_run=True`.
  - [`tests/test_module_artifact_paths.py`](tests/test_module_artifact_paths.py)
    — every module writes only under `context["output_dir"]`.

## Pull request workflow

```bash
git checkout -b feat/<short-name>
# ... commits ...
git push -u origin feat/<short-name>
gh pr create --title "..." --body "..."
```

PR guidelines:

- One coherent change per PR. Easier to review, easier to revert.
- Title format: `feat(<area>): ...`, `fix(<area>): ...`,
  `chore: ...`, `docs: ...`, `test(<area>): ...`.
- Update the relevant `docs/reports/*.md` snapshot if the change
  shifts a documented invariant.
- Don't touch `CHANGELOG.md` — it is updated at release-tag time.
- Don't commit `.local/`, `.claude/`, or any private process
  notes.

## Adding a new standard module

The standard module set lives in
[`src/core/modules/impl/standard_modules.py`](src/core/modules/impl/standard_modules.py).
A new module needs:

1. A class subclassing `BaseModule` with a unique `name`,
   advertised `attack_techniques`, and an `execute(params,
   context)` returning a `ModuleResult`.
2. A profile catalogue entry mapping operator-facing values to
   MITRE techniques, logsources, and detection-selection fields.
3. Registry entry in `src/core/modules/registry.py`.
4. Per-module tests covering the technique surface, telemetry
   shape, and detection-hint shape.
5. Entry in [`docs/reports/capability_inventory.md`](docs/reports/capability_inventory.md).

## Adding a new legacy adapter

Mirror the pattern in
[`src/core/modules/impl/legacy_packs.py`](src/core/modules/impl/legacy_packs.py):
gate via `evaluate_legacy_capability` + `_ensure_allowed`, route
through `safe_call`, and ship simulate-mode tradecraft notes that
are meaningfully richer than the standard module's profile.

Add a parametrised test file matching the sibling adapter style
(`test_legacy_<tactic>.py`).

## Release process

Maintainers tag a release after an end-of-phase milestone:

1. Refresh the `## [Unreleased]` section in `CHANGELOG.md` and
   move it under a new `## [x.y.z] - YYYY-MM-DD` header.
2. Bump `version` in `pyproject.toml`.
3. `git tag vX.Y.Z` + push.
4. GitHub Actions workflows run on the tag.

External tooling (Sphinx docs, PyPI publish, Discord server
links) referenced in older versions of this document is not
currently set up; remove that expectation if you encountered it.

## Getting help

- Check [`docs/USAGE_GUIDELINES.md`](docs/USAGE_GUIDELINES.md)
  first — it covers the operator-facing CLI surface.
- Architecture, mode model, and the `ModuleResult` contract live
  in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- Reports under `docs/reports/` cover capability inventory,
  scenario coverage, AI layer, and the project roadmap.
- Open a GitHub issue for bugs and questions; use a security
  advisory for security-sensitive reports.

## License

By contributing, you agree that your contributions will be
licensed under the project's [MIT License](LICENSE).

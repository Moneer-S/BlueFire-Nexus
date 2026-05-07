# Release-readiness audit

A snapshot of the repo's release-readiness against the canonical
checklist (package metadata, CHANGELOG, license / security /
contributing surfaces, doc links, status snapshot, hygiene). The
audit is intentionally conservative: it surfaces the choices a
maintainer would need to make before tagging a release, but it
deliberately does not create any tag — tagging is a maintainer
decision, not an automated one.

## 1. Snapshot at audit time

| Field | Value |
|---|---|
| Audit date | 2026-05-07 |
| Latest main SHA | `511bd5c` (PR #85 merged) |
| Latest commit | `feat(reporting): pure-CSS mini-charts in the static run viewer` |
| Test suite | 1436 passed, 5 skipped, 0 failed (~85s wallclock on this audit) |
| Bandit | 0 medium, 0 high |
| compileall | clean |
| Python required | `>=3.10` (pyproject.toml line 18) |

## 2. Package metadata (pyproject.toml)

- **`name = "bluefire-nexus"`** — distribution name; matches the
  README and PyPI conventions.
- **`version = "2.0.0"`** — declared version. **Out of sync** with
  the latest existing git tag (`v2.8.0`) and with the codebase's
  current state. See § 6 below for the recommended bump.
- `requires-python = ">=3.10"` — matches the readme badge.
- `dependencies = [...]` — 28 runtime deps, all version-pinned with
  lower bounds. No upper-bound caps (consistent with the project's
  dual-use research lens; major-version pins would create
  install friction without buying much safety).
- `optional-dependencies` — three coherent extras:
  - `[net]` — `netifaces` (legacy network discovery; gated out of
    the default install because its sdist needs a C compiler).
  - `[ai]` — `openai`, `anthropic`, `google-generativeai` (only
    needed when the operator opts into a vendor-specific AI
    backend; the shipped `template`/`offline` provider has no
    runtime dependency on any of them).
  - `[vector]` — `chromadb` (RAG path).
- `tool.pytest.ini_options.addopts = "-q"` — fast quiet runs.
- `tool.bandit.exclude_dirs = ["tests", "archive"]` and
  `skips = ["B101"]` — both reasonable for the project's
  defence-research scope.

**Action recommended**: bump `version` to whatever the maintainer
chooses for the next release tag (see § 6).

## 3. CHANGELOG.md

- `[Unreleased]` section is **accurate and up to date**: it
  enumerates every meaningful change since the prior release era,
  organised under `Added` / `Changed` / `Security`. The bullets
  match what is on disk today (local viewer, run aggregator,
  mini-charts, provider-agnostic AI layer, four step-to-step
  propagation pairs, simple-mode presets).
- Two historical entries (`[1.0.0] - 2024-03-20` and `[0.1.0] -
  2024-03-01`) document a prior release lineage. They predate
  the current state of the codebase and the only existing git
  version tag (`v2.8.0`) — the lineage was never tagged in git.
  Keeping the entries is fine for context; the maintainer may
  also choose to consolidate them under a single "Pre-2.8.0
  history" heading if the dual-existing semver lineage causes
  confusion at release time.

**Action recommended**: when cutting the next release, move the
`[Unreleased]` block under a dated version heading and start a new
empty `[Unreleased]` section.

## 4. LICENSE / SECURITY / CONTRIBUTING

| File | Status | Notes |
|---|---|---|
| `LICENSE` | present | MIT (5.7 KB). |
| `SECURITY.md` | present | Disclosure flow + contact (5.4 KB). Reachable from `README.md`. |
| `CONTRIBUTING.md` | present | Reflects actual tooling (`ruff`, `black`, `mypy`, `pytest`, `bandit`); tells contributors not to commit `.local/` or `.claude/`. |

All three files are referenced from `README.md` via working
relative links.

## 5. README.md

- **First-impression block**: badges (tests, security, python,
  license), value proposition, three-paragraph "Why this exists",
  "What it does" feature list, "Current baseline" hard
  constraints.
- **Quickstart**: 4-step end-to-end walkthrough (clone+install /
  run / inspect / open) with explicit Linux / macOS / Windows
  variants for the file-open command. Verified end-to-end via
  `tests/test_quickstart_smoke.py` (10 subprocess-driven smoke
  tests).
- **Limitations & scope**: present at line 260+. Documents
  single-host execution, no live destructive behaviour by
  default, opt-in AI providers, gated emulate, dual-use intent,
  static-not-live dashboard.
- **Status snapshot**: test count surfaced as `1436 passing
  tests` — currently up to date with the actual test count.
- **Doc links** (validated against the working tree at audit
  time): every internal link in README resolves to an existing
  file (`docs/USAGE_GUIDELINES.md`, `docs/ARCHITECTURE.md`,
  `tests/test_module_safety.py`, `tests/test_module_artifact_paths.py`,
  `SECURITY.md`, `docs/case-studies/`, `docs/reports/ai_layer.md`,
  `docs/reports/next_roadmap.md`,
  `docs/reports/capability_inventory.md`,
  `docs/reports/scenario_validation.md`,
  `docs/reports/orphan_files.md`, `tests/test_module_contract.py`,
  `.github/workflows/tests.yml`, `.github/workflows/analysis.yml`,
  `LICENSE`).

## 6. Hygiene

- `git ls-files .local/ .claude/` → empty. Both directories are
  excluded via `.git/info/exclude` (which is a local-only
  file, not committed) so each clone has to opt in to that
  exclusion separately. **For release-tag readiness**: this is
  fine for the maintainer's box, but a secondary contributor
  cloning the repo will not get the exclusion automatically —
  consider promoting `.local/` and `.claude/` to `.gitignore`
  before tagging if the project plans to onboard external
  contributors. (The project is single-maintainer today, so
  this is "future quality of life" rather than a blocker.)
- No private process notes were found in committed files: the
  matches for "claude" / "copilot" / "agent" all describe the
  *AI copilot feature* (vendor names, alias maps, the `template`
  default) — not internal workflow language.
- No leftover `TODO` / `FIXME` / `XXX` / `HACK` markers in any
  public doc.

## 7. Recommended tag for the next release

The latest git tag is `v2.8.0`; the working tree is several months
of work past it (>50 commits). The `pyproject.toml` declares
`version = "2.0.0"`, which is below the latest tag — an artefact
of the project's stabilisation pass. Three reasonable options:

1. **`v3.0.0-rc1`** *(recommended)*. A release candidate for a
   new major version. Signals to anyone with a `v2.x` install
   that the artifact contract / module registry / safety model
   have all been re-architected. Lets the maintainer ship
   patch-level RCs (`-rc2`, `-rc3`) until the demo is fully
   validated against external feedback. Pair with
   `version = "3.0.0rc1"` in pyproject.toml (PEP 440 form).
2. **`v3.0.0`**. A bare major release. Reasonable if the
   maintainer is confident in the demo bundle and the
   dual-use safety story. Pair with `version = "3.0.0"`.
3. **`v2.9.0`**. Continues semver from `v2.8.0`. Defensible if
   the project's API contract is broadly compatible with
   `v2.8.0`. Re-reading the changelog `[Unreleased]` block,
   the structural shifts (provider-agnostic AI, manifest
   schema, viewer, aggregator) are net-additive, so this is
   plausible — but the backwards-compat surface is non-trivial
   to verify and `v3.0.0-rc1` is the more honest framing.

A `v0.x` tag (as a "fresh start" framing) is **not recommended**:
the CHANGELOG already references `[1.0.0]` and `[0.1.0]` from
the prior lineage, and creating a `v0.x` git tag after a `v2.8.0`
git tag would be confusing to anyone reading
`git tag --list --sort=-v:refname`.

### When the maintainer cuts a tag

The recommended sequence:

1. Pick a version (likely `v3.0.0-rc1` per § 7).
2. Bump `pyproject.toml` `version` to the matching string.
3. In `CHANGELOG.md`, replace `## [Unreleased]` with
   `## [3.0.0-rc1] - YYYY-MM-DD` and start a new empty
   `## [Unreleased]` block above it.
4. Run the full validation sweep (`pytest tests/` + `bandit -r
   src -ll` + `compileall -q src tests`) and confirm all-green.
5. `git tag -a v3.0.0-rc1 -m "..."` and push.
6. Optionally: `gh release create` with the changelog block as
   the body.

## 8. Items deliberately not blocked on this audit

- **Top-level `output/index.html` aggregator** — landed in PR #84.
- **Pure-CSS viewer mini-charts** — landed in PR #85.
- **First-impression README polish** — landed in PR #83.

These were the open release-candidate polish items from the
prior backlog. They are now all merged.

## 9. Items the maintainer may still want to address

- **Promote `.local/` and `.claude/` to `.gitignore`** before
  external contributors join, so each clone gets the exclusion
  automatically.
- **Generate a screenshot or sample artifact bundle** for the
  README — currently the dashboard layout is described in text.
  See the next-roadmap entry for the screenshot decision; the
  short answer is "either no binary assets and good prose, or
  a single sanitised PNG of a sample run".

---

The audit was generated against `511bd5c`. Re-run before any
tag-cutting session to make sure the snapshot is still current.

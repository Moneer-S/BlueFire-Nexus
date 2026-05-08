# Release-readiness audit

A snapshot of the repo's release-readiness against the canonical
checklist (package metadata, CHANGELOG, license / security /
contributing surfaces, doc links, status snapshot, hygiene). The
audit is intentionally conservative: it surfaces the choices a
maintainer would need to make before tagging a release, but it
deliberately does not create any tag — tagging is a maintainer
decision, not an automated one.

> **Status**: `v3.0.0-rc1` was published as a GitHub prerelease
> on 2026-05-07. The stale draft `v3.0.0` release was deleted.
> The audit body below reflects the **pre-rc1 cut** snapshot at
> commit `511bd5c`; § 8 ("Post-rc1 status & path to v3.0.0")
> below tracks what's happened since and what would trigger an
> rc2 vs. a bare `v3.0.0`.

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
| **Post-rc1 status** | See § 8 for current main / test count / open items. |

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

The audit body above was generated against `511bd5c`. The
post-rc1 status block below is appended on every meaningful
update; re-read both before any new tag-cutting session.

## 8. Post-rc1 status & path to v3.0.0

### 8.1 What was published

| Field | Value |
|---|---|
| Tag | `v3.0.0-rc1` (annotated) |
| Tagged commit | `0fa8d72` |
| Annotated tag SHA | `53508898` |
| GitHub release | Prerelease at <https://github.com/Moneer-S/BlueFire-Nexus/releases/tag/v3.0.0-rc1> |
| GitHub "Latest" label | `v2.8.0` (a prerelease does not displace a published Latest) |
| Stale `v3.0.0` draft | **Deleted** (had 2025-04-01 notes referencing removed Splunk/Elastic features) |

### 8.2 What was validated at the rc1 cut

- Full pytest sweep: green at every commit.
- `bandit -r src -ll`: 0 medium / 0 high across every PR.
- `compileall -q src tests`: clean.
- End-to-end smoke against `apt29_credential_access`: zero
  filenames with `:`, YARA-L meta carries real run id, SPL
  carries `DRAFT detection search` header (not metadata-echo
  only), `validate-run --json` returns `ok=true`, CLI output
  free of replacement char `?`, `file://` URI on a standalone
  line, copilot narrative carries scenario name + step-by-step
  timeline + run-specific paths under `output/<run_id>/`.

### 8.3 Pre-rc1 polish PRs (in order of merge)

| PR | Title | Merge SHA |
|---|---|---|
| #92 | docs(readme): make .env copy step optional in quickstart | `2c32a91` |
| #91 | fix(cli): Windows polish — em-dash mojibake + URL on own line | `6c58e11` |
| #93 | feat(ai): enrich TemplateProvider with intent-aware run-summary rendering | `5cf386a` |
| #89 | fix(detections): YARA-L run_id + upgrade SPL from metadata echo | `33e5ead` |
| #94 | fix(detections): cross-platform-safe filenames (`:` → `__`) | `2c8c068` |
| #88 | release(v3.0.0-rc1): version bump + CHANGELOG release-candidate cut | `0fa8d72` |

### 8.4 Post-rc1 hardening PRs (post-tag, in order of merge)

Tracks any change merged AFTER the `v3.0.0-rc1` tag but BEFORE
the next release tag. Each row should list the PR + its merge
SHA + a one-line rationale.

| PR | Title | Merge SHA | Rationale |
|---|---|---|---|
| #95 | docs: post-rc1 consistency audit — README rc1 callout + CHANGELOG cleanup | `3efed73` | Surface rc1 release at the top of the README; remove a stale "53 PRs" reference. |
| #96 | feat(release): maintainer-facing rc smoke script + pytest regression wrapper | `f30ca88` | `scripts/smoke_release_candidate.py` runs the canonical operator path end-to-end and re-asserts every rc1-polish invariant; pytest wrapper makes the same checks part of regular CI. |
| #97 | feat(reporting): static dashboard quality polish (header severity, draft maturity, local-only promise) | `e60e91a` | Header severity badge, detection-drafts maturity caveat, "static page" promise inline in the header card of both viewer and aggregator. |
| #98 | test(detections): end-to-end detection-output regression invariants | `e3c1fb3` | Walks the entire generated artifact tree to assert cross-engine consistency, NTFS filename safety, no manual run_id leak, no metadata-echo SPL, manifest <-> on-disk consistency. |
| #118 | feat(scenario): sharpen flagship step names + scenario objective for SOC narrative | `e465eba` | Loop F first wave — every step's defender-facing `name` rewritten as a chain narrative beat; scenario `objective:` paragraph rewritten as the chain story; new tests pin narrative-quality invariants (every step name ≥12 chars, contains a space, not equal to slug). Step IDs and propagation matrix byte-identical. |
| #119 | feat(viewer,manifest): surface scenario objective + propagation narrative | `86fef06` | Loop F second wave — manifest gains `run.scenario_objective` plus per-edge `from_module` and `narrative`; viewer renders the scenario objective in the dashboard header (paragraph-aware) and adds a `narrative` column to the propagation table. Templates use module-agnostic `"produced by"` so the prose reads correctly across upstream modules. |
| #120 | feat(reporting): surface scenario objective + propagation narrative in report.md | `f0b8aa7` | Loop F third wave — `report.md` gains `## Scenario objective` and `## Propagation narrative` sections (above Module Results) so the markdown report tells the same chain story as the dashboard. New public helper `compute_propagation_edges` so the report writer consumes the same canonical edge list the manifest builder produces. |
| #121 | feat(copilot): ground offline narrative artifact in scenario objective | `432f07e` | Loop F fourth wave — `summarise_run_state` accepts `scenario_objective` (capped at 1000 chars to bound prompt budget); the offline `copilot_narrative.md` body and YAML metadata header now lead with the chain story. Closes the narrative loop on the AI surface. |
| #122 | docs: refresh README + status snapshot + Loop F batch entries (test count 2094 → 2127) | TBD | Pure docs PR. README test count badge bump and chain-narrative bullet; next_roadmap.md gains a Loop F entry; release_readiness.md §8.4 records #118-#121. |

### 8.5 What would trigger an rc2 (vs. wait)

Cut **rc2** when ANY of the following lands after rc1:

- A real P1 / P2 bug surfaced by external operators against the
  rc1 build (e.g. fresh-clone smoke fails on a documented OS,
  data leak, regression in a documented contract).
- A behaviour change that adds public surface (new CLI command,
  new manifest field, new artifact type, new safety gate) — the
  rebuilt baseline is at major-version 3, so additive surface
  should ride a new `-rcN` rather than a silent main-branch
  shift.
- A capability addition the maintainer wants soaked-tested by
  external operators before final.
- A breaking-change fix (rare; rc1 already broke compat with
  v2.8.0, but a *further* break vs. rc1 would force rc2).

**Do NOT** cut rc2 for:

- Pure docs touch-ups that don't change anyone's mental model.
- Internal test additions (no behaviour change).
- Refactors with identical observable behaviour.

### 8.6 What would block a final v3.0.0

The maintainer should not cut bare `v3.0.0` until:

- ✅ rc1 has soaked for **at least one realistic external user
  pass** (fresh clone on a target OS, run the canonical
  scenario, exercise the CLI, open the dashboard).
- ✅ All rc1-polish PRs (#89/#91/#92/#93/#94) merged into main
  (done at `0fa8d72`).
- ✅ Public release notes match the actual release shape (CHANGELOG
  `[3.0.0-rc1]` block consolidated; rc2 would need the same
  treatment).
- 🟡 Codex / Bugbot review on every release-candidate PR
  surfaces no real P1 / P2 finding the maintainer hasn't
  acknowledged in writing.
- 🟡 No open GitHub issues labelled `rc-blocker` / `release-
  blocker` (none currently; this is a forward guard).

### 8.7 Recommended cut sequence (when ready)

For an `-rcN` (rc2 / rc3 / ...):

1. Merge any pending rc-polish PRs into main.
2. Run `python scripts/smoke_release_candidate.py` (added in
   PR #96). Expect 16/16 checks pass.
3. Run the full validation gate:
   ```
   python -m pytest tests/
   python -m bandit -r src -ll
   python -m compileall -q src tests
   ```
4. Bump `pyproject.toml` `version` to `3.0.0rcN`.
5. Move CHANGELOG `[Unreleased]` content under `## [3.0.0-rcN] -
   YYYY-MM-DD` (or extend the existing `[3.0.0-rc1]` block with
   a "Pre-rc2 changes" subsection — pick one shape and stay
   consistent).
6. Open the version-bump PR; request `@codex review`.
7. After merge: tag and push.
   ```
   git tag -a v3.0.0-rcN -m "v3.0.0-rcN: ..."
   git push origin v3.0.0-rcN
   gh release create v3.0.0-rcN --prerelease --notes-file <notes>
   ```

For the bare `v3.0.0` (final):

1-3. Same gates as the rcN cut, plus § 8.6 acceptance.
4. Bump `pyproject.toml` `version` to `3.0.0`.
5. Move the latest `[3.0.0-rcN]` CHANGELOG block under
   `## [3.0.0] - YYYY-MM-DD` (collapse rc-only intermediate
   blocks if the maintainer wants).
6. Open the cut PR.
7. After merge: tag, push, and create a NON-prerelease GitHub
   release (`gh release create v3.0.0 --notes-file <notes>` —
   note no `--prerelease`). This will displace `v2.8.0` as
   "Latest".

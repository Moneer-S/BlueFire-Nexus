# BlueFire Nexus — autonomous-work changelog

Running per-PR log of autonomous-mode work. Newest first. Each entry names
the PR, the merge commit on `main`, and a one-line description of what the
PR delivered. Intended as a quick "what changed and why" alongside `git log`.

## 2026-05-05

- **#13 (`48b7524`) — `feat/missing-tactics-batch`**: Bundled
  `lateral_movement` (8-entry catalog), `privilege_escalation` (9),
  `impact` (10), and `collection` (10) into one PR after the
  individually-staged PRs #9/#10/#11/#12 conflicted on the same insertion
  points in `standard_modules.py` and `test_module_contract.py`. Combined
  with #8 (credential_access), all five missing ATT&CK-tactic modules from
  `next_roadmap.md` item 1 are now on main. Registry: 21 → 25 modules.
  +80 tests. Closed PRs #9/#10/#11/#12 with rationale (branches retained).
- **#8 (`7d2d127`) — `feat/credential-access-module`**: New
  `CredentialAccessModule` registered in `BUILTIN_MODULE_CLASSES`. 9-entry
  technique catalog (lsass_dump / sam_dump / ntds_dump / browser_credentials
  / keychain / ssh_keys / keylogging / clipboard / screen_capture). +17
  focused tests in `tests/test_credential_access_module.py`. First of the
  five missing ATT&CK-tactic modules from the roadmap. Legacy
  `src/core/credential/credential_access.py` preserved unchanged for
  emulate-mode follow-up.
- **#7 (`fdb3cfd`) — `docs/readme-positioning-overhaul`**: Rewrote `README.md` as a
  high-fidelity adversary-emulation pitch (hero / why / what / baseline /
  quickstart / example output / core concepts / modes & safety / legacy
  packs / AI layer / dev & tests / roadmap). Moved CLI command lists to
  `docs/USAGE_GUIDELINES.md`. Initialized this work log. Added the
  contributor-attribution audit findings to `docs/reports/contributor_audit.md`.
  No code changes.

## 2026-05-05 (pre-autonomous-cycle: prior PRs that informed this log)

- **#6 (`65a105d`) — `feat/discovery-type-fanout`**: `DiscoveryModule`
  fans out telemetry / hints by `discovery_type` (10 catalog entries:
  network_scan / host_discovery / port_scan / service_scan / system_info /
  process_info / service_info / user_info / group_info / files), honors
  `network_touch=False` as planning-only path, expands `attack_techniques`
  to 8 MITRE IDs. +18 behavior tests in `tests/test_discovery_module.py`.
- **#5 (`bb3b801`) — `reports/capability-scenario-ai-audit`**: Added
  `docs/reports/{capability_inventory,next_roadmap,scenario_validation,ai_operator_audit}.md`.
  Docs only; no code changes.
- **#4 (`c0b0669`) — `harden/bandit-strict-and-artifact-mtime`**: 14
  narrow per-line `# nosec BXXX – <reason>` annotations across 11 source
  files; removed `--exit-zero` from the Bandit workflow step (Bandit now
  fails CI on any new unjustified finding); `tests/test_module_artifact_paths.py`
  uses an mtime cutoff so pre-existing `output/` files don't pollute the
  test snapshot. Verified strictness with a probe.
- **#3 — `cursor/core-package-coherence-89b7`**: Closed with rationale.
  Branch retained per directive.
- **#2 (`c860a61` Phase 9 squash) — `cursor/defense-evasion-packages-89b7`**:
  Branch deleted post-merge per the approved limited cleanup.
- **Phase 9 squash (`c860a61`) — `cursor/overhaul-89b7`**: 11-commit
  integration trunk squash-merged to main as "Stabilize BlueFire Nexus
  baseline". Recovery tag `stable-baseline-2026-05-04` cut at the
  pre-squash tip.

## Conventions

- Each PR gets a single bullet here at merge time.
- Format: `- **#N (`<merge-sha>`) — `<branch>`**: <what + why in one or two lines>.`
- Sort newest-first within a date; dates newest-first.
- Contributor identity: commits are authored as `Moneer Shoukri`; agent-
  produced PRs no longer add `Co-authored-by` trailers (see
  `contributor_audit.md`).

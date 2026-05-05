# Contributor attribution audit

Snapshot at `main` = `65a105d` (post PR #4 / #5 / #6).

## Findings

- **Author identity is correct.** Every commit on `main` is authored as
  `Moneer Shoukri <128552943+Moneer-S@users.noreply.github.com>`. The
  local and global Git identity were already configured to the user; no
  agent commits were ever authored as Claude.
- **A `Co-authored-by` trailer was added to PR commit bodies during the
  stabilization cycle.** Specifically, `Co-authored-by: Claude Opus 4.7
  <noreply@anthropic.com>` appears in the squash-merge bodies of:
    - `c0b0669` — PR #4 (Bandit hardening + artifact-path mtime).
    - `bb3b801` — PR #5 (capability/scenario/AI audit reports).
    - `65a105d` — PR #6 (discovery `discovery_type` fan-out).
- The Phase 9 squash `c860a61` ("Stabilize BlueFire Nexus baseline") does
  **not** carry the trailer.
- The trailers do not affect commit author or push attribution; they are
  recognized by GitHub's contributor avatars on the merge commit page,
  which is why "Claude" shows up as a contributor.

## Why removing existing trailers is high-risk

Removing the `Co-authored-by` trailers from `c0b0669`, `bb3b801`, and
`65a105d` would require **rewriting `main`'s history** — either via
`git rebase -i` + `git push --force-with-lease`, or `git filter-repo`
across the three commits. Both are explicitly out of scope per the
operating rules: "Do not rewrite history. Do not force-push to main."

A cleaner non-destructive path is to leave history alone and stop adding
the trailer in **future** commits, so the contributor list stops growing.
The three existing trailers will fade out of the GitHub contributor
sidebar over time as new commits without the trailer accumulate.

## Recommended path (non-destructive, applied)

1. Confirmed local + global Git identity is `Moneer Shoukri`. No change
   needed.
2. Going forward, agent-produced commits **do not** include
   `Co-authored-by: Claude` trailers in their messages. This audit
   document is the first deliverable that adopts that policy; subsequent
   PRs in this autonomous cycle follow the same rule.
3. The autonomous-work changelog (`docs/reports/autonomous_work_log.md`)
   documents which PRs are agent-produced for transparency without
   altering Git's contributor metadata.

## Optional future cleanup (NOT performed)

If at some point a coordinated history cleanup is acceptable (e.g. before
a v3.0 release), the three trailer-bearing squash commits could be
rewritten in a single planned operation. That decision belongs to the
project owner and is out of scope for the autonomous mode operating today.

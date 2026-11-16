# Working in this repository

These notes apply to everyone who works here.

## Where work happens

New work goes in `lab/`. It is a test bench for defenders: it runs published
attack tests against a disposable lab target, records what the defenses on that
target saw, and shows what changes when a defense is changed.

The rest of the tree (`bluefire/`, `runner/`, `frontend/`, `tests_platform/`,
`tools/`) is the earlier product. It is being reduced. Do not add to it.

## Rules

1. **A result is real or it is labelled.** Real means the attack test ran on a
   lab target, a sensor on that target produced the telemetry, and a rule engine
   evaluated that telemetry. Fixtures, replays and mocks help development, and
   they are never presented as results. A claim in a document links to the CI
   run that shows it, or says "not yet shown".
2. **Attack tests run only on lab targets.** A lab target is a GitHub-hosted
   runner inside this repository's own workflows, or a disposable container
   whose name starts with `bluefire-lab-`, on a network named the same way.
   Never run an attack test on a developer machine itself, and never send test
   traffic to anything the lab did not create.
3. **Use published tests and tools, pinned.** Attack steps come from maintained
   public projects such as Atomic Red Team, pinned to a commit or version and
   recorded in `THIRD_PARTY_NOTICES.md`. Do not write new attack techniques.
   Detection rules, hardening changes, parsers and reports are ours to write.
4. **This repository is public.** Commits, pull requests, issues, comments, CI
   logs and CI artifacts can be read by anyone. Keep out secrets and details of
   any developer machine: user names, host names, local paths, addresses.
   Published evidence comes from CI runners only.
5. **Write for a stranger.** Commit messages, pull request text and documents
   say what the change does and how it was checked. Plain messages only: no
   trailers or footers, no status notes or to-do lists. Name a branch after the
   change, for example `lab/first-loop`.
6. **Keep it small.** The lab is a thin layer that joins existing tools. Before
   adding a module, look for a maintained tool that already does the job. A CI
   run on a clean runner is the proof: do not build machinery whose job is to
   hold or check proof. When a new way of doing something in `lab/` replaces an
   old one there, delete the old one in the same change: the next contributor
   copies the nearest example.

## Pull requests

- Open a pull request as a draft and keep it a draft while you work.
- Mark it ready once, when it is finished and CI is green. An automated reviewer
  reads the pull request at that moment. Do not switch back and forth between
  draft and ready.
- Treat each review finding as a claim to check. Fix real defects. Where you
  disagree, reply in a sentence or two with the reason.
- One idea per pull request. The description says what the change does, what it
  could break if anything, and how it was checked: the command or run, and its
  outcome.
- Push a batch of related commits, not one commit at a time. Every push to a
  pull request cancels the CI run that was still going.

## Checks

- The scan for private paths and the secret scans run on every pull request.
  Keep them running when other checks change.
- Do not skip, disable or loosen a check to make a failing change pass. Removing
  a check together with the code it guarded is a different thing, and fine.
  Checks for code that is being removed may be switched off ahead of the
  removal.
- When the same mistake happens twice, make it impossible: by design first, then
  a type, then a lint or CI check whose error names the fix, then a test. A rule
  in this file comes last, for judgment calls only. Add a check only for a
  mistake that really happened, and show that it fails on that mistake.
- A test checks behaviour that a user of the code can observe. Fix or delete a
  test that still passes when that behaviour breaks, or that fails when only the
  internals change, in a change of its own: never in the change that makes it
  fail.

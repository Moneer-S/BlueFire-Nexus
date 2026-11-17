# BlueFire Nexus

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what the sensors on that target saw, has a rule engine evaluate
pinned detection rules over those records, and reports two answers for every
test: did the technique take effect, and what did the defense see. Then it
changes a defense and runs the tests again, to show what the change did.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/report-dark.png">
  <img src="docs/report-light.png" width="1280" alt="The top of the report of run 44133154347: 60 published attack tests, all took effect; 3 raised an alert, 56 left telemetry but no alert, 1 left no telemetry; with the lab's own rules 17 raised an alert; 12 tests ran again with a hardening change, and 8 of those changes blocked the technique. Below it the run's facts and the first rows of the results table.">
</picture>

The top of the report of
[run 44133154347](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44133154347),
as that run's job pictured it. The whole report is in the run's artifact.

## What it shows today

Everything below comes from runs of the `lab` workflow on GitHub-hosted
runners, each linked. [`lab/README.md`](lab/README.md) gives the details, the
limits, and how each answer is computed.

In [run 44133154347](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44133154347),
the workflow's run on `main` of 17 November 2026, on an `ubuntu-24.04` runner
with kernel 7.0.0-1017-azure:

- **61 published tests** from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  for Linux are on the list. 60 ran, one at a time, through its own executor,
  with Sysmon for Linux and auditd recording; five of them with one input
  argument changed, for example to search only the test account's home
  instead of the whole disk. The runner has no `ccencrypt`, so the ccrypt test
  was left out, and the report says why. All 60 took effect.
- **What the defense saw:** with 188 pinned [SigmaHQ](https://github.com/SigmaHQ/sigma)
  rules, 3 tests raised an alert (a rule of level high or critical matched one
  of its events), 56 left telemetry that no rule of an alert level matched,
  and 1 left none: emptying the shell history with the shell's own `echo`.
  One of the 3 alerts comes from a rule for another technique that also
  matched ordinary work in the same run.
- **Detection rules of the lab's own:** 8 of its 9 rules are accepted: each
  still alerted when its tests ran again with changed input arguments, and
  none matched a baseline of ordinary administration or the runner's own work.
  With them, 17 of the 60 tests raise an alert. The rule for a systemd unit
  written by a shell, written for two tests, also catches three published
  procedures added later. Other procedures of the same techniques show where
  the rules stop, for example a search for TLS key files that the rule for a
  search for SSH keys does not describe.
- **Hardening:** 12 tests ran again with one of four hardening changes in
  place, such as `/tmp` mounted `noexec` or crontab limited by
  `/etc/cron.allow`. 8 of the 12 runs were blocked. The four others show what
  a change leaves open: a script in `/tmp` still runs through `bash`, root
  still puts a job into `/etc/cron.d`, and with `~/.bashrc` immutable the
  account's `~/.bash_profile` and `~/.profile` still take new lines.
- **Sensor changes:** with Sysmon alone, appending a command to `~/.bashrc`
  left no telemetry; with auditd watching the shell start files, it leaves a
  record that two pinned rules match
  ([run 44029759448](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44029759448)).
  With auditd recording process starts too, 18 of the 53 pinned auditd rules
  match something and two tests became alerts, among them turning ASLR off.
- **The target:** each run starts with an inventory of the runner (accounts
  that can log in, running services, listening addresses, the programs the
  tests need) and chooses the tests by it: here it left out the one test whose
  program the runner lacks.
- **Before and after:** every run is compared with the latest run on `main`.
  When 12 tests were added,
  [the comparison](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44133154347/job/134224713568)
  found the 74 runs of the earlier list with the same answers, and 17 new ones.
- **Seven controls** on the measurement passed: the sensors were ready before
  the first test, every test's markers were recorded, every hardening change
  was removed again, no sensor lost a record, the rule engine read every rule
  and event, a test the pinned rules are known to catch raised its alert first
  and last, and a harmless command raised none. A run in which a control fails
  is reported as failed.

## Run it

The attack tests run only on GitHub-hosted runners, which GitHub throws away
after each job. The `lab` workflow runs on pull requests and pushes to `main`
that change `lab/`, once a week, and by hand from the Actions tab of this
repository or of a fork. Its run page shows the table of answers and how they differ from the
latest run on `main`, and its artifact `lab-run` holds the sensors' raw output,
the results and the report.

The answers can be computed again from a run's artifact, on any machine with
Python 3.10 or newer and [Zircolite](https://github.com/wagga40/Zircolite)
4.7.1:

```bash
pip install ./lab
bluefire-lab evaluate <folder of the unpacked artifact> --engine <path to Zircolite>
bluefire-lab report <folder of the unpacked artifact>
bluefire-lab compare <folder of an earlier run> <folder of a later run>
```

## Not yet shown

- Tests on Windows.
- Attack chains of several steps, and an attacker the bench does not control.
- A lab on your own machine, in containers, with a one-step install and an
  interface.
- The product asking a model to draft a detection rule or a hardening change
  for a gap, and checking the draft on a run before it accepts it.

## Earlier versions

Until November 2026 this repository held an earlier product, which the lab
replaces. It stays in the git history, for example at the tag `v3.0.0-rc2` and
its release.

## License

MIT, see [LICENSE](LICENSE). The lab fetches third-party tools and content at
run time and copies none of them here: see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Security reports:
[SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

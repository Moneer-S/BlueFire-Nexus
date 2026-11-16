# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what the sensors on that target saw and which detection rules
fired, and reports both plainly.

## What is shown today

Nothing yet. No attack test has run.

The first step is a spike that tries sensors on a GitHub-hosted runner, with
harmless probe commands only: the `spike-*` jobs of
[`.github/workflows/lab.yml`](../.github/workflows/lab.yml). Its findings will
be written here, each with a link to the run that shows it.

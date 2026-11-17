# Security policy

## What the lab does, and where

The lab runs published attack tests, unchanged, from Atomic Red Team. It runs
them only on lab targets: GitHub-hosted runners inside this repository's own
workflows, which GitHub throws away after each job. `bluefire-lab run` refuses
to start unless `RUNNER_ENVIRONMENT` is `github-hosted`, which GitHub sets on
its own runners. That guards against starting it by mistake on another
machine; it cannot stop someone who sets the variable on purpose. Do not run
the attack tests on a machine you care about.

The tests run one at a time, as an unprivileged account whose outbound traffic
and name lookups are rejected, unless a test declares that it needs root. The
list leaves out tests that read other processes' memory or environment, search
the file system for secrets, contact other hosts, send data out, reboot, or
change the firewall or the network. The lab jobs hold no secrets and a
read-only token, and a step refuses to upload a run whose files contain the
job's token.

Everything a run records is published as a CI artifact: the sensors' raw
output, the results and the report. Do not point the workflow at anything
whose telemetry you would not publish.

## Reporting a vulnerability

Use a private GitHub security advisory on this repository. If that is not
available to you, open an issue that asks for a private channel, without the
details.

Include the file and commit, what you expected and what happened, and the
smallest way to reproduce it. Never include credentials or anything about a
system you are not allowed to test.

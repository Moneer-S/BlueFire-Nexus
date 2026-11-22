# Security policy

## What the lab does, and where

The lab runs pinned Atomic Red Team test definitions on disposable
GitHub-hosted runners. Some tests use different input arguments to limit their
scope. GitHub discards the runner after each job. `bluefire-lab run` refuses
to start unless `RUNNER_ENVIRONMENT` is `github-hosted`, which GitHub sets on
its own runners. That guards against starting it by mistake on another
machine; it cannot stop someone who sets the variable on purpose. Do not run
the attack tests on a machine you care about.

The tests run one at a time. The unprivileged test account has outbound traffic
and name lookups blocked. Tests that declare a need for elevated privileges run
as root. The workflow can also install a test's prerequisites as root.

Credential-access tests use files planted in the test account's home,
including sample shell history and dummy key files. The list excludes tests
that search the whole disk for credentials, read other processes' memory or
environment, contact other hosts, send data out, reboot, or change the network
or firewall.

The workflow uses a read-only job token. Before uploading the artifact it
checks the run files for that token and its encoded Git credential.

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

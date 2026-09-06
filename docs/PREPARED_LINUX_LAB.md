# Prepared Linux lab

This Windows-hosted setup prepares a disposable WSL2 clone for the ordinary BlueFire UI and
CLI. It does not install a new runner service, approve experiments, execute a scenario, or run
release acceptance. The supported prepared boundary is Linux x86_64 on WSL2 with CPython 3.12;
this is not a general Linux installer or proof for arbitrary Linux hosts.

The launcher is included in the product package:

```powershell
python -m bluefire.prepared_lab --help
```

## Prepare the prerequisites

Use a Windows installation of the matching BlueFire version, WSL2, an independently obtained
Linux x86_64 BlueFire wheel, and its offline dependency wheels. A Windows wheel cannot supply
the Linux runner. The Linux wheel must include `bluefire.prepared_lab_guest` and a Linux native
runner manifest; the ordinary `runner bootstrap` command later performs native artifact checks.
Keep and verify your downloaded wheel hashes according to your software-distribution policy.

The launcher uses the existing distribution ownership manager and its dedicated base name,
`BlueFire-Gate11-Base-v1`. It only reads/exports that base. It never modifies, terminates, or
unregisters it. Create this base explicitly once, with no personal files, credentials, mounted
shares, extra services, or user accounts. UID/GID 1000 and the name `bluefire` must be unused.
The clone preparation refuses an existing account rather than repurposing one.

Obtain and verify an Ubuntu 24.04 x86_64 root filesystem using
[Ubuntu's documented WSL image process](https://documentation.ubuntu.com/wsl/latest/howto/custom-ubuntu-distro/).
Use its verified rootfs tar as `ubuntu-rootfs.tar` below. Microsoft documents
[tar imports and their root default](https://learn.microsoft.com/en-us/windows/wsl/use-custom-distro).
Choose a new, local base storage directory, then run:

```powershell
$BaseStorage = Join-Path $env:LOCALAPPDATA 'BlueFire\Base-v1'
wsl.exe --import BlueFire-Gate11-Base-v1 $BaseStorage .\ubuntu-rootfs.tar --version 2
wsl.exe --distribution BlueFire-Gate11-Base-v1 --user root --exec /usr/bin/apt-get update
wsl.exe --distribution BlueFire-Gate11-Base-v1 --user root --exec /usr/bin/apt-get install --yes python3.12 python3.12-venv util-linux mount iproute2 passwd
wsl.exe --distribution BlueFire-Gate11-Base-v1 --user root --exec /usr/bin/python3 -I -c "import sys,pwd,grp; assert sys.version_info[:2] == (3,12); assert not any(p.pw_uid == 1000 or p.pw_name == 'bluefire' for p in pwd.getpwall()); assert not any(g.gr_gid == 1000 or g.gr_name == 'bluefire' for g in grp.getgrall())"
wsl.exe --terminate BlueFire-Gate11-Base-v1
```

These are explicit prerequisite installation commands, outside any effects session. They need
network access to the distribution's configured package repositories. If the account check
fails, use a clean dedicated image; do not remove an existing person's account.

WSL's Windows-to-Linux localhost forwarding must be available for browser access. The launcher
does not change the user's global `.wslconfig`. See Microsoft's
[localhost forwarding and per-distribution settings](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

For source development, build a Linux wheel in a separate Linux build environment with the
reviewed native artifact and normal build prerequisites. From that source checkout:

```bash
python tools/stage_native_runner.py --runner bluefire/native/linux-x86_64/bluefire-runner --output-root bluefire/native --platform linux --architecture x86_64
python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .
python -m pip download --only-binary=:all: --dest wheelhouse dist/bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl
```

Use the actual versioned filename produced by your build. The download step resolves the
product's declared runtime dependencies for that Linux interpreter. Review and retain the exact
resulting files before transferring the wheel and wheelhouse to Windows. Build tooling and
network dependency resolution are not available inside the effects namespace. Optional Sigma
and YARA backend installation is separate; this setup installs the product's standard runtime
dependencies, including its built-in SQLite evaluator.

## Create and start an owned lab

Choose a **new** local state directory with enough disk space for the cloned base and bounded
wheel input archive. The following commands use paths relative to the current PowerShell folder:

```powershell
python -m bluefire.prepared_lab prepare --state-dir .\lab-state --wheel .\dist\bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl --wheelhouse .\wheelhouse
python -m bluefire.prepared_lab start --state-dir .\lab-state --port 8767
```

`prepare` clones the dedicated base, creates the unprivileged lab account, streams only local
wheel files, and installs them offline into the clone's virtual environment. It then stops the
clone. No runner is bootstrapped or started and no experiment is performed.

`start` creates private mount, network, PID, and IPC namespaces, removes host-backed mounts and
shared socket directories, and enables only loopback. Product processes run as UID/GID 1000
with no supplementary groups, zero capabilities, and `no_new_privs`. Source/runtime files are
read-only in that namespace. The inherited Windows environment, interop, proxies, and secrets
are not forwarded. The exact
[util-linux namespace controls](https://man7.org/linux/man-pages/man1/unshare.1.html) are checked
again before starting the product. `/home/bluefire/lab-isolation.json` records those local checks;
it is setup diagnostics, not independently observed experiment evidence.

Open the **complete URL printed by BlueFire**, including its one-time session fragment. The
relay forwards only the selected loopback port to the ordinary product listener; normal browser
session authentication remains required. It does not create a second API or change endpoint
authorization. The relay permits eight concurrent connections, bounds connection lifetime,
idle time, and bytes, and supports immediate reuse after a prior connection enters TIME_WAIT.

The same terminal accepts normal BlueFire arguments, without a shell. For example:

```text
--help
runner status --profile sandbox-execute.v1
runner bootstrap --profile sandbox-execute.v1
runner start --profile sandbox-execute.v1
```

The latter two commands are explicit operator actions. Use the UI's ordinary Build, preflight,
approval, run, comparison, and detector flows. Quoted CLI arguments are supported; pipes,
redirection, shell expansion, and arbitrary executables are not. A foreground receiver can be
started from this prompt while the UI remains usable. Review the normal
[runner and receiver instructions](RUNNER_DEPLOYMENT.md) for its bounded options and approvals.
The lab has no external network route, so a remote provider's live test will fail here.

## Stop, restart, and destroy

Enter `quit` or press Ctrl+C. The launcher requests normal runner shutdown, closes the UI and
relay, then terminates only its verified clone to ensure guest descendants do not survive a
lost WSL client. It retains the lab filesystem and run history. Start it again with the same
`start` command. Only one launcher or management operation may own a saved lease at once.

The bridge socket is removed only if its device/inode identity still matches this session.
An unexpected or stale replacement is retained and blocks restart; inspect the retained clone
or destroy it after deciding that its results are no longer needed. The tool does not blindly
unlink another session's socket to make startup succeed.

Destroy only after exporting any reviewed artifacts through normal product facilities:

```powershell
python -m bluefire.prepared_lab destroy --state-dir .\lab-state
```

This command permanently unregisters the exact cloned distribution and removes its storage.
The saved state-directory identity, clone-storage identity, WSL registration key, and exact
registration storage path must all agree before destructive management. Replacement or moved
state is refused. The existing ownership manager then verifies fresh registration absence and
empty-storage removal. The small lease and wheel-input archive remain in `lab-state` for review;
the original base and unrelated distributions are preserved.

# Contributing to BlueFire Nexus

Security reports go through the private process in [SECURITY.md](SECURITY.md),
not a public issue. All participation is covered by
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The rules for working in this
repository are in [AGENTS.md](AGENTS.md).

## Set up and check a change

Python 3.10 or newer. These are the commands the `lab package` job runs:

```bash
python3 -m venv .venv
.venv/bin/pip install -e "lab[dev]"
.venv/bin/ruff check lab
.venv/bin/ruff format --check lab
.venv/bin/pytest --rootdir lab -c lab/pyproject.toml lab/tests
```

Before you push, scan the files and every commit of your branch for private
paths. The scan needs nothing installed:

```bash
python3 .github/scripts/privacy_scan.py
python3 .github/scripts/privacy_scan.py --commits origin/main..HEAD
```

Attack tests run only in the `lab` workflow, on GitHub-hosted runners. A pull
request that changes `lab/` runs it, and its run page shows the answers and how
they differ from the latest run on `main`.

## Adding a test, a hardening change or a rule

- A test is a published Atomic Red Team test, pinned by its GUID in
  [`lab/pinned-tests.yaml`](lab/pinned-tests.yaml), with a check that can show
  it did not take effect. The file's header says which tests belong there and
  how each key works.
- A hardening change goes under `defenses` in the same file, with the command
  that puts it in place, the command that removes it, and why a defender would
  deploy it.
- A detection rule of the lab's own is a Sigma rule in
  [`lab/rules/linux`](lab/rules/linux). It counts only once a run accepts it:
  see [the lab's README](lab/README.md#detection-rules-of-the-labs-own).

Contributions are licensed under the [MIT License](LICENSE).

#!/usr/bin/env python3
r"""Reject private details in the files that git tracks.

A tracked file fails the scan when it

- names a path inside a user's home directory (a name under /home, /Users or
  <drive>:\Users), unless it is the account of a GitHub-hosted runner
  (/home/runner, /Users/runner or C:\Users\runneradmin) or the account the lab
  creates on a lab target to run its tests (/home/bluefire-lab);
- carries a marker string that tags a file as not for publication; or
- is a kind of file that is never committed: logs, databases, keys, and build
  or run output.

Every tracked file is read as bytes, so binary files are scanned too.

Usage: python3 .github/scripts/privacy_scan.py [repository]
Prints one line per finding and exits 1, or exits 0 when the tree is clean.
The matched text is never printed: the output of a CI job is public.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

USER_PATH = re.compile(rb"(?i)(?:[a-z]:[\\/]+users[\\/]+|/(?:home|users)/)[^\\/\s]+")
# Telemetry recorded on a lab target names these accounts. They identify nobody.
PUBLIC_HOME = re.compile(
    rb"(?:/home/runner|/Users/runner|C:[\\/]+Users[\\/]+runneradmin|/home/bluefire-lab)(?![A-Za-z0-9._-])"
)

# Each marker is written in two parts so that this file does not carry it.
MARKERS = (
    b"anti_" b"larping_acceptance_contract",
    b"bluefire_real_" b"product_completion_prompt",
)

FORBIDDEN_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".log", ".trace", ".key", ".pem", ".p12", ".pfx")
FORBIDDEN_FOLDERS = {"node_modules", "__pycache__", ".pytest_cache", "runs", "build"}

# The earlier product names the home directory of its own lab account in five
# files, and one of its tests feeds made-up paths to a redaction function.
# These exact strings are accepted in these files only. The entries go when
# the files go.
LAB_HOME = b"/home" b"/bluefire"
EARLIER_PRODUCT_PATHS = {
    "bluefire/prepared_lab.py": (LAB_HOME,),
    "bluefire/prepared_lab_guest.py": (LAB_HOME,),
    "bluefire/prepared_lab_install.py": (LAB_HOME,),
    "bluefire/prepared_lab_runtime.py": (LAB_HOME,),
    "docs/PREPARED_LINUX_LAB.md": (LAB_HOME + b"/lab-isolation.json",),
    "tests_platform/test_defense_frontier_validation.py": (
        b"C:\\Users" b"\\Example",
        b"/home" b"/example-user/private",
    ),
}

ADVICE = {
    "user home path": "write the path relative to the repository or with a placeholder "
    "such as <home>; only the accounts of a hosted runner and of the lab are accepted",
    "private marker": "this file is not for publication; take it out of the commit",
    "never committed": "logs, databases, keys and build or run output stay out of git; "
    "keep a text fixture under an extension such as .txt or .jsonl",
}


def findings_in(relative: str, data: bytes) -> list[str]:
    """Return 'path[:line]: reason' for every problem with one tracked file."""

    found = set()
    parts = relative.lower().split("/")
    if parts[-1].endswith(FORBIDDEN_SUFFIXES) or FORBIDDEN_FOLDERS.intersection(parts[:-1]):
        found.add(f"{relative}: never committed")
    # UTF-16 text keeps a zero byte beside each ASCII character: read it both ways.
    for text in {data, data.replace(b"\0", b"")}:
        if any(marker in text for marker in MARKERS):
            found.add(f"{relative}: private marker")
        for literal in EARLIER_PRODUCT_PATHS.get(relative, ()):
            text = re.sub(re.escape(literal) + rb"(?=$|[\s\"'`])", b"<accepted>", text)
        for match in USER_PATH.finditer(text):
            if not PUBLIC_HOME.match(text, match.start()):
                line = text.count(b"\n", 0, match.start()) + 1
                found.add(f"{relative}:{line}: user home path")
    return sorted(found)


def scan(repository: str) -> list[str]:
    listing = subprocess.run(
        ["git", "-C", repository, "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    found = []
    for relative in filter(None, listing.decode("utf-8", "surrogateescape").split("\0")):
        path = os.path.join(repository, relative)
        if os.path.islink(path):
            data = os.fsencode(os.readlink(path))
        elif os.path.isfile(path):
            with open(path, "rb") as handle:
                data = handle.read()
        else:
            continue  # deleted in the working tree, or a submodule
        found.extend(findings_in(relative, data))
    return found


def main() -> int:
    found = scan(sys.argv[1] if len(sys.argv) > 1 else ".")
    for finding in found:
        print(finding)
    for reason, advice in ADVICE.items():
        if any(finding.endswith(reason) for finding in found):
            print(f"{reason}: {advice}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
r"""Reject private details in what git tracks.

A file fails the scan when its content or its name

- names a home directory: an account name after a folder named home or Users,
  written with either kind of slash, or a tool's folder named after a home
  directory (/-home-<name>-..., C--Users-<name>-..., pytest-of-<name>). Only the
  accounts that hosted runners and lab targets use are accepted: /home/runner,
  /Users/runner, C:\Users\runneradmin and /home/bluefire-lab;
- carries a marker string that tags a file as not for publication; or
- is a kind of file that is never committed: logs, databases, keys, archives, or
  anything in a folder for build or run output.

Files are read as bytes, so binary files are scanned too, and so is UTF-16
text. Archives are refused because what is inside them cannot be read.

Usage:
  privacy_scan.py [REPOSITORY]           scan the files git tracks
  privacy_scan.py --commits BASE..HEAD   scan what each commit in the range adds

Prints one line per finding and exits 1, or exits 0 when nothing was found. A
finding names the file and the line, never the matched text: the output of a
CI job is public.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

# What cannot be part of an account name. A quote, bracket, glob or placeholder
# right after the folder says that no name follows: '/home/', "/home/" + user,
# /home/*, /home/<user>, /home/$USER, C:\Users\%USERNAME%.
NOT_A_NAME = rb"\s\\/\"'`<>*?$%{}\[\]()|,;:=&\x00"
HOME_PATH = re.compile(rb"(?i)[\\/](home|users)[\\/]+([^" + NOT_A_NAME + rb"]+)")
TOOL_FOLDER = re.compile(rb"(?i)(?:[\\/]-(?:home|users)-|\b[a-z]--users-|pytest-of-)([^" + NOT_A_NAME + rb"]+)")
PUBLIC_HOMES = {(b"home", b"runner"), (b"users", b"runner"), (b"users", b"runneradmin"), (b"home", b"bluefire-lab")}
PUBLIC_ACCOUNTS = (b"runner", b"runneradmin", b"bluefire-lab")

# Each marker is written in two parts so that this file does not carry it.
MARKERS = (
    b"anti_" b"larping_acceptance_contract",
    b"bluefire_real_" b"product_completion_prompt",
)

FORBIDDEN_SUFFIXES = (
    ".db", ".sqlite", ".sqlite3", ".log", ".trace", ".key", ".pem", ".p12", ".pfx",
    ".gz", ".tgz", ".zip", ".tar", ".7z", ".xz", ".bz2", ".rar",
)  # fmt: skip
FORBIDDEN_FOLDERS = {"node_modules", "__pycache__", ".pytest_cache", "runs", "build"}

# The earlier product names the home directory of its own lab account in four
# files, and four of its tests feed made-up paths to redaction and layout
# checks. These exact strings are accepted in these files only. The entries go
# when the files go.
LAB_HOME = b"/home" b"/bluefire"
EARLIER_PRODUCT_PATHS = {
    "bluefire/prepared_lab.py": (LAB_HOME,),
    "bluefire/prepared_lab_install.py": (LAB_HOME,),
    "bluefire/prepared_lab_runtime.py": (LAB_HOME,),
    "docs/PREPARED_LINUX_LAB.md": (LAB_HOME + b"/lab-isolation.json",),
    "tests_platform/test_architecture_gate.py": (b"pytest-of" b"-fixture",),
    "tests_platform/test_defense_frontier_validation.py": (
        b"C:\\Users" b"\\Example",
        b"/home" b"/example-user/private",
    ),
    "tests_platform/test_product_acceptance.py": (
        b"\\\\Users" b"\\\\private-user\\\\artifact.json",
        b"\\Users" b"\\private-user\\artifact.json",
    ),
    "tests_platform/test_runner_bootstrap.py": (b"\\Users" b"\\private-user\\runner.exe",),
}

ADVICE = {
    "user home path": "write the path relative to the repository or with a placeholder such as "
    "<home>; only the accounts of hosted runners and lab targets are accepted. A path that "
    "reached a pushed commit stays in its history when a later commit removes it",
    "private marker": "this file is not for publication; take it out of the commit",
    "file kind never committed": "logs, databases, keys and archives stay out of git; keep a "
    "text fixture under an extension such as .txt or .jsonl, and commit files unpacked",
    "output folder never committed": "folders named build, runs, node_modules, __pycache__ or "
    ".pytest_cache hold generated output and stay out of git; choose another folder name",
}


def home_paths(text: bytes) -> list[int]:
    """Where text names a home directory, other than a public account's."""

    offsets = [
        match.start()
        for match in HOME_PATH.finditer(text)
        if (match[1].lower(), match[2].rstrip(b".")) not in PUBLIC_HOMES
    ]
    offsets += [
        match.start()
        for match in TOOL_FOLDER.finditer(text)
        if not any(match[1] == name or match[1].startswith(name + b"-") for name in PUBLIC_ACCOUNTS)
    ]
    return sorted(offsets)


def readings(data: bytes) -> list[bytes]:
    """The bytes as stored and, when they hold zero bytes, as UTF-16 text would read."""

    if b"\0" not in data:
        return [data]
    return [
        data,
        data.replace(b"\0", b""),  # ASCII in UTF-16 or UTF-32, at any alignment
        data.decode("utf-16-le", "replace").encode("utf-8", "replace"),
        data.decode("utf-16-be", "replace").encode("utf-8", "replace"),
    ]


def findings_in(relative: str, data: bytes) -> set[tuple[str, int, str]]:
    """Every problem with one file, as (where, line, reason). Line 0 means the whole file."""

    found = set()
    parts = relative.lower().split("/")
    if parts[-1].endswith(FORBIDDEN_SUFFIXES):
        found.add((relative, 0, "file kind never committed"))
    if FORBIDDEN_FOLDERS.intersection(parts[:-1]):
        found.add((relative, 0, "output folder never committed"))
    name = relative.encode("utf-8", "surrogateescape")
    if any(marker in name for marker in MARKERS):
        found.add((f"{relative} (file name)", 0, "private marker"))
    if home_paths(b"/" + name):
        found.add((f"{relative} (file name)", 0, "user home path"))
    for text in readings(data):
        if any(marker in text for marker in MARKERS):
            found.add((relative, 0, "private marker"))
        for literal in EARLIER_PRODUCT_PATHS.get(relative, ()):
            text = re.sub(re.escape(literal) + rb"(?=$|[\s\"'`])", b"<accepted>", text)
        line, counted = 1, 0
        for offset in home_paths(text):
            line += text.count(b"\n", counted, offset)
            counted = offset
            found.add((relative, line, "user home path"))
    return found


def git(repository: str, *arguments: str) -> bytes:
    # git exports these to hooks; they would point every command at the hook's repository.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    command = ["git", "-C", repository, *arguments]
    return subprocess.run(command, check=True, capture_output=True, env=environment).stdout


def scan_tree(repository: str) -> set[tuple[str, int, str]]:
    top = git(repository, "rev-parse", "--show-toplevel").decode().strip()
    found = set()
    for relative in filter(None, git(top, "ls-files", "-z").decode("utf-8", "surrogateescape").split("\0")):
        path = os.path.join(top, relative)
        if os.path.islink(path):
            data = os.fsencode(os.readlink(path))
        elif os.path.isfile(path):
            with open(path, "rb") as handle:
                data = handle.read()
        else:
            continue  # deleted in the working tree, or a submodule
        found |= findings_in(relative, data)
    return found


def scan_commits(repository: str, revisions: str) -> set[tuple[str, int, str]]:
    """What each commit in the range adds or changes, compared with its first parent."""

    found, seen = set(), set()
    for commit in git(repository, "rev-list", revisions).decode().split():
        parents = git(repository, "rev-list", "--parents", "-n", "1", commit).decode().split()[1:]
        compare = [parents[0], commit] if parents else ["--root", commit]
        changes = git(repository, "diff-tree", "-r", "-z", "--no-commit-id", "--no-renames",
                      "--diff-filter=AMT", *compare).split(b"\0")  # fmt: skip
        for meta, path in zip(changes[0::2], changes[1::2]):
            mode, blob = meta.split()[1], meta.split()[3].decode()
            relative = path.decode("utf-8", "surrogateescape")
            if mode == b"160000" or (relative, blob) in seen:
                continue  # a submodule, or content already read
            seen.add((relative, blob))
            for where, line, reason in findings_in(relative, git(repository, "cat-file", "blob", blob)):
                found.add((f"commit {commit[:12]} {where}", line, reason))
    return found


def main(arguments: list[str]) -> int:
    if len(arguments) == 2 and arguments[0] == "--commits":
        found = scan_commits(".", arguments[1])
    elif len(arguments) <= 1 and not (arguments and arguments[0].startswith("-")):
        found = scan_tree(arguments[0] if arguments else ".")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for where, line, reason in sorted(found):
        print(f"{where}:{line}: {reason}" if line else f"{where}: {reason}")
    for reason in sorted({reason for _, _, reason in found}):
        print(f"{reason}: {ADVICE[reason]}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

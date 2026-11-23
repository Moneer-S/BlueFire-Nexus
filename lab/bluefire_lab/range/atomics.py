"""The files of Atomic Red Team that a range carries, fetched at the spec's commit and checked against a lock.

A range needs three kinds of published file: the technique YAML of every step
of its path, every file of the `src` folders its hosts carry (`atomics_src`),
and single files that a host serves or that a planted password is read from.
The project's licence comes with them.
They are fetched from raw.githubusercontent.com at the commit the spec pins.
Every fetched file must have the SHA-256 that the spec's lock file gives it,
and a file the lock does not list, or lists with another hash, stops the build
with the file's name. No published text is run: the files are data.

The lock is written by `bluefire-lab range lock <spec>`, which also lists the
`src` folders through GitHub's API. Its lines are `<sha256>  <path>`, as
`sha256sum` writes them, after a comment that names the repository and commit.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .spec import Spec, SpecError

RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"
CONTENTS = "https://api.github.com/repos/{repo}/contents/{path}?ref={commit}"
FETCH_SECONDS = 60
# The folder on a host that holds the published files it carries, as the executor names it.
ATOMICS_PATH = "/opt/atomics"
# Atomic Red Team's licence (MIT), at the root of its repository. The build context holds it as
# atomics/LICENSE.txt, beside the files it covers, and every host that carries published files has it.
LICENSE = "LICENSE.txt"

Fetch = Callable[[str], bytes]


def http_get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "bluefire-lab"})
    with urllib.request.urlopen(request, timeout=FETCH_SECONDS) as response:  # noqa: S310 - https only
        return response.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def single_files(spec: Spec) -> list[str]:
    """The technique YAMLs of the path, every single file a host serves or reads a password from, and,
    with any of them, the project's licence, which travels with every copy of its files."""

    found = [f"atomics/{technique}/{technique}.yaml" for technique, _ in spec.steps]
    for host in spec.hosts.values():
        found += [source for _, source in host.serve]
        found += [account.listed.file for account in host.accounts if account.listed]
    if found or src_folders(spec):
        found.append(LICENSE)
    return sorted(set(found))


def src_folders(spec: Spec) -> list[str]:
    return sorted({f"atomics/{t}/src" for host in spec.hosts.values() for t in host.atomics_src})


def lock_path(spec: Spec) -> Path:
    if spec.atomics is None or not spec.atomics.lock or spec.folder is None:
        raise SpecError("the spec's atomic_red_team names no lock file beside it")
    return spec.folder / spec.atomics.lock


def read_lock(text: str, spec: Spec) -> dict[str, str]:
    """A lock file's hashes by path; its first line must name the spec's repository and commit."""

    lines = text.splitlines()
    header = f"# {spec.atomics.repo} {spec.atomics.commit}"
    if not lines or lines[0] != header:
        raise SpecError(
            f"the lock file {spec.atomics.lock} is not for {spec.atomics.repo} at {spec.atomics.commit}: "
            "write it again with bluefire-lab range lock"
        )
    found = {}
    for number, line in enumerate(lines[1:], start=2):
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not path or path in found:
            raise SpecError(f"line {number} of {spec.atomics.lock} is not '<sha256>  <path>' of a new file")
        found[path] = digest
    return found


def write_lock(hashes: dict[str, str], spec: Spec) -> str:
    lines = [f"# {spec.atomics.repo} {spec.atomics.commit}"]
    lines += [f"{hashes[path]}  {path}" for path in sorted(hashes)]
    return "\n".join(lines) + "\n"


def wanted(spec: Spec, locked: dict[str, str]) -> list[str]:
    """Every file the spec needs, the src folders' files as the lock lists them; refuse a lock that differs."""

    singles = single_files(spec)
    folders = src_folders(spec)
    for folder in folders:
        if not any(path.startswith(folder + "/") for path in locked):
            raise SpecError(
                f"{spec.atomics.lock} lists no file of {folder}: write it again with bluefire-lab range lock"
            )
    missing = [path for path in singles if path not in locked]
    if missing:
        raise SpecError(
            f"{spec.atomics.lock} does not list {', '.join(missing)}, which the spec uses: write it again with "
            "bluefire-lab range lock"
        )
    extra = [
        path
        for path in locked
        if path not in singles and not any(path.startswith(folder + "/") for folder in folders)
    ]
    if extra:
        raise SpecError(
            f"{spec.atomics.lock} lists {', '.join(sorted(extra))}, which the spec does not use: write it again "
            "with bluefire-lab range lock"
        )
    return sorted(locked)


def fetch(spec: Spec, get: Fetch = http_get) -> dict[str, bytes]:
    """Every file the spec needs, fetched at its commit; a file whose hash is not the lock's stops it, by name."""

    path = lock_path(spec)
    try:
        locked = read_lock(path.read_text(encoding="utf-8"), spec)
    except FileNotFoundError as error:
        raise SpecError(
            f"there is no lock file {path.name} beside the spec: write it with bluefire-lab range lock"
        ) from error
    found = {}
    for relative in wanted(spec, locked):
        url = RAW.format(repo=spec.atomics.repo, commit=spec.atomics.commit, path=relative)
        try:
            data = get(url)
        except OSError as error:
            raise SpecError(f"could not fetch {relative} at {spec.atomics.commit}: {error}") from error
        if sha256(data) != locked[relative]:
            raise SpecError(
                f"{relative} at {spec.atomics.commit} has SHA-256 {sha256(data)}, and {path.name} says "
                f"{locked[relative]}: the build stops"
            )
        found[relative] = data
    for host in spec.hosts.values():
        for account in host.accounts:
            if account.listed:
                check_listed(account.name, account.password, account.listed, found[account.listed.file])
    return found


def check_listed(name: str, password: str, listed, data: bytes) -> None:
    """A planted password that the spec says is in a published list must be on that line of it."""

    lines = data.decode("utf-8", errors="replace").splitlines()
    line = lines[listed.line - 1] if len(lines) >= listed.line else None
    if line != f"{name}:{password}":
        raise SpecError(
            f"the account {name} is planted with a password that line {listed.line} of {listed.file} "
            f"should hold as {name}:<password>, and that line is {line!r}"
        )


def list_folder(spec: Spec, folder: str, get: Fetch) -> list[str]:
    """The files of a folder of the repository at the commit, through GitHub's contents API."""

    url = CONTENTS.format(repo=spec.atomics.repo, commit=spec.atomics.commit, path=folder)
    found = []
    for entry in json.loads(get(url)):
        if entry.get("type") == "dir":
            found += list_folder(spec, entry["path"], get)
        elif entry.get("type") == "file":
            found.append(entry["path"])
        else:
            raise SpecError(
                f"{entry.get('path')} at {spec.atomics.commit} is a {entry.get('type')}, not a file"
            )
    return found


def lock(spec: Spec, get: Fetch = http_get) -> Path:
    """Fetch every file the spec needs at its commit and write the lock beside the spec."""

    path = lock_path(spec)
    paths = single_files(spec)
    for folder in src_folders(spec):
        listed = list_folder(spec, folder, get)
        if not listed:
            raise SpecError(f"{folder} at {spec.atomics.commit} holds no file")
        paths += listed
    hashes = {}
    for relative in sorted(set(paths)):
        data = get(RAW.format(repo=spec.atomics.repo, commit=spec.atomics.commit, path=relative))
        hashes[relative] = sha256(data)
        for host in spec.hosts.values():
            for account in host.accounts:
                if account.listed and account.listed.file == relative:
                    check_listed(account.name, account.password, account.listed, data)
    path.write_text(write_lock(hashes, spec), encoding="utf-8")
    return path

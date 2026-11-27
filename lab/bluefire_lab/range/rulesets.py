"""The public rule sets a range's defenses run: fetched file by file at each set's commit, and locked.

A rule set is folders of a public repository at a commit, with the
repository's licence file (`rule_sets` in the spec). Its lock file, beside the
spec, gives the SHA-256 of every one of those files, as `<sha256>  <path>`
lines under a line that names the set, its repository and its commit; rule
sets that name the same lock file share it, one section each.
`bluefire-lab range lock <spec>` writes it: it lists each folder through
GitHub's contents API and fetches every file from raw.githubusercontent.com at
the commit. Nothing is cloned.

A run fetches the files by the lock into its own folder, `rules/<set>/`, each
at its path in the repository, the licence file with them, and writes
`SOURCE` there, one line that says where they come from:
`<repository>@<commit>`. A file whose SHA-256 is not the lock's stops the run
with the file's name. `held` reads a run folder's rules back and checks them
the same way, so scoring a run folder again fetches nothing.
"""

from __future__ import annotations

import shutil
import urllib.parse
from pathlib import Path, PurePosixPath

from . import atomics
from .spec import RuleSet, Spec, SpecError

FOLDER = "rules"
SOURCE = "SOURCE"


def archived(rule_set: RuleSet) -> bool:
    """Whether this set is one immutable archive already carried by the repository."""

    return bool(rule_set.source_file)


def archive_name(rule_set: RuleSet) -> str:
    return PurePosixPath(rule_set.source_file).name


def header(rule_set: RuleSet) -> str:
    return f"# {rule_set.name}: {rule_set.repo} {rule_set.commit}"


def lock_path(spec: Spec, rule_set: RuleSet) -> Path:
    if archived(rule_set):
        raise SpecError(f"the rule set {rule_set.name} is pinned by the SHA-256 of its archive, not a lock")
    if spec.folder is None:
        raise SpecError(
            f"the rule set {rule_set.name} names the lock {rule_set.lock}, and the spec has no folder"
        )
    return spec.folder / rule_set.lock


def read_lock(text: str, rule_set: RuleSet) -> dict[str, str]:
    """The hashes of a rule set's files by path, from its section of a lock file."""

    lines = text.splitlines()
    if header(rule_set) not in lines:
        raise SpecError(
            f"the lock file {rule_set.lock} has no section for the rule set {rule_set.name} of "
            f"{rule_set.repo} at {rule_set.commit}: write it again with bluefire-lab range lock"
        )
    found: dict[str, str] = {}
    start = lines.index(header(rule_set)) + 1
    for number, line in enumerate(lines[start:], start=start + 1):
        if line.startswith("# "):
            break
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not plain(path) or path in found:
            raise SpecError(f"line {number} of {rule_set.lock} is not '<sha256>  <path>' of a new file")
        found[path] = digest
    return found


def plain(path: str) -> bool:
    """True for a path the lab writes under a run's folder: relative, with no empty part, `.` or `..`."""

    parts = PurePosixPath(path).parts
    return (
        bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and "\0" not in path
        and all(part not in (".", "..") for part in parts)
        and "/".join(parts) == path
    )


def in_folder(rule_set: RuleSet, path: str) -> bool:
    return any(path.startswith(folder + "/") for folder in rule_set.folders)


def wanted(rule_set: RuleSet, locked: dict[str, str]) -> list[str]:
    """Every file of the rule set as its lock lists them; refuse a lock that is not of the spec's folders."""

    again = "write it again with bluefire-lab range lock"
    if rule_set.licence not in locked:
        raise SpecError(
            f"{rule_set.lock} does not list {rule_set.licence}, the licence of {rule_set.name}: {again}"
        )
    for folder in rule_set.folders:
        if not any(path.startswith(folder + "/") for path in locked):
            raise SpecError(f"{rule_set.lock} lists no file of {folder} for {rule_set.name}: {again}")
    extra = sorted(path for path in locked if path != rule_set.licence and not in_folder(rule_set, path))
    if extra:
        raise SpecError(
            f"{rule_set.lock} lists {', '.join(extra[:5])} for {rule_set.name}, outside the folders the spec "
            f"names: {again}"
        )
    return sorted(locked)


def locked(spec: Spec, rule_set: RuleSet) -> dict[str, str]:
    """A rule set's lock, read from the file beside the spec and checked against the spec's folders."""
    if archived(rule_set):
        return {archive_name(rule_set): rule_set.sha256}

    path = lock_path(spec, rule_set)
    try:
        found = read_lock(path.read_text(encoding="utf-8"), rule_set)
    except FileNotFoundError as error:
        raise SpecError(
            f"there is no lock file {path.name} beside the spec: write it with bluefire-lab range lock"
        ) from error
    wanted(rule_set, found)
    return found


def raw_url(rule_set: RuleSet, path: str) -> str:
    return atomics.RAW.format(repo=rule_set.repo, commit=rule_set.commit, path=urllib.parse.quote(path))


def source(rule_set: RuleSet) -> str:
    if archived(rule_set):
        return f"{rule_set.source_file}@{rule_set.version}"
    return f"{rule_set.repo}@{rule_set.commit}"


def rule_root(out: Path, *, create: bool = False) -> Path:
    """The real ``rules`` folder under an output folder, never a link or another kind of file."""

    root = Path(out) / FOLDER
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise SpecError(f"{FOLDER} is not a folder in the run's folder")
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def fetch(spec: Spec, rule_set: RuleSet, out: Path, get: atomics.Fetch = atomics.http_get) -> dict:
    """Fetch a rule set by its lock into `out`/rules/<set>/; a file whose hash is not the lock's stops it, by name.

    Returns what the run's manifest records of the set: where it came from and the lock it was checked against.
    """

    if archived(rule_set):
        if spec.folder is None:
            raise SpecError(f"the rule set {rule_set.name} names a source file, and the spec has no folder")
        roots = (spec.folder, *spec.folder.parents)
        repository = next((folder for folder in roots if (folder / ".git").exists()), spec.folder)
        root = repository.resolve()
        source_path = repository.joinpath(*PurePosixPath(rule_set.source_file).parts)
        try:
            resolved = source_path.resolve(strict=True)
        except OSError as error:
            raise SpecError(
                f"the archive {rule_set.source_file} of {rule_set.name} is not beside the spec"
            ) from error
        if source_path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            raise SpecError(
                f"the archive {rule_set.source_file} of {rule_set.name} must be a regular file inside the spec folder"
            )
        digest_ = atomics.sha256(resolved.read_bytes())
        if digest_ != rule_set.sha256:
            raise SpecError(
                f"{rule_set.source_file} of {rule_set.name} has SHA-256 {digest_}, and the spec says "
                f"{rule_set.sha256}: the run stops"
            )
        folder = Path(out) / FOLDER / rule_set.name
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / archive_name(rule_set)
        shutil.copyfile(resolved, target)
        (folder / SOURCE).write_text(source(rule_set) + "\n", encoding="utf-8")
        return record(rule_set, {target.name: digest_})

    hashes = locked(spec, rule_set)
    root = rule_root(out)
    folder = root / rule_set.name
    if folder.is_symlink() or folder.exists():
        raise SpecError(
            f"{FOLDER}/{rule_set.name} exists already in the run's folder: use a new run folder, or "
            "remove that rule set before fetching it"
        )
    files: dict[str, bytes] = {}
    for relative in sorted(hashes):
        try:
            data = get(raw_url(rule_set, relative))
        except OSError as error:
            raise SpecError(
                f"could not fetch {relative} of {rule_set.name} at {rule_set.commit}: {error}"
            ) from error
        if atomics.sha256(data) != hashes[relative]:
            raise SpecError(
                f"{relative} of {rule_set.name} at {rule_set.commit} has SHA-256 {atomics.sha256(data)}, and "
                f"{rule_set.lock} says {hashes[relative]}: the run stops"
            )
        files[relative] = data
    root = rule_root(out, create=True)
    folder = root / rule_set.name
    if folder.is_symlink() or folder.exists():
        raise SpecError(f"{FOLDER}/{rule_set.name} appeared while the rule set was being fetched")
    folder.mkdir()
    for relative, data in files.items():
        target = folder.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (folder / SOURCE).write_text(source(rule_set) + "\n", encoding="utf-8")
    return record(rule_set, hashes)


def record(rule_set: RuleSet, hashes: dict[str, str]) -> dict:
    """What a run's manifest holds of a rule set."""

    if archived(rule_set):
        return {
            "kind": rule_set.kind,
            "source": rule_set.source_file,
            "version": rule_set.version,
            "sha256": rule_set.sha256,
            "folder": f"{FOLDER}/{rule_set.name}",
            "files": 1,
            "digest": rule_set.sha256,
            "lock": dict(sorted(hashes.items())),
            "note": (
                "the published archive was copied byte for byte from the repository after its SHA-256 "
                "matched the spec; its own licence files remain inside it and SOURCE names its version"
            ),
        }
    return {
        "kind": rule_set.kind,
        "repo": rule_set.repo,
        "commit": rule_set.commit,
        "folders": list(rule_set.folders),
        "licence": rule_set.licence,
        "folder": f"{FOLDER}/{rule_set.name}",
        "files": len(hashes) - 1,
        "digest": digest(rule_set, hashes),
        "lock": dict(sorted(hashes.items())),
        "note": "every file was fetched from raw.githubusercontent.com at the commit and had the lock's "
        "SHA-256; the licence file and SOURCE, which names the repository and commit, are beside the rules",
    }


def digest(rule_set: RuleSet, hashes: dict[str, str]) -> str:
    """The SHA-256 of what `sha256sum` prints for the set's rule files, sorted by their path in the set's
    folder: the files of the rule folders, without the licence file and SOURCE."""

    if archived(rule_set):
        return hashes.get(archive_name(rule_set), rule_set.sha256)
    listing = "".join(f"{hashes[path]}  {path}\n" for path in sorted(hashes) if in_folder(rule_set, path))
    return atomics.sha256(listing.encode("utf-8"))


def held(run: Path, name: str, expected: dict[str, str]) -> Path:
    """The folder of a rule set in a run's folder, once every file of it has the SHA-256 the run recorded.

    Refused, with the file's name, when a file is missing or differs, or when the folder holds a
    rule file the lock does not list.
    """

    root = rule_root(run)
    folder = root / name
    if folder.is_symlink() or not folder.is_dir():
        raise SpecError(f"{FOLDER}/{name} is not a folder in the run's folder")
    for relative, wanted_hash in sorted(expected.items()):
        if not plain(relative):
            raise SpecError(f"{FOLDER}/{name}/{relative} is not in the run's folder")
        parts = PurePosixPath(relative).parts
        path = folder.joinpath(*parts)
        parents = [folder.joinpath(*parts[:place]) for place in range(1, len(parts))]
        if any(parent.is_symlink() for parent in parents) or path.is_symlink() or not path.is_file():
            raise SpecError(f"{FOLDER}/{name}/{relative} is not in the run's folder")
        found = atomics.sha256(path.read_bytes())
        if found != wanted_hash:
            raise SpecError(
                f"{FOLDER}/{name}/{relative} has SHA-256 {found}, and the lock the run was checked against "
                f"says {wanted_hash}"
            )
    extra = sorted(
        path.relative_to(folder).as_posix()
        for path in folder.rglob("*")
        if (path.is_file() or path.is_symlink())
        and path.relative_to(folder).as_posix() not in expected
        and path.relative_to(folder).as_posix() != SOURCE
    )
    if extra:
        raise SpecError(f"{FOLDER}/{name} holds {', '.join(extra[:5])}, which the lock does not list")
    return folder


def lock(spec: Spec, get: atomics.Fetch = atomics.http_get) -> list[Path]:
    """Fetch every file of every rule set at its commit and write the lock files beside the spec."""

    sections: dict[str, list[str]] = {}
    for rule_set in spec.rule_sets:
        if archived(rule_set):
            continue
        lock_path(spec, rule_set)
        paths = [rule_set.licence]
        for folder in rule_set.folders:
            found = atomics.listed(rule_set.repo, rule_set.commit, folder, get)
            if not found:
                raise SpecError(f"{folder} of {rule_set.repo} at {rule_set.commit} holds no file")
            paths += found
        refused = [path for path in paths if not plain(path)]
        if refused:
            raise SpecError(f"{rule_set.name}: the lab does not write a file named {refused[0]!r}")
        hashes = {path: atomics.sha256(get(raw_url(rule_set, path))) for path in sorted(set(paths))}
        lines = [header(rule_set)] + [f"{hashes[path]}  {path}" for path in sorted(hashes)]
        sections.setdefault(rule_set.lock, []).extend(lines)
    written = []
    for name, lines in sections.items():
        path = spec.folder / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)
    return written

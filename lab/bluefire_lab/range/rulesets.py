"""The public rule sets a range's defenses run: fetched file by file at each set's commit, and locked.

A rule set is folders of a public repository at a commit, with the
repository's licence file (`rule_sets` in the spec). Its lock file, beside the
spec, gives the SHA-256 of every selected file, as `<sha256>  <path>` lines
under a line that names the set, its repository and its commit. A set may take
every file or only rule documents below named source paths; the lock records
that selection and counts what it left out. Rule sets that name the same lock
file share it, one section each.
`bluefire-lab range lock <spec>` writes it: it lists each folder through
GitHub's contents API and fetches each selected candidate from
raw.githubusercontent.com at the commit. Nothing is cloned.

A run fetches the files by the lock into its own folder, `rules/<set>/`, each
at its path in the repository, the licence file with them, and writes
`SOURCE` there, one line that says where they come from:
`<repository>@<commit>`. A file whose SHA-256 is not the lock's stops the run
with the file's name. `held` reads a run folder's rules back and checks them
the same way, so scoring a run folder again fetches nothing.
"""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

from . import atomics
from .spec import RuleSet, Spec, SpecError

FOLDER = "rules"
SOURCE = "SOURCE"


class Locked(dict[str, str]):
    """The file hashes of one locked set, with the files discovery left out by reason."""

    def __init__(self, hashes: dict[str, str], left_out: dict[str, int] | None = None):
        super().__init__(hashes)
        self.left_out = dict(sorted((left_out or {}).items()))


INCLUDE = "# include: "
RULE_PATH = "# rule path: "
EXCLUDE = "# exclude: "
LEFT_OUT = "# left out: "
SURICATA_RULE = re.compile(r"^(alert|drop|pass|reject(?:src|dst|both)?)\s+", re.IGNORECASE)


def header(rule_set: RuleSet) -> str:
    return f"# {rule_set.name}: {rule_set.repo} {rule_set.commit}"


def lock_path(spec: Spec, rule_set: RuleSet) -> Path:
    if spec.folder is None:
        raise SpecError(
            f"the rule set {rule_set.name} names the lock {rule_set.lock}, and the spec has no folder"
        )
    return spec.folder / rule_set.lock


def read_lock(text: str, rule_set: RuleSet) -> Locked:
    """The hashes of a rule set's files by path, from its section of a lock file."""

    lines = text.splitlines()
    if header(rule_set) not in lines:
        raise SpecError(
            f"the lock file {rule_set.lock} has no section for the rule set {rule_set.name} of "
            f"{rule_set.repo} at {rule_set.commit}: write it again with bluefire-lab range lock"
        )
    found: dict[str, str] = {}
    include = "all"
    rule_paths: list[str] = []
    excluded: list[str] = []
    left_out: dict[str, int] = {}
    start = lines.index(header(rule_set)) + 1
    for number, line in enumerate(lines[start:], start=start + 1):
        if line.startswith(INCLUDE):
            include = line.removeprefix(INCLUDE)
            continue
        if line.startswith(RULE_PATH):
            path = line.removeprefix(RULE_PATH)
            if not path or path in rule_paths:
                raise SpecError(f"line {number} of {rule_set.lock} does not name a new rule path")
            rule_paths.append(path)
            continue
        if line.startswith(EXCLUDE):
            path = line.removeprefix(EXCLUDE)
            if not plain(path) or path in excluded:
                raise SpecError(f"line {number} of {rule_set.lock} does not name a new excluded file")
            excluded.append(path)
            continue
        if line.startswith(LEFT_OUT):
            count, separator, reason = line.removeprefix(LEFT_OUT).partition(" ")
            if not separator or not count.isdigit() or int(count) < 1 or not reason or reason in left_out:
                raise SpecError(
                    f"line {number} of {rule_set.lock} does not count files left out for one reason"
                )
            left_out[reason] = int(count)
            continue
        if line.startswith("# "):
            break
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not plain(path) or path in found:
            raise SpecError(f"line {number} of {rule_set.lock} is not '<sha256>  <path>' of a new file")
        found[path] = digest
    if (
        include != rule_set.include
        or sorted(rule_paths) != sorted(rule_set.rule_paths)
        or sorted(excluded) != sorted(rule_set.exclude)
    ):
        raise SpecError(
            f"the section for {rule_set.name} in {rule_set.lock} selects different files than the spec: "
            "write it again with bluefire-lab range lock"
        )
    return Locked(found, left_out)


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

    left_out = dict(getattr(hashes, "left_out", {}))
    return {
        "kind": rule_set.kind,
        "repo": rule_set.repo,
        "commit": rule_set.commit,
        "folders": list(rule_set.folders),
        "licence": rule_set.licence,
        "folder": f"{FOLDER}/{rule_set.name}",
        "files": len(hashes) - 1,
        "selection": {
            "include": rule_set.include,
            "rule paths": list(rule_set.rule_paths),
            "exclude": list(rule_set.exclude),
            "selected files": len(hashes) - 1,
            "left out files": sum(left_out.values()),
            "left out by reason": left_out,
        },
        "digest": digest(rule_set, hashes),
        "lock": dict(sorted(hashes.items())),
        "note": "every selected file was fetched from raw.githubusercontent.com at the commit and had the "
        "lock's SHA-256; the licence file and SOURCE, which names the repository and commit, are beside "
        "the rules",
    }


def digest(rule_set: RuleSet, hashes: dict[str, str]) -> str:
    """The SHA-256 of what `sha256sum` prints for the set's rule files, sorted by their path in the set's
    folder: the files of the rule folders, without the licence file and SOURCE."""

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


def selection_reason(rule_set: RuleSet, path: str, data: bytes) -> str | None:
    """Why fetched bytes are not one rule of the set's kind, or None when the lock takes them."""

    if rule_set.include == "all":
        return None
    if rule_set.kind == "sigma":
        return sigma_reason(path, data)
    if rule_set.kind == "suricata":
        return suricata_reason(path, data)
    return f"not a rule for {rule_set.kind}"


def path_selection_reason(rule_set: RuleSet, path: str) -> str | None:
    """Why discovery can leave out a path without fetching its contents."""

    if path in rule_set.exclude:
        return "excluded by the spec"
    if rule_set.rule_paths and not any(in_rule_path(path, pattern) for pattern in rule_set.rule_paths):
        return "outside selected source paths"
    return None


def in_rule_path(path: str, pattern: str) -> bool:
    """True when a repository file is below a source-folder pattern whose `*` matches one whole part."""

    parts, wanted = PurePosixPath(path).parts, PurePosixPath(pattern).parts
    return len(parts) > len(wanted) and all(
        pattern == "*" or pattern == part for part, pattern in zip(parts, wanted, strict=False)
    )


def sigma_reason(path: str, data: bytes) -> str | None:
    """Why bytes are not one Sigma atomic rule or correlation."""

    if PurePosixPath(path).suffix.lower() not in (".yml", ".yaml"):
        return "not YAML"
    try:
        documents = [found for found in yaml.safe_load_all(data.decode("utf-8")) if found is not None]
    except (UnicodeDecodeError, yaml.YAMLError):
        return "not readable as YAML"
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return "not one Sigma YAML document"
    document = documents[0]
    atomic = isinstance(document.get("logsource"), dict) and isinstance(document.get("detection"), dict)
    correlation = isinstance(document.get("correlation"), dict)
    if atomic or correlation:
        return None
    if "pipelines" in PurePosixPath(path).parts or "transformations" in document:
        return "Sigma pipeline"
    return "not a Sigma rule or correlation"


def suricata_reason(path: str, data: bytes) -> str | None:
    """Why bytes are not an active Suricata rule file."""

    if PurePosixPath(path).suffix.lower() != ".rules":
        return "not a Suricata .rules file"
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return "not readable as text"
    active = (line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    if not any(SURICATA_RULE.match(line) for line in active):
        return "no active Suricata rule"
    return None


def selection_lines(rule_set: RuleSet, left_out: dict[str, int]) -> list[str]:
    """Lock comments that bind a section to its selection and preserve the excluded counts."""

    lines = []
    if rule_set.include != "all":
        lines.append(INCLUDE + rule_set.include)
    lines += [RULE_PATH + path for path in sorted(rule_set.rule_paths)]
    lines += [EXCLUDE + path for path in sorted(rule_set.exclude)]
    lines += [f"{LEFT_OUT}{count} {reason}" for reason, count in sorted(left_out.items())]
    return lines


def lock(spec: Spec, get: atomics.Fetch = atomics.http_get) -> list[Path]:
    """Discover and fetch each selected file at a set's commit, then write its exact hashes."""

    sections: dict[str, list[str]] = {}
    for rule_set in spec.rule_sets:
        lock_path(spec, rule_set)
        candidates: list[str] = []
        for folder in rule_set.folders:
            found = atomics.listed(rule_set.repo, rule_set.commit, folder, get)
            if not found:
                raise SpecError(f"{folder} of {rule_set.repo} at {rule_set.commit} holds no file")
            candidates += found
        candidates = sorted(set(candidates))
        refused = [path for path in [rule_set.licence] + candidates if not plain(path)]
        if refused:
            raise SpecError(f"{rule_set.name}: the lab does not write a file named {refused[0]!r}")
        missing = sorted(set(rule_set.exclude) - set(candidates))
        if missing:
            raise SpecError(
                f"{rule_set.name}: exclude names {', '.join(missing[:5])}, which the configured folders do "
                "not hold at the pinned commit"
            )
        unmatched = sorted(
            pattern
            for pattern in rule_set.rule_paths
            if not any(in_rule_path(path, pattern) for path in candidates)
        )
        if unmatched:
            raise SpecError(
                f"{rule_set.name}: rule_paths names {', '.join(unmatched[:5])}, which match no file in the "
                "configured folders at the pinned commit"
            )
        left_out: Counter[str] = Counter()
        inspect = []
        for path in candidates:
            reason = path_selection_reason(rule_set, path)
            if reason is None:
                inspect.append(path)
            else:
                left_out[reason] += 1
        paths = [rule_set.licence] + inspect
        downloaded = {path: get(raw_url(rule_set, path)) for path in paths}
        hashes = {rule_set.licence: atomics.sha256(downloaded[rule_set.licence])}
        for path in inspect:
            reason = selection_reason(rule_set, path, downloaded[path])
            if reason is None:
                hashes[path] = atomics.sha256(downloaded[path])
            else:
                left_out[reason] += 1
        locked = Locked(hashes, left_out)
        wanted(rule_set, locked)
        lines = [header(rule_set)] + selection_lines(rule_set, left_out)
        lines += [f"{locked[path]}  {path}" for path in sorted(locked)]
        sections.setdefault(rule_set.lock, []).extend(lines)
    written = []
    for name, lines in sections.items():
        path = spec.folder / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)
    return written

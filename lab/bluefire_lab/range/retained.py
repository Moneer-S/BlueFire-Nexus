"""Verify and copy a retained range run before judging its telemetry again."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path, PurePosixPath

from .. import replay as replay_page
from . import engine
from .spec import SpecError, load

SCHEMA = "bluefire.range-run/1"
PROVENANCE = "provenance.json"
GIT_HEAD = re.compile(r"[0-9a-f]{12}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
CLOCK = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")


class RetainedError(ValueError):
    """A retained folder or requested materialization is not safe to use."""


@dataclass(frozen=True)
class RetainedFile:
    stored_path: PurePosixPath
    run_path: PurePosixPath
    artifact_path: PurePosixPath
    role: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class RetainedRun:
    root: Path
    source: dict
    run: dict
    files: tuple[RetainedFile, ...]
    provenance_sha256: str


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    found = {}
    for key, value in pairs:
        if key in found:
            raise RetainedError("the JSON document repeats a key")
        found[key] = value
    return found


def _json(path: Path, what: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetainedError(f"{what} cannot be read as JSON: {error}") from error
    if not isinstance(value, dict):
        raise RetainedError(f"{what} must be a JSON object")
    return value


def _keys(value: dict, expected: set[str], what: str) -> None:
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"{len(missing)} required field(s) missing")
        if extra:
            parts.append(f"{len(extra)} unknown field(s)")
        raise RetainedError(f"{what} has " + "; ".join(parts))


def _text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) < 32 for c in value):
        raise RetainedError(f"{what} must be non-empty plain text")
    return value


def _integer(value: object, what: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        word = "non-negative" if zero else "positive"
        raise RetainedError(f"{what} must be a {word} integer")
    return value


def _path(value: object, what: str) -> PurePosixPath:
    value = _text(value, what)
    path = PurePosixPath(value)
    if (
        "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise RetainedError(f"{what} must be one normalized relative POSIX path")
    return path


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for piece in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(piece)
    return digest.hexdigest()


def _regular(path: Path, what: str) -> None:
    try:
        status = path.lstat()
    except OSError as error:
        raise RetainedError(f"{what} cannot be read: {error}") from error
    if stat.S_ISLNK(status.st_mode):
        raise RetainedError(f"{what} is a link; retained evidence must be regular files and folders")
    if not stat.S_ISREG(status.st_mode):
        raise RetainedError(f"{what} is not a regular file")
    if status.st_nlink != 1:
        raise RetainedError(f"{what} has more than one hard link; retained evidence must not contain links")


def _file(value: object, number: int) -> RetainedFile:
    what = f"files[{number}]"
    if not isinstance(value, dict):
        raise RetainedError(f"{what} must be an object")
    _keys(value, {"stored_path", "run_path", "artifact_path", "role", "bytes"}, what)
    stored = _path(value["stored_path"], f"{what}.stored_path")
    if stored.parts[0] != "files":
        raise RetainedError(f"{what}.stored_path must be below files/")
    run_path = _path(value["run_path"], f"{what}.run_path")
    if run_path.as_posix() == PROVENANCE:
        raise RetainedError(f"{what}.run_path cannot replace {PROVENANCE}")
    return RetainedFile(
        stored,
        run_path,
        _path(value["artifact_path"], f"{what}.artifact_path"),
        _text(value["role"], f"{what}.role"),
        _integer(value["bytes"], f"{what}.bytes", zero=True),
        "",
    )


def _source(value: object) -> dict:
    if not isinstance(value, dict):
        raise RetainedError("source must be an object")
    _keys(
        value,
        {"repository", "workflow", "run_id", "run_attempt", "job", "head", "run_url", "artifact"},
        "source",
    )
    repository = _text(value["repository"], "source.repository")
    if not REPOSITORY.fullmatch(repository):
        raise RetainedError("source.repository must be an owner and repository name")
    workflow = _path(value["workflow"], "source.workflow")
    if workflow.parts[:2] != (".github", "workflows") or workflow.suffix not in (".yml", ".yaml"):
        raise RetainedError("source.workflow must name a YAML file below .github/workflows/")
    run_id = _integer(value["run_id"], "source.run_id")
    run_url = _text(value["run_url"], "source.run_url")
    expected_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    if run_url != expected_url:
        raise RetainedError(f"source.run_url must be {expected_url}")
    _text(value["artifact"], "source.artifact")
    _integer(value["run_attempt"], "source.run_attempt")
    _text(value["job"], "source.job")
    head = _text(value["head"], "source.head")
    if not GIT_HEAD.fullmatch(head):
        raise RetainedError("source.head must be the first 12 lower-case hexadecimal digits of the commit")
    return value


def _run(value: object) -> dict:
    if not isinstance(value, dict):
        raise RetainedError("run must be an object")
    _keys(value, {"id", "spec", "result", "exit_code"}, "run")
    _text(value["id"], "run.id")
    _path(value["spec"], "run.spec")
    if value["result"] != "sealed" or value["exit_code"] != 0:
        raise RetainedError("run must record a sealed result with exit_code 0")
    return value


def _cross_check(root: Path, source: dict, run: dict, files: tuple[RetainedFile, ...]) -> None:
    by_run = {entry.run_path.as_posix(): entry for entry in files}
    missing = sorted({"manifest.json", run["spec"]} - by_run.keys())
    if missing:
        raise RetainedError("files must materialize " + " and ".join(missing))
    manifest_entry = by_run["manifest.json"]
    manifest = _json(root.joinpath(*manifest_entry.stored_path.parts), "the retained manifest")
    spec_entry = by_run[run["spec"]]
    try:
        pinned = load(root.joinpath(*spec_entry.stored_path.parts))
    except (OSError, SpecError) as error:
        raise RetainedError(f"the pinned run spec cannot be read: {error}") from error
    spec = manifest.get("spec")
    expected_spec = PurePosixPath(run["spec"]).name
    clock = manifest.get("recording_clock")
    checks = (
        (manifest.get("run_id") == run["id"], "the manifest run_id differs from run.id"),
        (manifest.get("run_url") == source["run_url"], "the manifest run_url differs from source.run_url"),
        (
            isinstance(spec, dict) and spec.get("file") == expected_spec,
            f"the retained manifest must name the pinned run spec {expected_spec}",
        ),
        (manifest.get("result") == "sealed", "the retained manifest does not say the run was sealed"),
        (manifest.get("exit_code") == 0, "the retained manifest does not have exit_code 0"),
        (manifest.get("teardown_complete") is True, "the retained manifest does not show complete teardown"),
        (
            isinstance(clock, dict),
            "the retained manifest has no recording_clock selected from the Docker event times",
        ),
        (manifest.get("range") == pinned.range, "the retained manifest and pinned spec name other ranges"),
    )
    for passed, message in checks:
        if not passed:
            raise RetainedError(message)
    _keys(clock, {"started", "ended", "basis"}, "manifest.recording_clock")
    _text(clock["basis"], "manifest.recording_clock.basis")
    values = [_text(clock[name], f"manifest.recording_clock.{name}") for name in ("started", "ended")]
    if not all(CLOCK.fullmatch(value) for value in values):
        raise RetainedError("manifest.recording_clock must hold two UTC times with microseconds")
    try:
        moments = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in values]
    except ValueError as error:
        raise RetainedError("manifest.recording_clock must hold two ISO times") from error
    if any(moment.tzinfo is None for moment in moments) or moments[1] < moments[0]:
        raise RetainedError("manifest.recording_clock must hold two ordered, timezone-aware times")


def verify_retained(root: Path) -> RetainedRun:
    """Verify one exact retained source tree and validate its declared provenance."""

    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise RetainedError(f"{root} is not a regular retained-run folder")
    root = root.resolve()
    provenance = root / PROVENANCE
    _regular(provenance, PROVENANCE)
    document = _json(provenance, PROVENANCE)
    _keys(document, {"schema", "source", "run", "files"}, PROVENANCE)
    if document["schema"] != SCHEMA:
        raise RetainedError(f"{PROVENANCE}.schema must be {SCHEMA}")
    source, run = _source(document["source"]), _run(document["run"])
    if not isinstance(document["files"], list) or not document["files"]:
        raise RetainedError(f"{PROVENANCE}.files must be a non-empty list")
    files = tuple(_file(value, number) for number, value in enumerate(document["files"]))
    stored = [entry.stored_path.as_posix() for entry in files]
    materialized = [entry.run_path.as_posix() for entry in files]
    artifacts = [entry.artifact_path.as_posix() for entry in files]
    if stored != sorted(stored):
        raise RetainedError("files must be sorted by stored_path")
    if len(set(stored)) != len(stored):
        raise RetainedError("two file entries have the same stored_path")
    if len(set(materialized)) != len(materialized):
        raise RetainedError("two file entries have the same run_path")
    if len(set(artifacts)) != len(artifacts):
        raise RetainedError("two file entries have the same artifact_path")

    actual = {PROVENANCE}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise RetainedError(f"{relative} is a link; retained evidence must not contain links")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode):
            raise RetainedError(f"{relative} is not a regular file or folder")
        if status.st_nlink != 1:
            raise RetainedError(
                f"{relative} has more than one hard link; retained evidence must not contain links"
            )
        actual.add(relative)
    expected = {PROVENANCE, *stored}
    missing, extra = sorted(expected - actual), sorted(actual - expected)
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("unlisted " + ", ".join(extra))
        raise RetainedError("the retained folder's exact file closure has " + "; ".join(parts))
    checked = []
    for entry in files:
        path = root.joinpath(*entry.stored_path.parts)
        _regular(path, entry.stored_path.as_posix())
        if path.stat().st_size != entry.bytes:
            raise RetainedError(f"{entry.stored_path} has another byte count")
        checked.append(replace(entry, sha256=_digest(path)))
    files = tuple(checked)
    _cross_check(root, source, run, files)
    return RetainedRun(root, source, run, files, _digest(provenance))


def _same_source(before: RetainedRun, after: RetainedRun) -> None:
    before_files = [(entry.stored_path, entry.bytes, entry.sha256) for entry in before.files]
    after_files = [(entry.stored_path, entry.bytes, entry.sha256) for entry in after.files]
    if (
        before.source != after.source
        or before.run != after.run
        or before.provenance_sha256 != after.provenance_sha256
        or before_files != after_files
    ):
        raise RetainedError("the retained source changed while its copy was being used")


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _output(retained: Path, out: Path) -> Path:
    out = Path(out).resolve(strict=False)
    if _lexists(out):
        raise RetainedError(f"{out} exists; rejudgment writes a new folder only")
    if out == retained or out.is_relative_to(retained) or retained.is_relative_to(out):
        raise RetainedError("the output and retained source folders must not contain one another")
    return out


def _temporary(out: Path) -> Path:
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f".{out.name}.partial-", dir=out.parent))
    except OSError as error:
        raise RetainedError(f"cannot create a private partial folder beside {out}: {error}") from error


def _copy(proof: RetainedRun, target: Path) -> None:
    for entry in proof.files:
        source = proof.root.joinpath(*entry.stored_path.parts)
        destination = target.joinpath(*entry.run_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with source.open("rb") as read, destination.open("xb") as written:
                shutil.copyfileobj(read, written, 1024 * 1024)
        except OSError as error:
            raise RetainedError(f"cannot materialize {entry.run_path}: {error}") from error
        if destination.stat().st_size != entry.bytes or _digest(destination) != entry.sha256:
            raise RetainedError(f"the materialized copy of {entry.run_path} differs from its retained bytes")


def _publish(work: Path, out: Path) -> None:
    if _lexists(out):
        raise RetainedError(f"{out} appeared while the new folder was being written")
    try:
        os.rename(work, out)
    except OSError as error:
        raise RetainedError(f"cannot publish {out}: {error}") from error


def materialize_retained(retained: Path, out: Path) -> RetainedRun:
    """Verify retained bytes, copy them to their canonical run paths, and publish a new folder."""

    proof = verify_retained(retained)
    out = _output(proof.root, out)
    work = _temporary(out)
    try:
        _copy(proof, work)
        _same_source(proof, verify_retained(proof.root))
        _publish(work, out)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    return proof


def rejudge(
    retained: Path,
    defenses: Path,
    out: Path,
    template: Path,
    rule_engine: Path | None = None,
    *,
    suricata_image: str | None = None,
) -> int:
    """Validate, copy and rejudge a retained run, then write its standalone replay page."""

    try:
        proof = verify_retained(retained)
        out = _output(proof.root, out)
        judged_by = load(defenses)
        if judged_by.rule_sets and rule_engine is None:
            raise RetainedError("the judging spec has rule sets, so --engine is required")
        if rule_engine is not None and not Path(rule_engine).is_file():
            raise RetainedError(f"the rule engine {rule_engine} is not a file")
        if not Path(template).is_file():
            raise RetainedError(f"the replay template {template} is not a file")
    except (OSError, RetainedError, SpecError) as error:
        print(f"bluefire-lab range rejudge: {error}", file=sys.stderr)
        return 2

    work = _temporary(out)
    published = False
    try:
        _copy(proof, work)
        recording = work / "recording.json"
        if recording.is_symlink() or (recording.exists() and not recording.is_file()):
            raise RetainedError("the materialized recording.json is not a regular file")
        recording.unlink(missing_ok=True)
        run_spec = work.joinpath(*PurePosixPath(proof.run["spec"]).parts)
        original = load(run_spec)
        manifest_path = work / "manifest.json"
        manifest = _json(manifest_path, "the materialized manifest")
        manifest["spec"] = {"file": run_spec.name, "sha256": original.sha256, "text": original.text}
        engine.write_json(manifest_path, manifest)
        if judged_by.rule_sets and engine.rules(defenses, work) != 0:
            return 1
        code = engine.rescore(work, rule_engine, defenses, suricata_image=suricata_image)
        if code != 0:
            return code
        _regular(recording, "the newly generated recording.json")
        page = work / "replay.html"
        if page.is_symlink() or (page.exists() and not page.is_file()):
            raise RetainedError("the materialized replay.html is not a regular file")
        page.unlink(missing_ok=True)
        code = replay_page.main(recording, template, page)
        if code != 0:
            return code
        # A concurrent edit of the source is caught before the derived folder becomes visible.
        _same_source(proof, verify_retained(proof.root))
        _publish(work, out)
        published = True
    except (OSError, RetainedError, SpecError) as error:
        print(f"bluefire-lab range rejudge: {error}", file=sys.stderr)
        return 2
    finally:
        if not published:
            shutil.rmtree(work, ignore_errors=True)
    print(f"{out}: rejudged retained range run {proof.run['id']}")
    print(f"{out / 'recording.json'}: recording for the app")
    print(f"{out / 'replay.html'}: standalone replay page")
    return 0

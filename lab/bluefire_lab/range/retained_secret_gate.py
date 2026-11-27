"""Certify non-secret fingerprints before scanning a retained candidate's raw bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import atomics, retained_occurrences
from .retained import RetainedError, RetainedRun, verify_retained
from .spec import Spec, SpecError, load

SCANNER_VERSION = "1.5.0"
FINDING_TYPE = "Hex High Entropy String"
SCRIPT_RUN_PATH = PurePosixPath("atomics/T1105/src/atomic.sh")
SCRIPT_FIM_PATH = "/tmp/atomic.sh"
HEX = {"md5": 32, "sha1": 40, "sha256": 64}
EVENTS = {
    "added": ("syscheck_new_entry", "554", ("after",)),
    "modified": ("syscheck_integrity_changed", "550", ("before", "after")),
    "deleted": ("syscheck_deleted", "553", ("after",)),
}
SAFE_FINDING_KEYS = {"type", "filename", "hashed_secret", "is_verified", "line_number", "is_secret"}


class CandidateSecretError(ValueError):
    """The retained candidate cannot safely receive a fingerprint-only baseline."""


@dataclass(frozen=True)
class Certification:
    """A scanner identity whose plaintext occurrences have all been proved."""

    filename: str
    value: str
    lines: frozenset[int]

    @property
    def secret_hash(self) -> str:
        return hashlib.sha1(self.value.encode()).hexdigest()  # noqa: S324 - detector identity


def _json_data(data: bytes, what: str) -> dict:
    try:
        value = retained_occurrences.loads_object(data, what)
    except ValueError as error:
        raise CandidateSecretError(str(error)) from error
    return value


def _json_file(path: Path, what: str) -> tuple[dict, bytes]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CandidateSecretError(f"{what} cannot be read: {error}") from error
    return _json_data(data, what), data


def _ndjson(path: Path, what: str) -> tuple[list[dict], bytes]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CandidateSecretError(f"{what} cannot be read: {error}") from error
    records = []
    for number, line in enumerate(data.splitlines(), start=1):
        if not line:
            raise CandidateSecretError(f"{what} line {number} is empty")
        records.append(_json_data(line, f"{what} line {number}"))
    if not records:
        raise CandidateSecretError(f"{what} is empty")
    return records, data


def _digest(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    try:
        with path.open("rb") as stream:
            for piece in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(piece)
    except OSError as error:
        raise CandidateSecretError(f"{path} cannot be hashed: {error}") from error
    return digest.hexdigest()


def _regular(path: Path, what: str) -> None:
    try:
        status = path.lstat()
    except OSError as error:
        raise CandidateSecretError(f"{what} cannot be inspected: {error}") from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise CandidateSecretError(f"{what} must be one regular, unlinked file")


def _entry_path(proof: RetainedRun, run_path: str, role: str | None = None) -> Path:
    matches = [entry for entry in proof.files if entry.run_path.as_posix() == run_path]
    if len(matches) != 1 or (role is not None and matches[0].role != role):
        raise CandidateSecretError(f"the retained provenance does not declare exactly one {run_path}")
    return proof.root.joinpath(*matches[0].stored_path.parts)


def _pointer(parts: tuple[object, ...]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped)


def _line_numbers(data: bytes, value: str) -> frozenset[int]:
    encoded = value.encode()
    return frozenset(number for number, line in enumerate(data.splitlines(), start=1) if encoded in line)


def _relative_file(repository: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repository.resolve()).as_posix()
    except ValueError as error:
        raise CandidateSecretError(f"{path} is not below the candidate repository {repository}") from error


def _audit(value: object, plaintext: str, expected: Counter[tuple[str, str]], what: str) -> None:
    actual = retained_occurrences.occurrence_locations(value, plaintext)
    if actual != expected:
        categories = ", ".join(f"{kind}:{pointer}" for kind, pointer in sorted(actual)) or "none"
        raise CandidateSecretError(
            f"{what} occurs outside its approved JSON locations; observed {categories}"
        )


def _manifest_certifications(
    repository: Path,
    proof: RetainedRun,
    spec: Spec,
) -> list[Certification]:
    path = _entry_path(proof, "manifest.json", "minimal truthful run context")
    manifest, data = _json_file(path, "the retained manifest")
    atomic = manifest.get("atomic_red_team")
    if not isinstance(atomic, dict) or set(atomic) != {"commit"} or atomic["commit"] != spec.atomics.commit:
        raise CandidateSecretError(
            "the retained manifest Atomic Red Team commit differs from the tracked spec"
        )

    approved: dict[str, Counter[tuple[str, str]]] = {
        spec.atomics.commit: Counter({("string", "/atomic_red_team/commit"): 1})
    }
    capture = manifest.get("packet_capture")
    hosts = capture.get("hosts") if isinstance(capture, dict) else None
    expected_hosts = {name for name, settings in spec.hosts.items() if settings.capture == "packets"}
    if not isinstance(hosts, dict) or set(hosts) != expected_hosts:
        raise CandidateSecretError("the retained manifest packet hosts differ from the tracked spec")
    for host, host_record in hosts.items():
        files = host_record.get("files") if isinstance(host_record, dict) else None
        if not isinstance(files, dict) or not files:
            raise CandidateSecretError(f"the retained manifest has no packet files for {host}")
        for name, record in files.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+[.]pcap", name)
                or not isinstance(record, dict)
            ):
                raise CandidateSecretError(f"the retained manifest has an unsafe packet record for {host}")
            run_path = f"raw/hosts/{host}/var/log/bluefire/packets/{name}"
            if record.get("file") != run_path:
                raise CandidateSecretError(
                    f"the retained manifest packet path for {host}/{name} is not canonical"
                )
            packet = _entry_path(proof, run_path, "raw packet capture")
            digest = _digest(packet)
            if record.get("sha256") != digest:
                raise CandidateSecretError(f"the retained manifest packet digest for {host}/{name} is false")
            location = ("string", _pointer(("packet_capture", "hosts", host, "files", name, "sha256")))
            approved.setdefault(digest, Counter())[location] += 1

    filename = _relative_file(repository, path)
    certified = []
    for plaintext, expected in approved.items():
        _audit(manifest, plaintext, expected, "a certified manifest fingerprint")
        certified.append(Certification(filename, plaintext, _line_numbers(data, plaintext)))
    return certified


def _script_hashes(spec: Spec, script: Path) -> dict[str, str]:
    if spec.atomics is None or spec.folder is None:
        raise CandidateSecretError("the tracked spec has no Atomic Red Team pin")
    _regular(script, "the rendered Atomic Red Team script")
    lock_path = spec.folder / spec.atomics.lock
    try:
        locked = atomics.read_lock(lock_path.read_text(encoding="utf-8"), spec)
    except (OSError, UnicodeDecodeError, SpecError) as error:
        raise CandidateSecretError(f"the tracked Atomic Red Team lock cannot be verified: {error}") from error
    expected = locked.get(SCRIPT_RUN_PATH.as_posix())
    if expected is None or _digest(script) != expected:
        raise CandidateSecretError("the rendered T1105 script differs from the tracked Atomic Red Team lock")
    return {name: _digest(script, name) for name in HEX}


def _event_semantics(record: dict) -> str:
    semantic = {key: value for key, value in record.items() if key != "id"}
    return json.dumps(semantic, sort_keys=True, separators=(",", ":"))


def _full_log_occurrences(full_log: str, event: str, hashes: dict[str, str]) -> Counter[str]:
    first = f"File '{SCRIPT_FIM_PATH}' {event}\nMode: realtime\n"
    if event != "modified":
        if full_log != first:
            raise CandidateSecretError(f"the {event} Atomic script FIM full_log is not canonical")
        return Counter()
    if not full_log.startswith(first):
        raise CandidateSecretError("the modified Atomic script FIM full_log is not canonical")
    expected_lines = []
    for algorithm, digest in hashes.items():
        expected_lines.extend([f"Old {algorithm}sum was: '{digest}'", f"New {algorithm}sum is : '{digest}'"])
    lines = full_log.splitlines()
    for line in expected_lines:
        if lines.count(line) != 1:
            raise CandidateSecretError("the modified Atomic script FIM checksum clauses are not exact")
    found = Counter()
    for digest in hashes.values():
        found[digest] = full_log.count(digest)
        if found[digest] != 2:
            raise CandidateSecretError("the modified Atomic script FIM checksum count is not exact")
    return found


def _fim_record(record: dict, hashes: dict[str, str]) -> tuple[str, dict[str, Counter[tuple[str, str]]]]:
    syscheck = record.get("syscheck")
    rule = record.get("rule")
    decoder = record.get("decoder")
    agent = record.get("agent")
    if not all(isinstance(value, dict) for value in (syscheck, rule, decoder, agent)):
        raise CandidateSecretError("an Atomic script FIM event lacks its structured context")
    event = syscheck.get("event")
    if event not in EVENTS:
        raise CandidateSecretError("an Atomic script FIM event has an unknown event kind")
    expected_decoder, expected_rule, suffixes = EVENTS[event]
    expected_groups = {"ossec", "syscheck", f"syscheck_entry_{event}", "syscheck_file"}
    groups = rule.get("groups")
    if (
        record.get("location") != "syscheck"
        or agent.get("name") != "web"
        or syscheck.get("path") != SCRIPT_FIM_PATH
        or syscheck.get("mode") != "realtime"
        or decoder.get("name") != expected_decoder
        or rule.get("id") != expected_rule
        or not isinstance(groups, list)
        or not all(isinstance(group, str) for group in groups)
        or not expected_groups.issubset(set(groups))
    ):
        raise CandidateSecretError("an Atomic script FIM event is outside the canonical sensor context")

    expected_fields = {f"{algorithm}_{suffix}" for suffix in suffixes for algorithm in HEX}
    actual_fields = {key for key in syscheck if re.fullmatch(r"(?:md5|sha1|sha256)_(?:before|after)", key)}
    if actual_fields != expected_fields:
        raise CandidateSecretError(f"the {event} Atomic script FIM digest fields are incomplete or extra")
    approved: dict[str, Counter[tuple[str, str]]] = {digest: Counter() for digest in hashes.values()}
    for suffix in suffixes:
        for algorithm, digest in hashes.items():
            field = f"{algorithm}_{suffix}"
            if syscheck.get(field) != digest or not re.fullmatch(rf"[0-9a-f]{{{HEX[algorithm]}}}", digest):
                raise CandidateSecretError(
                    f"the {event} Atomic script FIM {field} differs from the fetched script"
                )
            approved[digest][("string", f"/syscheck/{field}")] += 1
    full_log = record.get("full_log")
    if not isinstance(full_log, str):
        raise CandidateSecretError("an Atomic script FIM event has no full_log")
    for digest, count in _full_log_occurrences(full_log, event, hashes).items():
        approved[digest][("string", "/full_log")] += count
    for digest, expected in approved.items():
        _audit(record, digest, expected, "a fetched-script digest in an Atomic script FIM event")
    return event, approved


def _wazuh_certifications(
    repository: Path,
    proof: RetainedRun,
    spec: Spec,
    hashes: dict[str, str],
) -> list[Certification]:
    manager = spec.manager
    if manager is None:
        raise CandidateSecretError("the tracked spec has no Wazuh manager")
    streams = {}
    for kind in ("archives", "alerts"):
        run_path = f"raw/hosts/{manager}/var/ossec/logs/{kind}/{kind}.json"
        role = "complete raw Wazuh archive" if kind == "archives" else "complete raw Wazuh alerts"
        path = _entry_path(proof, run_path, role)
        records, data = _ndjson(path, f"the retained Wazuh {kind}")
        selected = []
        approved_by_line: dict[int, dict[str, Counter[tuple[str, str]]]] = {}
        observed: Counter[tuple[str, str]] = Counter()
        for number, record in enumerate(records, start=1):
            syscheck = record.get("syscheck")
            digest_fields = (
                {key for key in syscheck if re.fullmatch(r"(?:md5|sha1|sha256)_(?:before|after)", key)}
                if isinstance(syscheck, dict)
                else set()
            )
            if digest_fields:
                fim_path = syscheck.get("path")
                path_class = (
                    "atomic-script"
                    if fim_path == SCRIPT_FIM_PATH
                    else "tmp-other"
                    if isinstance(fim_path, str) and fim_path.startswith("/tmp/")
                    else "outside-tmp"
                )
                event = syscheck.get("event")
                event_class = event if event in EVENTS else "unknown"
                observed[(path_class, event_class)] += 1
            if isinstance(syscheck, dict) and syscheck.get("path") == SCRIPT_FIM_PATH:
                checked_event, approved = _fim_record(record, hashes)
                selected.append((checked_event, _event_semantics(record), number))
                approved_by_line[number] = approved
        if len(selected) != 3 or {event for event, _, _ in selected} != set(EVENTS):
            description = (
                ", ".join(
                    f"{count} {path_class}/{event}" for (path_class, event), count in sorted(observed.items())
                )
                or "none"
            )
            raise CandidateSecretError(
                "the retained Wazuh "
                f"{kind} must have one added, modified and deleted Atomic script event; observed {description}"
            )
        streams[kind] = (path, records, data, selected, approved_by_line)

    archive_semantics = Counter(semantics for _, semantics, _ in streams["archives"][3])
    alert_semantics = Counter(semantics for _, semantics, _ in streams["alerts"][3])
    if archive_semantics != alert_semantics or any(count != 1 for count in archive_semantics.values()):
        raise CandidateSecretError(
            "the Atomic script FIM events are not mirrored one-to-one in archives and alerts"
        )

    certified = []
    for kind in ("archives", "alerts"):
        path, records, data, _, approved_by_line = streams[kind]
        filename = _relative_file(repository, path)
        for digest in hashes.values():
            actual: Counter[tuple[int, str, str]] = Counter()
            expected: Counter[tuple[int, str, str]] = Counter()
            for number, record in enumerate(records, start=1):
                for location, count in retained_occurrences.occurrence_locations(record, digest).items():
                    actual[(number, *location)] += count
                for location, count in approved_by_line.get(number, {}).get(digest, {}).items():
                    expected[(number, *location)] += count
            if actual != expected:
                categories = (
                    ", ".join(
                        f"line-{number}:{kind_name}:{pointer}"
                        for number, kind_name, pointer in sorted(actual)
                    )
                    or "none"
                )
                raise CandidateSecretError(
                    f"a fetched-script digest occurs outside approved Wazuh {kind} locations; observed {categories}"
                )
            certified.append(Certification(filename, digest, _line_numbers(data, digest)))
    return certified


def certify(
    repository: Path,
    candidate: Path,
    spec_path: Path,
    script: Path,
    source_head: str,
) -> tuple[RetainedRun, list[Certification], list[str]]:
    """Verify candidate semantics and return only independently proved scanner identities."""

    repository = repository.resolve()
    candidate = candidate.resolve()
    try:
        proof = verify_retained(candidate)
    except RetainedError as error:
        raise CandidateSecretError(str(error)) from error
    if not re.fullmatch(r"[0-9a-f]{40}", source_head) or proof.source["head"] != source_head[:12]:
        raise CandidateSecretError("the retained source head differs from the checked-out workflow head")
    candidate_spec = _entry_path(proof, proof.run["spec"], "exact tracked run spec")
    try:
        if candidate_spec.read_bytes() != spec_path.read_bytes():
            raise CandidateSecretError("the retained run spec differs byte-for-byte from the tracked spec")
        spec = load(spec_path)
    except (OSError, SpecError) as error:
        raise CandidateSecretError(f"the tracked spec cannot be loaded: {error}") from error
    if spec.atomics is None:
        raise CandidateSecretError("the tracked spec has no Atomic Red Team pin")
    hashes = _script_hashes(spec, script)
    certified = _manifest_certifications(repository, proof, spec)
    certified += _wazuh_certifications(repository, proof, spec, hashes)

    expected = {_relative_file(repository, proof.root / "provenance.json")}
    expected.update(
        _relative_file(repository, proof.root.joinpath(*entry.stored_path.parts)) for entry in proof.files
    )
    try:
        tracked_data = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
        tracked = sorted(path for path in tracked_data.decode().rstrip("\0").split("\0") if path)
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError) as error:
        raise CandidateSecretError(
            f"the scanner repository's tracked closure cannot be read: {error}"
        ) from error
    if set(tracked) != expected:
        raise CandidateSecretError(
            "the scanner repository does not track the retained candidate's exact closure"
        )
    if any(PurePosixPath(path).name == ".secrets.baseline" for path in tracked):
        raise CandidateSecretError("the retained candidate must not contain a scanner baseline file")
    return proof, certified, tracked


def _write_json_exclusive(path: Path, value: object) -> None:
    data = (json.dumps(value, indent=2) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    except OSError as error:
        raise CandidateSecretError(f"cannot create private scanner baseline {path}: {error}") from error


def _strict_report(text: str) -> dict:
    try:
        return retained_occurrences.loads_object(text.encode(), "the raw candidate pre-scan report")
    except ValueError as error:
        raise CandidateSecretError(str(error)) from error


def _runtime_filters(filters: list, baseline_path: Path) -> list:
    normalized = json.loads(json.dumps(filters))
    matches = [
        entry
        for entry in normalized
        if isinstance(entry, dict)
        and entry.get("path") == "detect_secrets.filters.common.is_baseline_file"
        and entry.get("filename") == ".secrets.baseline"
    ]
    if len(matches) != 1:
        raise CandidateSecretError("the tracked scanner baseline has another baseline-file filter")
    matches[0]["filename"] = str(baseline_path)
    return normalized


def prepare_baseline(
    repository: Path,
    candidate: Path,
    spec_path: Path,
    script: Path,
    source_head: str,
    tracked_baseline: Path,
    scanner_hook: Path,
    out: Path,
) -> int:
    """Write a private baseline containing only findings matched to certified fingerprints."""

    _, certifications, tracked = certify(repository, candidate, spec_path, script, source_head)
    baseline, _ = _json_file(tracked_baseline, "the tracked scanner baseline")
    if baseline.get("version") != SCANNER_VERSION:
        raise CandidateSecretError(f"the tracked scanner baseline must use detect-secrets {SCANNER_VERSION}")
    if not isinstance(baseline.get("plugins_used"), list) or not isinstance(
        baseline.get("filters_used"), list
    ):
        raise CandidateSecretError(
            "the tracked scanner baseline has no exact plugin and filter configuration"
        )
    settings = {
        "version": baseline["version"],
        "plugins_used": baseline["plugins_used"],
        "filters_used": baseline["filters_used"],
        "results": {},
    }
    out = out.resolve(strict=False)
    if not out.parent.is_dir():
        raise CandidateSecretError("the private baseline parent does not exist")
    with tempfile.TemporaryDirectory(prefix="retained-secret-settings-", dir=out.parent) as folder:
        settings_path = Path(folder) / "settings.json"
        _write_json_exclusive(settings_path, settings)
        runtime_filters = _runtime_filters(settings["filters_used"], settings_path)
        try:
            version = subprocess.run(
                [str(scanner_hook), "--version"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            if version.returncode != 0 or version.stdout.strip() != SCANNER_VERSION or version.stderr.strip():
                raise CandidateSecretError(
                    f"the raw candidate scanner must be detect-secrets {SCANNER_VERSION}"
                )
            process = subprocess.run(
                [str(scanner_hook), "--json", "--baseline", str(settings_path), *tracked],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as error:
            raise CandidateSecretError(f"the raw candidate pre-scan could not start: {error}") from error
    if process.returncode not in (0, 1):
        raise CandidateSecretError("the raw candidate pre-scan could not run to completion")
    if process.stderr.strip():
        raise CandidateSecretError("the raw candidate pre-scan wrote an unexpected diagnostic")
    if process.returncode == 0:
        if process.stdout.strip():
            raise CandidateSecretError("the clean raw candidate pre-scan printed an unexpected report")
        report = {**settings, "results": {}}
    else:
        report = _strict_report(process.stdout)
    if (
        report.get("version") != settings["version"]
        or report.get("plugins_used") != settings["plugins_used"]
        or report.get("filters_used") != runtime_filters
        or not isinstance(report.get("results"), dict)
    ):
        raise CandidateSecretError("the raw candidate pre-scan changed its pinned configuration")

    approved = {(item.filename, FINDING_TYPE, item.secret_hash): item for item in certifications}
    matched: dict[str, list[dict]] = {}
    count = 0
    for filename, findings in report["results"].items():
        if filename not in tracked or not isinstance(findings, list):
            raise CandidateSecretError("the raw candidate pre-scan reported an unknown file")
        for finding in findings:
            if not isinstance(finding, dict) or not set(finding).issubset(SAFE_FINDING_KEYS):
                raise CandidateSecretError("the raw candidate pre-scan reported an unknown finding shape")
            if finding.get("filename") != filename:
                raise CandidateSecretError(
                    "the raw candidate pre-scan finding disagrees with its file bucket"
                )
            identity = (finding.get("filename"), finding.get("type"), finding.get("hashed_secret"))
            certification = approved.get(identity)
            line = finding.get("line_number")
            if certification is None or type(line) is not int or line not in certification.lines:
                raise CandidateSecretError(
                    "the raw candidate contains a finding outside a certified fingerprint"
                )
            matched.setdefault(filename, []).append(finding)
            count += 1
    if count == 0:
        raise CandidateSecretError("the retained candidate produced no certified fingerprint findings")
    exact = {**settings, "results": matched}
    _write_json_exclusive(out, exact)
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--tracked-baseline", type=Path, required=True)
    parser.add_argument("--scanner-hook", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        count = prepare_baseline(
            arguments.repository,
            arguments.candidate,
            arguments.spec,
            arguments.script,
            arguments.source_head,
            arguments.tracked_baseline,
            arguments.scanner_hook,
            arguments.out,
        )
    except (CandidateSecretError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f"Certified {count} raw scanner findings as source-bound cryptographic fingerprints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Run Suricata over retained web PCAPs without a network, then read its evidence.

The adapter accepts one already-held rule-set folder. It gives that folder and
one retained capture at a time to a pinned container read-only, gives each
invocation one writable output folder, and does not pull an image or join a
network. EVE records stay raw: validation and alert-to-event linking never
invent or rewrite network evidence.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TypeAlias

from . import packets

ENGINE = "Suricata"
IMAGE = "jasonish/suricata:8.0.8@sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3"
IMAGE_PIN = re.compile(r"[^/@\s]+(?:/[^/@\s]+)*:[^@\s]+@sha256:[0-9a-f]{64}\Z")
EVE_TYPES = ("alert", "flow", "http", "tls", "ssh", "dns")
NETWORK_TYPES = EVE_TYPES[1:]
APP_TYPES = EVE_TYPES[2:]
COMMUNITY_ID_SEED = 0
EVE_CONFIG_TARGET = "/tmp/bluefire-eve.yaml"
EVE_CONFIG = f"""%YAML 1.1
---
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      pcap-file: yes
      community-id: yes
      community-id-seed: {COMMUNITY_ID_SEED}
      types:
        - alert:
            tagged-packets: yes
        - flow
        - http:
            extended: yes
        - tls:
            extended: yes
        - ssh
        - dns
  - stats:
      enabled: yes
      filename: stats.log
      append: no
      totals: yes
      threads: no
"""
CONTAINER_USER = "998:998"
CONTAINER_PREFIX = "bluefire-suricata-"
CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
ENGINE_SECONDS = 900
CLEANUP_SECONDS = 30
Runner = Callable[[list[str], float], subprocess.CompletedProcess[str]]
EventKey: TypeAlias = tuple[object, ...]

VERSION_LINE = re.compile(
    r"\bSuricata version ([0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?)\b",
    re.IGNORECASE,
)
RULES_LOADED = re.compile(r"\b([0-9]+) rules successfully loaded\b", re.IGNORECASE)
RULES_FAILED = re.compile(r"\b([0-9]+) rules failed\b", re.IGNORECASE)
STAT_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
LOAD_ERROR = re.compile(r"\b(?:error|failed|failure|invalid signature)\b", re.IGNORECASE)
MAX_LOAD_ERRORS = 20
MAX_LOAD_ERROR_LENGTH = 300


class SuricataError(RuntimeError):
    """A held input, offline engine result, or link between its records is invalid."""


def valid_image(value: object) -> bool:
    """Whether value is a container reference with both a tag and immutable digest."""

    return isinstance(value, str) and IMAGE_PIN.fullmatch(value) is not None


def severity(value: object) -> str:
    """Map Suricata's numeric alert priority to the recording's words."""

    if type(value) is not int:
        return "informational"
    return {1: "high", 2: "medium", 3: "low"}.get(value, "informational")


def _run(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        timeout=timeout,
    )


def _folder(path: Path, description: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise SuricataError(f"the {description} is a link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise SuricataError(f"the {description} cannot be read: {error}") from error
    if not resolved.is_dir():
        raise SuricataError(f"the {description} is not a folder")
    return resolved


def _relative(path: Path, root: Path, description: str) -> str:
    if path.is_symlink():
        raise SuricataError(f"{description} is a link")
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise SuricataError(f"{description} is outside its held folder") from error
    if not resolved.is_file():
        raise SuricataError(f"{description} is not a regular file")
    name = PurePosixPath(*relative.parts).as_posix()
    if not name or any(character in name for character in ("\0", "\n", "\r")):
        raise SuricataError(f"{description} has an unsafe name")
    return name


def _held_rules(
    folder: Path,
) -> tuple[Path, list[tuple[Path, str]], tuple[Path, str] | None]:
    root = _folder(folder, "held rule-set folder")
    try:
        entries = list(root.rglob("*"))
    except OSError as error:
        raise SuricataError(f"the held rule-set folder cannot be listed: {error}") from error
    linked = next((entry for entry in entries if entry.is_symlink()), None)
    if linked is not None:
        raise SuricataError(f"the held rule-set path {linked.relative_to(root).as_posix()} is a link")

    rule_paths = sorted(
        (entry for entry in entries if entry.name.endswith(".rules")),
        key=lambda entry: entry.relative_to(root).as_posix(),
    )
    if not rule_paths:
        raise SuricataError("the held rule-set folder has no .rules file")
    rules = [
        (path, _relative(path, root, f"the rule file {path.relative_to(root).as_posix()}"))
        for path in rule_paths
    ]

    configs = [entry for entry in entries if entry.name == "classification.config"]
    if len(configs) > 1:
        raise SuricataError("the held rule-set folder has more than one classification.config")
    classification = None
    if configs:
        config = configs[0]
        classification = (config, _relative(config, root, "classification.config"))
    return root, rules, classification


def _captures(folder: Path) -> tuple[Path, list[Path], dict[str, dict]]:
    root = _folder(folder, "web capture folder")
    try:
        entries = list(root.rglob("*"))
    except OSError as error:
        raise SuricataError(f"the web capture folder cannot be listed: {error}") from error
    linked = next((entry for entry in entries if entry.is_symlink()), None)
    if linked is not None:
        raise SuricataError(f"the web capture path {linked.relative_to(root).as_posix()} is a link")
    pcap_entries = [path for path in entries if path.name.endswith(".pcap")]
    nested = next((path for path in pcap_entries if path.parent != root), None)
    if nested is not None:
        raise SuricataError(f"the capture {nested.relative_to(root).as_posix()} is not a top-level web PCAP")
    found = sorted(pcap_entries)
    if not found:
        raise SuricataError("the web capture folder has no classic .pcap file")
    facts = {}
    for path in found:
        _relative(path, root, f"the capture {path.name}")
        try:
            facts[path.name] = packets.pcap(path)
        except (OSError, packets.CaptureError) as error:
            raise SuricataError(f"the capture {path.name} is not a complete classic PCAP: {error}") from error
        if facts[path.name]["packets"] == 0:
            raise SuricataError(f"the capture {path.name} contains no packet")
    return root, found, facts


def _stage_captures(paths: Sequence[Path], facts: dict[str, dict], folder: Path) -> Path:
    """Copy only independently parsed PCAP bytes into one read-only container input."""

    for source in paths:
        target = folder / source.name
        try:
            shutil.copyfile(source, target)
            if packets.pcap(target) != facts[source.name]:
                raise SuricataError(f"the staged capture {source.name} does not match the retained PCAP")
            target.chmod(0o444)
        except SuricataError:
            raise
        except (OSError, packets.CaptureError) as error:
            raise SuricataError(f"the capture {source.name} cannot be staged safely: {error}") from error
    try:
        folder.chmod(0o555)
    except OSError as error:
        raise SuricataError(f"the staged capture folder cannot be made read-only: {error}") from error
    return folder


def _mount_source(path: Path) -> str:
    value = str(path)
    if any(character in value for character in (",", "\0", "\n", "\r")):
        raise SuricataError("a Docker mount source has a character --mount cannot represent")
    return value


def _stage_eve_config(folder: Path) -> Path:
    """Write the exact YAML sequence that replaces the image's stock outputs."""

    path = folder / "eve.yaml"
    try:
        path.write_text(EVE_CONFIG, encoding="utf-8")
        path.chmod(0o444)
    except OSError as error:
        raise SuricataError(f"the Suricata EVE configuration cannot be staged: {error}") from error
    return path


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _prepare_output(path: Path, captures: Path, rules: Path | None = None) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise SuricataError("the Suricata output folder is a link")
    resolved = candidate.resolve(strict=False)
    if _overlap(resolved, captures) or (rules is not None and _overlap(resolved, rules)):
        raise SuricataError("the Suricata output folder overlaps a read-only input folder")
    if candidate.exists():
        if not candidate.is_dir():
            raise SuricataError("the Suricata output path is not a folder")
        try:
            if any(candidate.iterdir()):
                raise SuricataError("the Suricata output folder is not empty")
        except OSError as error:
            raise SuricataError(f"the Suricata output folder cannot be listed: {error}") from error
    else:
        try:
            candidate.mkdir(parents=True)
        except OSError as error:
            raise SuricataError(f"the Suricata output folder cannot be made: {error}") from error
    try:
        candidate.chmod(0o700)
    except OSError as error:
        raise SuricataError(f"the Suricata output folder cannot be made private: {error}") from error
    return candidate.resolve(strict=True)


def _addresses(values: Sequence[str]) -> list[str]:
    found: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise SuricataError("HOME_NET contains a value that is not an address")
        try:
            found.add(str(ipaddress.ip_address(value)))
        except ValueError as error:
            raise SuricataError(f"HOME_NET contains an invalid address {value!r}") from error
    if not found:
        raise SuricataError("HOME_NET has no protected sensor-host address")
    return sorted(found, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))


def _docker_command(
    image: str,
    captures: Path,
    capture: str,
    home_net: Sequence[str],
    output: Path,
    container_name: str,
    cidfile: Path,
    eve_config: Path,
    rules: Path | None = None,
    rule_files: Sequence[tuple[Path, str]] = (),
    classification: tuple[Path, str] | None = None,
) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--cidfile",
        str(cidfile),
        "--network",
        "none",
        "--pull",
        "never",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--user",
        CONTAINER_USER,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,source={_mount_source(captures)},target=/captures,readonly",
        "--mount",
        f"type=bind,source={_mount_source(eve_config)},target={EVE_CONFIG_TARGET},readonly",
    ]
    if rules is not None:
        command.extend(
            (
                "--mount",
                f"type=bind,source={_mount_source(rules)},target=/rules,readonly",
            )
        )
    command.extend(
        (
            "--mount",
            f"type=bind,source={_mount_source(output)},target=/output",
            "--entrypoint",
            "/usr/bin/suricata",
            image,
            "-c",
            "/etc/suricata/suricata.yaml",
            "--include",
            EVE_CONFIG_TARGET,
            "-r",
            f"/captures/{capture}",
            "--runmode",
            "single",
            "-l",
            "/output",
            "-k",
            "none",
            "--set",
            f"vars.address-groups.HOME_NET=[{','.join(home_net)}]",
        )
    )
    if rules is None:
        command.append("--disable-detection")
    else:
        command.extend(("--set", "default-rule-path=/rules"))
        for number, (_, relative) in enumerate(rule_files):
            command.extend(("--set", f"rule-files.{number}={relative}"))
        if classification is not None:
            command.extend(("--set", f"classification-file=/rules/{classification[1]}"))
    command.extend(
        (
            "--set",
            "stats.enabled=yes",
            "--set",
            "stats.interval=1",
        )
    )
    return command


def capture_files(folder: Path) -> tuple[Path, ...]:
    """The exact regular, non-linked classic PCAP files evaluation will read."""

    _, found, _ = _captures(Path(folder))
    return tuple(found)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    found: dict = {}
    for key, value in pairs:
        if key in found:
            raise ValueError(f"duplicate key {key!r}")
        found[key] = value
    return found


def _nonfinite(value: str) -> object:
    raise ValueError(f"{value} is not a JSON number")


def _timestamp(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SuricataError(f"{where} has no timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SuricataError(f"{where} has an invalid timestamp {value!r}") from error
    if parsed.tzinfo is None:
        raise SuricataError(f"{where} has a timestamp without a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _integer(value: object, description: str) -> int:
    if type(value) is not int or value < 0:
        raise SuricataError(f"{description} is not a non-negative integer")
    return value


def _port(raw: dict, name: str, where: str) -> int | None:
    if name not in raw:
        return None
    value = raw[name]
    if type(value) is not int or not 0 <= value <= 65_535:
        raise SuricataError(f"{where}'s {name} is not a network port")
    return value


def _container_capture(value: object, where: str, *, allow_unknown: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise SuricataError(f"{where} has no pcap_filename")
    if allow_unknown and value == "unknown":
        return value
    if "\\" in value or "\0" in value or "\n" in value or "\r" in value:
        raise SuricataError(f"{where}'s pcap_filename is unsafe")
    parts = value.split("/")
    if (
        len(parts) < 3
        or parts[0] != ""
        or parts[1] != "captures"
        or any(part in ("", ".", "..") for part in parts[2:])
        or not parts[-1].endswith(".pcap")
        or PurePosixPath(value).as_posix() != value
    ):
        raise SuricataError(f"{where}'s pcap_filename is outside /captures")
    return value


def _validate_event(
    raw: object,
    where: str,
    allowed_captures: set[str] | None = None,
) -> dict:
    if not isinstance(raw, dict):
        raise SuricataError(f"{where} is not an object")
    missing = [
        name
        for name in (
            "timestamp",
            "event_type",
            "flow_id",
            "src_ip",
            "dest_ip",
            "proto",
            "pcap_filename",
            "community_id",
        )
        if name not in raw
    ]
    if missing:
        raise SuricataError(f"{where} has no {', '.join(missing)}")

    kind = raw["event_type"]
    if kind not in EVE_TYPES:
        raise SuricataError(f"{where} has event_type {kind!r}, which was not configured")
    _timestamp(raw["timestamp"], where)
    _integer(raw["flow_id"], f"{where}'s flow_id")

    for name in ("src_ip", "dest_ip"):
        value = raw[name]
        if not isinstance(value, str):
            raise SuricataError(f"{where}'s {name} is not an address")
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise SuricataError(f"{where}'s {name} is not an address") from error

    proto = raw["proto"]
    if not isinstance(proto, str) or not proto.strip() or proto != proto.strip():
        raise SuricataError(f"{where}'s proto is not a protocol name")
    source_port = _port(raw, "src_port", where)
    destination_port = _port(raw, "dest_port", where)
    if proto.upper() in ("TCP", "UDP") and (source_port is None or destination_port is None):
        raise SuricataError(f"{where} has no complete TCP/UDP port pair")

    capture = _container_capture(raw["pcap_filename"], where, allow_unknown=kind == "alert")
    if allowed_captures is not None and capture != "unknown" and capture not in allowed_captures:
        raise SuricataError(f"{where}'s pcap_filename does not name an input capture")

    community = raw["community_id"]
    if not isinstance(community, str) or not community.strip() or community != community.strip():
        raise SuricataError(f"{where}'s community_id is not a non-empty string")
    if "tx_id" in raw:
        _integer(raw["tx_id"], f"{where}'s tx_id")
    if "app_proto" in raw and (
        not isinstance(raw["app_proto"], str)
        or not raw["app_proto"].strip()
        or raw["app_proto"] != raw["app_proto"].strip()
    ):
        raise SuricataError(f"{where}'s app_proto is not a protocol name")

    if kind == "alert":
        alert = raw.get("alert")
        if not isinstance(alert, dict):
            raise SuricataError(f"{where} has no alert object")
        if type(alert.get("signature_id")) is not int or alert["signature_id"] < 0:
            raise SuricataError(f"{where}'s alert has no numeric signature_id")
        if not isinstance(alert.get("signature"), str) or not alert["signature"]:
            raise SuricataError(f"{where}'s alert has no signature")
        _integer(alert.get("severity"), f"{where}'s alert severity")
    elif not isinstance(raw.get(kind), dict):
        raise SuricataError(f"{where} has no {kind} object")
    return raw


def read_eve(
    path: Path,
    capture_files: Iterable[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Strictly read EVE NDJSON as raw non-alert records and raw alert records."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise SuricataError("Suricata wrote no regular eve.json")
    allowed = None
    if capture_files is not None:
        allowed = {_container_capture(name, "an allowed capture") for name in capture_files}
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise SuricataError(f"eve.json cannot be read as UTF-8: {error}") from error

    records: list[dict] = []
    alerts: list[dict] = []
    for number, text in enumerate(lines, start=1):
        where = f"line {number} of eve.json"
        if not text.strip():
            raise SuricataError(f"{where} is blank")
        try:
            raw = json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_constant=_nonfinite,
            )
        except (TypeError, ValueError) as error:
            raise SuricataError(f"{where} is not strict JSON: {error}") from error
        event = _validate_event(raw, where, allowed)
        (alerts if event["event_type"] == "alert" else records).append(event)
    return records, alerts


def _network_tuple(event: dict) -> tuple[object, ...]:
    """A direction-independent protocol and endpoint tuple."""

    endpoints: list[tuple[int, bytes, str, int | None]] = []
    for ip_name, port_name in (("src_ip", "src_port"), ("dest_ip", "dest_port")):
        address = ipaddress.ip_address(event[ip_name])
        endpoints.append((address.version, address.packed, str(address), event.get(port_name)))
    endpoints.sort(
        key=lambda endpoint: (
            endpoint[0],
            endpoint[1],
            -1 if endpoint[3] is None else endpoint[3],
        )
    )
    first, second = endpoints
    return (
        event["proto"].lower(),
        first[2],
        first[3],
        second[2],
        second[3],
    )


def _directed_tuple(event: dict) -> tuple[object, ...]:
    return (
        str(ipaddress.ip_address(event["src_ip"])),
        event.get("src_port"),
        str(ipaddress.ip_address(event["dest_ip"])),
        event.get("dest_port"),
    )


def _dns_role(event: dict) -> str | None:
    if event["event_type"] != "dns":
        return None
    value = (event.get("dns") or {}).get("type")
    return value if isinstance(value, str) and value else None


def event_key(raw: dict) -> EventKey:
    """A stable capture occurrence identity that excludes process-local flow_id."""

    event = _validate_event(raw, "the EVE record")
    kind = event["event_type"]
    if kind == "alert":
        raise SuricataError("an alert is not a non-alert network event")
    capture = PurePosixPath(event["pcap_filename"]).relative_to("/captures").as_posix()
    return (
        "network",
        capture,
        event["community_id"],
        kind,
        event.get("tx_id"),
        _dns_role(event),
        *_network_tuple(event),
        _timestamp(event["timestamp"], "the EVE record"),
    )


def _pick_occurrence(alert: dict, candidates: list[dict], description: str) -> dict | None:
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        return None
    alert_time = _timestamp(alert["timestamp"], "the EVE alert")
    timed = [
        record
        for record in candidates
        if _timestamp(record["timestamp"], "a matching EVE record") == alert_time
    ]
    pool = timed or candidates
    directed = [record for record in pool if _directed_tuple(record) == _directed_tuple(alert)]
    if len(directed) == 1:
        return directed[0]
    if len(pool) == 1:
        return pool[0]
    raise SuricataError(f"alert flow_id {alert['flow_id']} has more than one {description}")


def _flow_contains(alert: dict, record: dict) -> bool | None:
    flow = record.get("flow") or {}
    if not isinstance(flow.get("start"), str) or not isinstance(flow.get("end"), str):
        return None
    moment = _timestamp(alert["timestamp"], "the EVE alert")
    start = _timestamp(flow["start"], "a matching flow start")
    end = _timestamp(flow["end"], "a matching flow end")
    return start <= moment <= end


def link_alert(alert: dict, records: Sequence[dict]) -> dict:
    """Resolve an alert to one real application record, or otherwise its flow."""

    alert = _validate_event(alert, "the EVE alert")
    if alert["event_type"] != "alert":
        raise SuricataError("the record to link is not an alert")
    checked = [_validate_event(record, f"network record {number}") for number, record in enumerate(records)]
    alert_capture = alert["pcap_filename"]
    by_flow_id = [
        record
        for record in checked
        if record["event_type"] != "alert" and record["flow_id"] == alert["flow_id"]
    ]
    if alert_capture == "unknown" and len({record["pcap_filename"] for record in by_flow_id}) > 1:
        raise SuricataError(f"alert flow_id {alert['flow_id']} spans more than one input capture")
    scoped = [
        record
        for record in by_flow_id
        if alert_capture == "unknown" or record["pcap_filename"] == alert_capture
    ]
    same_flow = [
        record
        for record in scoped
        if record["community_id"] == alert["community_id"] and _network_tuple(record) == _network_tuple(alert)
    ]
    application = alert.get("app_proto")
    preferred = [
        record for record in same_flow if application in APP_TYPES and record["event_type"] == application
    ]
    if "tx_id" in alert:
        preferred = [record for record in preferred if record.get("tx_id") == alert["tx_id"]]
    picked = _pick_occurrence(alert, preferred, "matching application record")
    if picked is not None:
        return picked

    # A packet alert can fire before Suricata identifies the application, so
    # the alert itself then has no app_proto.  A sole later application record
    # on the same capture, flow, community ID and tuple is still exact evidence
    # of that occurrence.  Multiple candidates remain ambiguous and fall
    # through to the flow record (or fail closed when there is none).
    if "app_proto" not in alert:
        untyped = [record for record in same_flow if record["event_type"] in APP_TYPES]
        if "tx_id" in alert:
            untyped = [record for record in untyped if record.get("tx_id") == alert["tx_id"]]
        if len(untyped) == 1:
            return untyped[0]

    flows = [record for record in same_flow if record["event_type"] == "flow"]
    flows = [record for record in flows if _flow_contains(alert, record) is not False]
    picked = _pick_occurrence(alert, flows, "flow record")
    if picked is not None:
        return picked
    raise SuricataError(f"alert flow_id {alert['flow_id']} has no real non-alert record")


def alert_event_key(alert: dict, records: Sequence[dict]) -> EventKey:
    """Resolve an alert inside its pass, then return the linked record's stable key."""

    return event_key(link_alert(alert, records))


def record_index(records: Sequence[dict]) -> dict[EventKey, dict]:
    """Index one pass by stable key, refusing evidence with an ambiguous identity."""

    found: dict[EventKey, dict] = {}
    for record in records:
        key = event_key(record)
        if key in found:
            raise SuricataError(f"more than one network record has the stable key {key!r}")
        found[key] = record
    return found


def _regular_output(path: Path, name: str) -> Path:
    target = path / name
    if target.is_symlink() or not target.is_file():
        raise SuricataError(f"Suricata wrote no regular {name}")
    try:
        target.resolve(strict=True).relative_to(path)
    except (OSError, ValueError) as error:
        raise SuricataError(f"Suricata wrote {name} outside its output folder") from error
    return target


def _engine_result(path: Path, rules_enabled: bool) -> tuple[str, int, int, list[str]]:
    log_path = _regular_output(path, "suricata.log")
    try:
        log = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise SuricataError(f"suricata.log cannot be read: {error}") from error
    versions = VERSION_LINE.findall(log)
    loaded_values = RULES_LOADED.findall(log)
    failed_values = RULES_FAILED.findall(log)
    if not versions:
        raise SuricataError("suricata.log does not report the engine version")
    if rules_enabled and not loaded_values:
        raise SuricataError("suricata.log does not report how many rules were loaded")
    loaded = int(loaded_values[-1]) if loaded_values else 0
    failed = int(failed_values[-1]) if failed_values else 0
    if rules_enabled and not failed_values:
        raise SuricataError("suricata.log does not report how many rules failed")
    if rules_enabled and loaded == 0:
        raise SuricataError(f"Suricata loaded no rule ({failed} failed)")
    reasons: list[str] = []
    if failed:
        summary = f"{loaded} rules successfully loaded, {failed} rules failed"
        for line in log.splitlines():
            reason = line.strip()
            if (
                reason
                and summary not in reason
                and LOAD_ERROR.search(reason)
                and reason[:MAX_LOAD_ERROR_LENGTH] not in reasons
            ):
                reasons.append(reason[:MAX_LOAD_ERROR_LENGTH])
                if len(reasons) == MAX_LOAD_ERRORS:
                    break
        if not reasons:
            reasons.append(f"Suricata reported {failed} rules failed without a reason")
    return versions[-1], loaded, failed, reasons


def read_stats(path: Path) -> dict[str, int]:
    """Read the last numeric value of every counter in Suricata's stats.log."""

    stats_path = _regular_output(Path(path), "stats.log")
    try:
        lines = stats_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise SuricataError(f"stats.log cannot be read: {error}") from error
    found: dict[str, int] = {}
    for line in lines:
        columns = [column.strip() for column in line.split("|")]
        if len(columns) != 3 or not STAT_NAME.fullmatch(columns[0]):
            continue
        try:
            value = int(columns[2].replace(",", ""))
        except ValueError:
            continue
        if value < 0:
            raise SuricataError(f"stats.log gives {columns[0]} a negative count")
        found[columns[0]] = value
    if not found:
        raise SuricataError("stats.log has no numeric counters")
    if "decoder.pkts" not in found:
        raise SuricataError("stats.log has no decoder.pkts read count")
    return found


def _completed_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def _container_target(name: str, cidfile: Path) -> str:
    if not cidfile.is_symlink() and cidfile.is_file():
        try:
            value = cidfile.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            value = ""
        if CONTAINER_ID.fullmatch(value):
            return value
    return name


def _force_remove(runner: Runner, name: str, cidfile: Path) -> None:
    """Best-effort removal of this invocation's exact container, and no other."""

    try:
        runner(["docker", "rm", "--force", _container_target(name, cidfile)], CLEANUP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_container(
    command: list[str],
    output: Path,
    name: str,
    cidfile: Path,
    runner: Runner,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    try:
        output.chmod(0o733)
    except OSError as error:
        raise SuricataError(f"the Suricata output folder cannot be made writable: {error}") from error
    try:
        try:
            completed = runner(command, timeout)
        except BaseException:
            _force_remove(runner, name, cidfile)
            raise
    finally:
        try:
            output.chmod(0o700)
        except OSError as error:
            raise SuricataError(
                f"the Suricata output folder cannot be made private again: {error}"
            ) from error
    if completed.returncode != 0:
        _force_remove(runner, name, cidfile)
    return completed


def _evaluate(
    image: str,
    captures: Path,
    home_net: list[str],
    output: Path,
    rules: Path | None,
    runner: Runner,
    timeout: float,
) -> dict:
    if not valid_image(image):
        raise SuricataError("the Suricata image must be a string with a tag and immutable sha256 digest")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise SuricataError("the Suricata timeout must be positive")

    rule_root: Path | None = None
    rule_files: list[tuple[Path, str]] = []
    classification: tuple[Path, str] | None = None
    if rules is not None:
        rule_root, rule_files, classification = _held_rules(Path(rules))
    capture_root, pcaps, capture_facts = _captures(Path(captures))
    addresses = _addresses(home_net)
    output_root = _prepare_output(Path(output), capture_root, rule_root)
    expected_packets = sum(facts["packets"] for facts in capture_facts.values())
    records: list[dict] = []
    alerts: list[dict] = []
    alert_keys: list[EventKey] = []
    runs: list[dict] = []
    engine_facts: tuple[str, int, int, tuple[str, ...]] | None = None
    total_read = 0
    total_bytes = 0
    every_run_reported_bytes = True
    with tempfile.TemporaryDirectory(prefix="bluefire-suricata-supervisor-") as supervisor_text:
        supervisor = Path(supervisor_text)
        eve_config = _stage_eve_config(supervisor)
        deadline = time.monotonic() + float(timeout)
        for number, pcap in enumerate(pcaps, start=1):
            folder_name = f"pcap-{number:04d}"
            capture_output = _prepare_output(output_root / folder_name, capture_root, rule_root)
            with tempfile.TemporaryDirectory(prefix="bluefire-suricata-pcap-") as staged_text:
                staged = Path(staged_text)
                try:
                    _stage_captures((pcap,), capture_facts, staged)
                    container_name = CONTAINER_PREFIX + secrets.token_hex(12)
                    cidfile = supervisor / f"container-{number:04d}.cid"
                    command = _docker_command(
                        image,
                        staged,
                        pcap.name,
                        addresses,
                        capture_output,
                        container_name,
                        cidfile,
                        eve_config,
                        rule_root,
                        rule_files,
                        classification,
                    )
                    remaining = float(timeout) if number == 1 else deadline - time.monotonic()
                    if remaining <= 0:
                        raise SuricataError(f"offline Suricata took longer than {timeout:g} seconds")
                    try:
                        completed = _run_container(
                            command,
                            capture_output,
                            container_name,
                            cidfile,
                            runner,
                            remaining,
                        )
                    except subprocess.TimeoutExpired as error:
                        raise SuricataError(
                            f"offline Suricata took longer than {timeout:g} seconds"
                        ) from error
                    except OSError as error:
                        raise SuricataError(f"offline Suricata could not be started: {error}") from error
                finally:
                    try:
                        staged.chmod(0o700)
                    except OSError:
                        pass
            if completed.returncode != 0:
                detail = (
                    (_completed_text(completed.stderr) or _completed_text(completed.stdout))
                    .strip()
                    .splitlines()[-1:]
                )
                raise SuricataError(
                    f"offline Suricata failed on {pcap.name} with exit code {completed.returncode}: "
                    f"{' '.join(detail)[:300]}"
                )

            allowed = {f"/captures/{pcap.name}"}
            made_records, made_alerts = read_eve(_regular_output(capture_output, "eve.json"), allowed)
            record_index(made_records)
            made_alert_keys = [alert_event_key(alert, made_records) for alert in made_alerts]
            if rules is None and made_alerts:
                raise SuricataError("the rule-independent telemetry pass produced an alert")
            version, loaded, failed, load_errors = _engine_result(capture_output, rules is not None)
            facts = (version, loaded, failed, tuple(load_errors))
            if engine_facts is not None and facts != engine_facts:
                raise SuricataError(
                    "Suricata did not report the same engine and rule loading for every capture"
                )
            engine_facts = facts
            capture_stats = read_stats(capture_output)
            read = capture_stats["decoder.pkts"]
            independently_counted = capture_facts[pcap.name]["packets"]
            if read != independently_counted:
                raise SuricataError(
                    f"Suricata decoded {read} packets from {pcap.name}, but the retained PCAP parser "
                    f"counted {independently_counted}"
                )
            if not made_records:
                raise SuricataError(f"Suricata wrote no canonical network event for {pcap.name}")

            run_counts = {
                "packets": read,
                "independently counted packets": independently_counted,
                "eve records": len(made_records) + len(made_alerts),
                "network records": len(made_records),
                "alerts": len(made_alerts),
            }
            if "decoder.bytes" in capture_stats:
                run_counts["bytes"] = capture_stats["decoder.bytes"]
                total_bytes += capture_stats["decoder.bytes"]
            else:
                every_run_reported_bytes = False
            runs.append(
                {
                    "capture": pcap.name,
                    "folder": folder_name,
                    "read": read,
                    "read counts": run_counts,
                    "stats": capture_stats,
                }
            )
            total_read += read
            records.extend(made_records)
            alerts.extend(made_alerts)
            alert_keys.extend(made_alert_keys)

    record_index(records)
    if engine_facts is None:
        raise SuricataError("Suricata evaluated no capture")
    version, loaded, failed, reasons = engine_facts
    load_errors = list(reasons)
    stats = {"decoder.pkts": total_read}
    if every_run_reported_bytes:
        stats["decoder.bytes"] = total_bytes
    if total_read != expected_packets:
        raise SuricataError(
            f"Suricata decoded {total_read} packets, but the retained PCAP parser counted {expected_packets}"
        )
    relative_rules = [relative for _, relative in rule_files]
    read_counts = {
        "capture files": len(pcaps),
        "packets": total_read,
        "independently counted packets": expected_packets,
        "eve records": len(records) + len(alerts),
        "network records": len(records),
        "alerts": len(alerts),
    }
    if "decoder.bytes" in stats:
        read_counts["bytes"] = stats["decoder.bytes"]
    return {
        "engine": {"name": ENGINE, "version": version, "image": image},
        "rules": loaded + failed,
        "rule file count": len(rule_files),
        "rule files": relative_rules,
        "loaded": loaded,
        "failed": failed,
        "load errors": load_errors,
        "read": total_read,
        "read counts": read_counts,
        "stats": stats,
        "runs": runs,
        "home_net": addresses,
        "records": records,
        "alerts": alerts,
        "alert event keys": [list(key) for key in alert_keys],
    }


def telemetry(
    image: str,
    captures: Path,
    home_net: list[str],
    output: Path,
    *,
    runner: Runner = _run,
    timeout: float = ENGINE_SECONDS,
) -> dict:
    """Read canonical network events without loading any detection rule set."""

    return _evaluate(
        image,
        Path(captures),
        home_net,
        Path(output),
        None,
        runner,
        timeout,
    )


def evaluate(
    image: str,
    rules: Path,
    captures: Path,
    home_net: list[str],
    output: Path,
    *,
    runner: Runner = _run,
    timeout: float = ENGINE_SECONDS,
) -> dict:
    """Evaluate one held rule set over web PCAPs in one sealed, offline container."""

    return _evaluate(
        image,
        Path(captures),
        home_net,
        Path(output),
        Path(rules),
        runner,
        timeout,
    )

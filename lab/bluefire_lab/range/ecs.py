"""The manager's archived events and alerts as lines of the Elastic Common Schema (ECS) 8.17.

Each line of the manager's archives.json or alerts.json becomes one ECS line,
and nothing is dropped or merged. The ECS fields are copies of what the line
holds where ECS has a clear home for it. The line itself stays whole under
`wazuh.*`, less its `full_log` (in `event.original`) and its `timestamp` (in
`event.ingested` for an event, `@timestamp` for an alert), so that each
mapping can be checked against the line it came from.

`labels.*` holds keyword values only: `labels.origin` and `labels.job`, and for
a line tied to a step of the path `labels.step_id` and `labels.tied_by` (see
`score`); `labels.event_id` on an alert names the `event.id` of its event in
the archive; `labels.evidence_event_ids` on a multi-event match is a JSON list
of every contributing archive event id, with that terminal `event_id` last;
and `labels.time_source`, which says where `@timestamp` comes from:

- `rsyslog`: the time rsyslog wrote on the line, in microseconds, which the
  manager decoded into `predecoder.timestamp`;
- `log-second`: a time to the second written by the program itself at the
  start of the line (nginx, dpkg, MariaDB), taken as written; a time without a
  zone is the container's, which is UTC;
- `manager`: the manager's own time of the event, for lines with no time of
  their source, such as file integrity events.

`step` writes one line for each step of the path, at the Docker daemon's time
of its test's start (`daemon`), or the engine's own where the daemon's was not
matched (`engine clock`).

`match` writes a match of a rule that was evaluated after the run (see
`sigma`) in the same shape as an alert, at the time of the event it matched.
"""

from __future__ import annotations

import copy
import gzip
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "8.17.0"
FRAMEWORK = "MITRE ATT&CK"
SNOOPY_DECODER = "bluefire-snoopy"
NGINX_TIME = re.compile(r"\S+ \S+ \S+ \[([0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9:]{8} [+-][0-9]{4})\] ")
# dpkg writes 2026-11-23 23:20:57, nginx's error log 2026/11/23 23:20:57, and MariaDB pads an
# hour below 10 with a space: 2026-11-24  6:19:48.
LINE_TIME = re.compile(r"([0-9]{4}[-/][0-9]{2}[-/][0-9]{2}) +([0-9]{1,2}:[0-9]{2}:[0-9]{2})\b")
FIM_TYPES = {"added": "creation", "modified": "change", "deleted": "deletion"}
# The parts of a line that Wazuh writes as JSON objects.
OBJECTS = ("agent", "manager", "predecoder", "decoder", "data", "rule", "syscheck")

# Every ECS field the mapper writes, with its ECS type. A line with any other field outside
# `labels`, `wazuh` and `suricata` is refused, so this list is the whole of what the mapper can write.
FIELDS = {
    "@timestamp": "date",
    "message": "match_only_text",
    "ecs.version": "keyword",
    "event.kind": "keyword",
    "event.id": "keyword",
    "event.action": "keyword",
    "event.reason": "keyword",
    "event.start": "date",
    "event.end": "date",
    "event.duration": "long",
    "event.category": "keyword",
    "event.type": "keyword",
    "event.outcome": "keyword",
    "event.dataset": "keyword",
    "event.module": "keyword",
    "event.provider": "keyword",
    "event.original": "keyword",
    "event.severity": "long",
    "event.created": "date",
    "event.ingested": "date",
    "agent.id": "keyword",
    "agent.name": "keyword",
    "agent.type": "keyword",
    "host.name": "keyword",
    "host.ip": "ip",
    "observer.name": "keyword",
    "observer.vendor": "keyword",
    "observer.product": "keyword",
    "observer.type": "keyword",
    "observer.version": "keyword",
    "observer.ingress.interface.name": "keyword",
    "log.file.path": "keyword",
    "source.ip": "ip",
    "source.port": "long",
    "source.domain": "keyword",
    "source.bytes": "long",
    "source.packets": "long",
    "destination.ip": "ip",
    "destination.port": "long",
    "destination.domain": "keyword",
    "destination.bytes": "long",
    "destination.packets": "long",
    "network.bytes": "long",
    "network.packets": "long",
    "network.transport": "keyword",
    "network.protocol": "keyword",
    "network.community_id": "keyword",
    "network.type": "keyword",
    "user.name": "keyword",
    "user.id": "keyword",
    "user.effective.name": "keyword",
    "user.effective.id": "keyword",
    "related.user": "keyword",
    "related.ip": "ip",
    "related.hash": "keyword",
    "related.hosts": "keyword",
    "process.command_line": "wildcard",
    "process.executable": "keyword",
    "process.args": "keyword",
    "process.exit_code": "long",
    "process.working_directory": "keyword",
    "file.path": "keyword",
    "file.owner": "keyword",
    "file.group": "keyword",
    "file.uid": "keyword",
    "file.gid": "keyword",
    "file.inode": "keyword",
    "file.size": "long",
    "file.hash.md5": "keyword",
    "file.hash.sha1": "keyword",
    "file.hash.sha256": "keyword",
    "http.request.method": "keyword",
    "http.response.status_code": "long",
    "http.version": "keyword",
    "url.original": "wildcard",
    "url.domain": "keyword",
    "url.path": "wildcard",
    "user_agent.original": "keyword",
    "tls.client.server_name": "keyword",
    "tls.version": "keyword",
    "tls.version_protocol": "keyword",
    "dns.answers": "object",
    "dns.id": "keyword",
    "dns.question.class": "keyword",
    "dns.question.name": "keyword",
    "dns.question.type": "keyword",
    "dns.resolved_ip": "ip",
    "dns.response_code": "keyword",
    "dns.type": "keyword",
    "rule.id": "keyword",
    "rule.description": "keyword",
    "rule.name": "keyword",
    "rule.ruleset": "keyword",
    "rule.version": "keyword",
    "rule.author": "keyword",
    "rule.reference": "keyword",
    "threat.framework": "keyword",
    "threat.technique.id": "keyword",
    "threat.technique.subtechnique.id": "keyword",
    "threat.tactic.name": "keyword",
}
# The values of the categorization fields the mapper sets, each one allowed by ECS for its field.
CATEGORIES = {
    "event.kind": ("event", "alert"),
    "event.category": ("authentication", "file", "intrusion_detection", "network", "process", "web"),
    "event.type": (
        "info",
        "creation",
        "change",
        "deletion",
        "start",
        "access",
        "allowed",
        "connection",
        "denied",
        "protocol",
    ),
    "event.outcome": ("success", "failure", "unknown"),
}
# A step's outcome in ECS's words: its effect check passed, failed, or neither was known.
STEP_OUTCOMES = {"took effect": "success", "attempted without effect": "failure"}


class ConversionError(ValueError):
    """A raw line could not be read, or an ECS line would lack what every line must have."""


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def manager_time(raw: dict) -> datetime:
    """The manager's `timestamp` of a line, such as 2026-11-23T17:29:20.870+0000."""

    try:
        return datetime.strptime(str(raw.get("timestamp")), "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError as error:
        raise ConversionError(f"a line has no manager timestamp that can be read: {error}") from error


def chosen_time(raw: dict) -> tuple[datetime, str]:
    """The time of an archived event and its source, as the module's docstring says."""

    stamp = (raw.get("predecoder") or {}).get("timestamp")
    if stamp:
        try:
            moment = datetime.fromisoformat(stamp)
            if moment.tzinfo is not None:
                return moment, "rsyslog"
        except ValueError:
            pass
    log = raw.get("full_log") or ""
    try:
        found = NGINX_TIME.match(log)
        if found:
            return datetime.strptime(found.group(1), "%d/%b/%Y:%H:%M:%S %z"), "log-second"
        found = LINE_TIME.match(log)
        if found:
            written = f"{found.group(1).replace('/', '-')} {found.group(2)}"
            return datetime.strptime(written, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc), "log-second"
    except ValueError:
        pass
    return manager_time(raw), "manager"


def _ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _number(value: object) -> int | None:
    text = str(value)
    return int(text) if text.isdigit() else None


def executable(data: dict) -> str | None:
    """The path of the program a snoopy line is about: `exe`, the file its exec call named.

    A shell that found the program on its search path named it in full. A path
    given relative to the working folder, as in `./tool`, is joined to that
    folder, which is the folder the kernel resolved it from. None for a line
    without one: a run made before snoopy's line held it.
    """

    path = data.get("exe")
    if not isinstance(path, str) or not path or path.startswith("("):
        return None
    folder = data.get("cwd")
    if path.startswith("/") or not isinstance(folder, str) or not folder.startswith("/"):
        return path
    return "/".join([folder.rstrip("/"), *(part for part in path.split("/") if part not in ("", "."))])


def _put(document: dict, name: str, value: object) -> None:
    """Set a dotted ECS field in a nested document, leaving out empty values."""

    if value is None or value == "" or value == []:
        return
    parts = name.split(".") if name != "@timestamp" else [name]
    node = document
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _common(raw: dict, document: dict) -> None:
    """The fields an event and an alert share."""

    agent = raw.get("agent") or {}
    _put(document, "agent.id", agent.get("id"))
    _put(document, "agent.name", agent.get("name"))
    _put(document, "agent.type", "wazuh")
    _put(document, "host.name", agent.get("name"))
    _put(document, "host.ip", _ip(agent.get("ip")) if agent.get("ip") else None)
    _put(document, "observer.name", (raw.get("manager") or {}).get("name"))
    _put(document, "observer.vendor", "Wazuh")
    _put(document, "event.module", "wazuh")
    location = raw.get("location") or ""
    if location.startswith("/"):
        _put(document, "log.file.path", location)
    _put(document, "event.provider", (raw.get("predecoder") or {}).get("program_name"))
    _put(document, "event.original", raw.get("full_log"))

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    decoder = (raw.get("decoder") or {}).get("name")
    users: list[str] = []
    ips: list[str] = []
    source_ip = _ip(data["srcip"]) if "srcip" in data else None
    _put(document, "source.ip", source_ip)
    if source_ip:
        _put(document, "source.port", _number(data.get("srcport")) if "srcport" in data else None)
        ips.append(source_ip)
    source_user, target_user = data.get("srcuser"), data.get("dstuser")
    if source_user:
        # Who acted (ran sudo, or opened the session), and the account it acts as when that is another.
        _put(document, "user.name", source_user)
        if target_user != source_user:
            _put(document, "user.effective.name", target_user)
    else:
        _put(document, "user.name", target_user)
    users += [data[key] for key in ("srcuser", "dstuser") if data.get(key)]
    categories: list[str] = []
    types: list[str] = []
    if decoder == SNOOPY_DECODER:
        # snoopy logs each program start, with the account that started it. A run made before
        # snoopy's line held the program's path has no `exe`.
        _put(document, "process.command_line", data.get("command"))
        _put(document, "process.executable", executable(data))
        _put(document, "process.working_directory", data.get("cwd"))
        _put(document, "user.id", data.get("uid"))
        _put(document, "user.effective.id", data.get("euid"))
        categories, types = ["process"], ["start"]
    elif decoder == "web-accesslog":
        _put(document, "http.request.method", data.get("protocol"))
        _put(document, "url.original", data.get("url"))
        _put(document, "http.response.status_code", _number(data.get("id")) if "id" in data else None)
        categories, types = ["web"], ["access"]

    syscheck = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else None
    if syscheck is not None:
        _put(document, "file.path", syscheck.get("path"))
        _put(document, "file.owner", syscheck.get("uname_after"))
        _put(document, "file.group", syscheck.get("gname_after"))
        _put(document, "file.uid", syscheck.get("uid_after"))
        _put(document, "file.gid", syscheck.get("gid_after"))
        inode = syscheck.get("inode_after")
        _put(document, "file.inode", str(inode) if inode is not None else None)
        _put(document, "file.size", _number(syscheck.get("size_after")) if "size_after" in syscheck else None)
        hashes = []
        for kind in ("md5", "sha1", "sha256"):
            value = syscheck.get(f"{kind}_after")
            _put(document, f"file.hash.{kind}", value)
            if value:
                hashes.append(value)
        _put(document, "related.hash", hashes)
        if syscheck.get("uname_after"):
            users.append(syscheck["uname_after"])
        if syscheck.get("event") in FIM_TYPES:
            categories, types = ["file"], [FIM_TYPES[syscheck["event"]]]

    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else None
    if rule is not None:
        _put(document, "rule.id", rule.get("id"))
        _put(document, "rule.description", rule.get("description"))
        level = rule.get("level")
        _put(document, "event.severity", level if isinstance(level, int) else None)
        groups = rule.get("groups") or []
        # Wazuh's own rule groups say whether a login succeeded or failed.
        if "authentication_success" in groups:
            categories, types = ["authentication"], ["info"]
            _put(document, "event.outcome", "success")
        elif "authentication_failed" in groups or "authentication_failures" in groups:
            categories, types = ["authentication"], ["info"]
            _put(document, "event.outcome", "failure")
        mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
        ids = [str(i) for i in mitre.get("id") or []]
        if ids:
            _put(document, "threat.framework", FRAMEWORK)
            # ECS keeps a technique and a subtechnique apart: T1548.003 is subtechnique 003 of T1548.
            _put(document, "threat.technique.id", list(dict.fromkeys(i.split(".")[0] for i in ids)))
            _put(document, "threat.technique.subtechnique.id", [i for i in ids if "." in i])
            _put(document, "threat.tactic.name", [str(t) for t in mitre.get("tactic") or []])
    _put(document, "event.category", categories)
    _put(document, "event.type", types)
    _put(document, "related.user", list(dict.fromkeys(users)))
    _put(document, "related.ip", ips)
    document["wazuh"] = {key: value for key, value in raw.items() if key not in ("full_log", "timestamp")}


def _labels(document: dict, origin: str, job: str | None, time_source: str, **more: str | None) -> None:
    labels = {"origin": origin, "time_source": time_source}
    if job:
        labels["job"] = job
    labels.update({name: value for name, value in more.items() if value})
    document["labels"] = labels


def evidence_ids(document: dict) -> list[str]:
    """The archive ids a match rests on, terminal id last; old one-event lines still work."""

    labels = document.get("labels") or {}
    terminal = labels.get("event_id")
    encoded = labels.get("evidence_event_ids")
    if encoded is None:
        return [terminal] if isinstance(terminal, str) and terminal else []
    try:
        found = json.loads(encoded)
    except (json.JSONDecodeError, TypeError) as error:
        raise ConversionError("labels.evidence_event_ids is not a JSON list of archive event ids") from error
    if (
        not isinstance(found, list)
        or not found
        or any(not isinstance(value, str) or not value for value in found)
        or len(set(found)) != len(found)
        or found[-1] != terminal
    ):
        raise ConversionError(
            "labels.evidence_event_ids must name distinct archive event ids with labels.event_id last"
        )
    return found


def event(
    raw: dict,
    origin: str,
    job: str | None = None,
    step: str | None = None,
    tied_by: str | None = None,
    event_id: str | None = None,
) -> dict:
    """One line of the manager's archive as an ECS event; `event_id` is its place in the archive."""

    moment, time_source = chosen_time(raw)
    document: dict = {"@timestamp": iso(moment)}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "event")
    _put(document, "event.id", event_id)
    _put(document, "event.dataset", "wazuh.archives")
    _put(document, "event.ingested", iso(manager_time(raw)))
    _put(document, "message", raw.get("full_log"))
    _common(raw, document)
    _labels(document, origin, job, time_source, step_id=step, tied_by=tied_by)
    return checked(document)


def alert(
    raw: dict,
    origin: str,
    job: str | None = None,
    step: str | None = None,
    tied_by: str | None = None,
    event_id: str | None = None,
) -> dict:
    """One line of the manager's alerts as an ECS alert, at the time the manager raised it.

    `event_id` is the `event.id` of the alert's event in the archive, when it has one there.
    """

    raised = iso(manager_time(raw))
    document: dict = {"@timestamp": raised}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "alert")
    _put(document, "event.dataset", "wazuh.alerts")
    _put(document, "event.created", raised)
    _put(document, "message", (raw.get("rule") or {}).get("description"))
    _common(raw, document)
    _labels(document, origin, job, "manager", step_id=step, tied_by=tied_by, event_id=event_id)
    return checked(document)


def match(
    raw: dict,
    rule: dict,
    ruleset: str,
    origin: str,
    job: str | None = None,
    step: str | None = None,
    tied_by: str | None = None,
    event_id: str | None = None,
    evidence_event_ids: list[str] | None = None,
) -> dict:
    """A match of a rule that was evaluated after the run, as an ECS alert at the time of its event.

    `raw` is the archived event the rule matched and `rule` the rule's `id`,
    `title`, `level`, `author` and `reference`. The line holds the event's own
    fields again, without `wazuh.*` and without a rule the manager matched on
    it; `labels.event_id` names the event, `labels.level` gives the rule's own
    level, a multi-event match keeps all contributors in
    `labels.evidence_event_ids`, and there is no `event.created`: nothing raised this alert while the
    run lasted.
    """

    moment, time_source = chosen_time(raw)
    document: dict = {"@timestamp": iso(moment)}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "alert")
    _put(document, "message", rule.get("title"))
    _common({key: value for key, value in raw.items() if key != "rule"}, document)
    del document["wazuh"]
    _put(document, "event.dataset", "sigma.matches")
    _put(document, "event.module", "sigma")
    _put(document, "rule.id", rule.get("id"))
    _put(document, "rule.name", rule.get("title"))
    _put(document, "rule.ruleset", ruleset)
    _put(document, "rule.author", rule.get("author"))
    _put(document, "rule.reference", rule.get("reference"))
    evidence = evidence_event_ids or ([event_id] if event_id else [])
    if evidence and (
        any(not isinstance(value, str) or not value for value in evidence)
        or len(set(evidence)) != len(evidence)
        or evidence[-1] != event_id
    ):
        raise ConversionError(
            "a match's evidence must name distinct archive events with its terminal event last"
        )
    encoded_evidence = (
        json.dumps(evidence, separators=(",", ":"), ensure_ascii=False) if len(evidence) > 1 else None
    )
    _labels(
        document,
        origin,
        job,
        time_source,
        step_id=step,
        tied_by=tied_by,
        event_id=event_id,
        evidence_event_ids=encoded_evidence,
        level=rule.get("level"),
    )
    return checked(document)


NETWORK_EVENT_TYPES = ("flow", "http", "tls", "ssh", "dns")
NETWORK_MESSAGE_LIMIT = 500


def _required_keyword(value: object, description: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConversionError(f"a Suricata line has no valid {description}")
    return value


def _suricata_moment(value: object, description: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ConversionError(f"a Suricata line has no {description}")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ConversionError(f"a Suricata line has no {description} that can be read: {error}") from error
    if moment.tzinfo is None:
        raise ConversionError(f"a Suricata line's {description} has no time zone")
    return moment


def _suricata_ip(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise ConversionError(f"a Suricata line's {description} is not an address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ConversionError(f"a Suricata line's {description} is not an address") from error


def _suricata_port(raw: dict, name: str) -> int | None:
    if name not in raw:
        return None
    value = raw[name]
    if type(value) is not int or not 0 <= value <= 65_535:
        raise ConversionError(f"a Suricata line's {name} is not a network port")
    return value


def _counter(raw: dict, name: str, description: str) -> int | None:
    if name not in raw:
        return None
    value = raw[name]
    if type(value) is not int or value < 0:
        raise ConversionError(f"a Suricata line's {description} is not a non-negative integer")
    return value


def _engine_version(engine: dict | None) -> str | None:
    if engine is None:
        return None
    if not isinstance(engine, dict):
        raise ConversionError("the Suricata engine description is not an object")
    version = engine.get("version")
    return _required_keyword(version, "engine version") if version is not None else None


def _optional_keyword(value: object, description: str) -> str | None:
    return None if value is None else _required_keyword(value, description)


def _short(value: object, limit: int = 160) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bounded_message(value: str) -> str:
    return value if len(value) <= NETWORK_MESSAGE_LIMIT else value[: NETWORK_MESSAGE_LIMIT - 1] + "…"


def _endpoint(address: str, port: int | None) -> str:
    shown = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    return f"{shown}:{port}" if port is not None else shown


def _network_fields(raw: dict, document: dict) -> tuple[str, int | None, str, int | None]:
    source_ip = _suricata_ip(raw.get("src_ip"), "src_ip")
    destination_ip = _suricata_ip(raw.get("dest_ip"), "dest_ip")
    if ipaddress.ip_address(source_ip).version != ipaddress.ip_address(destination_ip).version:
        raise ConversionError("a Suricata line has endpoints from different IP families")
    source_port = _suricata_port(raw, "src_port")
    destination_port = _suricata_port(raw, "dest_port")
    transport = _required_keyword(raw.get("proto"), "transport protocol").lower()
    community_id = _required_keyword(raw.get("community_id"), "community_id")
    kind = raw.get("event_type")
    application = raw.get("app_proto") or (kind if kind != "flow" else None)
    if application is not None:
        application = _required_keyword(application, "application protocol").lower()

    _put(document, "source.ip", source_ip)
    _put(document, "source.port", source_port)
    _put(document, "destination.ip", destination_ip)
    _put(document, "destination.port", destination_port)
    _put(document, "network.type", f"ipv{ipaddress.ip_address(source_ip).version}")
    _put(document, "network.transport", transport)
    _put(document, "network.protocol", application)
    _put(document, "network.community_id", community_id)
    _put(document, "related.ip", list(dict.fromkeys((source_ip, destination_ip))))
    return source_ip, source_port, destination_ip, destination_port


def _flow_fields(raw: dict, document: dict, endpoints: tuple[str, int | None, str, int | None]) -> str:
    flow = raw.get("flow")
    if not isinstance(flow, dict):
        raise ConversionError("a Suricata flow line has no flow object")
    source_packets = _counter(flow, "pkts_toserver", "flow.pkts_toserver")
    destination_packets = _counter(flow, "pkts_toclient", "flow.pkts_toclient")
    source_bytes = _counter(flow, "bytes_toserver", "flow.bytes_toserver")
    destination_bytes = _counter(flow, "bytes_toclient", "flow.bytes_toclient")
    _put(document, "source.packets", source_packets)
    _put(document, "source.bytes", source_bytes)
    _put(document, "destination.packets", destination_packets)
    _put(document, "destination.bytes", destination_bytes)
    packet_parts = [value for value in (source_packets, destination_packets) if value is not None]
    byte_parts = [value for value in (source_bytes, destination_bytes) if value is not None]
    _put(document, "network.packets", sum(packet_parts) if packet_parts else None)
    _put(document, "network.bytes", sum(byte_parts) if byte_parts else None)

    start = _suricata_moment(flow["start"], "flow.start") if "start" in flow else None
    end = _suricata_moment(flow["end"], "flow.end") if "end" in flow else None
    _put(document, "event.start", iso(start) if start else None)
    _put(document, "event.end", iso(end) if end else None)
    if start is not None and end is not None:
        elapsed = end - start
        if elapsed.total_seconds() < 0:
            raise ConversionError("a Suricata flow ends before it starts")
        duration = (
            elapsed.days * 86_400_000_000_000 + elapsed.seconds * 1_000_000_000 + elapsed.microseconds * 1_000
        )
        _put(document, "event.duration", duration)

    source_ip, source_port, destination_ip, destination_port = endpoints
    transport = document["network"]["transport"].upper()
    details = []
    packets = document["network"].get("packets")
    byte_count = document["network"].get("bytes")
    if packets is not None:
        details.append(f"{packets} packet{'s' if packets != 1 else ''}")
    if byte_count is not None:
        details.append(f"{byte_count} byte{'s' if byte_count != 1 else ''}")
    summary = (
        f"{transport} {_endpoint(source_ip, source_port)} to {_endpoint(destination_ip, destination_port)}"
    )
    return summary + (f": {', '.join(details)}" if details else "")


def _http_fields(raw: dict, document: dict) -> str:
    http = raw.get("http")
    if not isinstance(http, dict):
        raise ConversionError("a Suricata HTTP line has no http object")
    method = _optional_keyword(http.get("http_method"), "HTTP method")
    path = _optional_keyword(http.get("url"), "HTTP URL")
    domain = _optional_keyword(http.get("hostname"), "HTTP hostname")
    user_agent = _optional_keyword(http.get("http_user_agent"), "HTTP user agent")
    version = _optional_keyword(http.get("protocol"), "HTTP version")
    if version and version.upper().startswith("HTTP/"):
        version = version[5:]
    status = _counter(http, "status", "http.status")
    _put(document, "http.request.method", method)
    _put(document, "http.response.status_code", status)
    _put(document, "http.version", version)
    _put(document, "url.original", path)
    _put(document, "url.path", path)
    _put(document, "url.domain", domain)
    _put(document, "user_agent.original", user_agent)
    message = f"HTTP {_short(method) or 'request'} {_short(path, 220) or '/'}"
    if status is not None:
        message += f" returned {status}"
    if user_agent:
        message += f"; user agent {_short(user_agent, 220)}"
    return message


def _tls_fields(raw: dict, document: dict) -> str:
    tls = raw.get("tls")
    if not isinstance(tls, dict):
        raise ConversionError("a Suricata TLS line has no tls object")
    server_name = _optional_keyword(tls.get("sni"), "TLS server name")
    written_version = _optional_keyword(tls.get("version"), "TLS version")
    version = written_version
    if version:
        lower = version.lower()
        if lower.startswith("tlsv"):
            version = version[4:]
        elif lower.startswith("tls "):
            version = version[4:]
    _put(document, "tls.client.server_name", server_name)
    _put(document, "tls.version", version)
    _put(document, "tls.version_protocol", "tls")
    message = f"TLS server {_short(server_name)}" if server_name else "TLS session"
    return message + (f", version {_short(version)}" if version else "")


def _ssh_peer(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    parts = [_short(value.get(name)) for name in ("proto_version", "software_version")]
    return " / ".join(part for part in parts if part) or None


def _ssh_fields(raw: dict) -> str:
    ssh = raw.get("ssh")
    if not isinstance(ssh, dict):
        raise ConversionError("a Suricata SSH line has no ssh object")
    client, server = _ssh_peer(ssh.get("client")), _ssh_peer(ssh.get("server"))
    parts = []
    if client:
        parts.append(f"client {client}")
    if server:
        parts.append(f"server {server}")
    return "SSH " + ("; ".join(parts) if parts else "session")


def _dns_fields(raw: dict, document: dict) -> str:
    dns = raw.get("dns")
    if not isinstance(dns, dict):
        raise ConversionError("a Suricata DNS line has no dns object")
    queries = dns.get("queries")
    if queries is not None and (
        not isinstance(queries, list) or any(not isinstance(query, dict) for query in queries)
    ):
        raise ConversionError("a Suricata DNS line's queries is not a list of objects")
    question = queries[0] if queries else dns
    dns_id = dns.get("id")
    if isinstance(dns_id, int) and not isinstance(dns_id, bool):
        if dns_id < 0:
            raise ConversionError("a Suricata DNS line's id is negative")
        dns_id = str(dns_id)
    elif dns_id is not None:
        dns_id = _required_keyword(dns_id, "dns.id")
    kind = _optional_keyword(dns.get("type"), "DNS type")
    name = _optional_keyword(question.get("rrname"), "DNS question name")
    query_type = _optional_keyword(question.get("rrtype"), "DNS question type")
    query_class = _optional_keyword(question.get("rrclass"), "DNS question class")
    response_code = _optional_keyword(dns.get("rcode"), "DNS response code")
    _put(document, "dns.id", dns_id)
    _put(document, "dns.type", kind.lower() if kind else None)
    _put(document, "dns.question.name", name)
    _put(document, "dns.question.type", query_type)
    _put(document, "dns.question.class", query_class)
    _put(document, "dns.response_code", response_code)

    raw_answers = dns.get("answers")
    if raw_answers is not None and (
        not isinstance(raw_answers, list) or any(not isinstance(answer, dict) for answer in raw_answers)
    ):
        raise ConversionError("a Suricata DNS line's answers is not a list of objects")
    answers, resolved = [], []
    for answer in raw_answers or []:
        data = _optional_keyword(answer.get("rdata"), "DNS answer data")
        mapped = {
            field: value
            for field, value in (
                ("name", _optional_keyword(answer.get("rrname"), "DNS answer name")),
                ("type", _optional_keyword(answer.get("rrtype"), "DNS answer type")),
                ("data", data),
                ("ttl", _counter(answer, "ttl", "dns.answers.ttl")),
            )
            if value is not None
        }
        if mapped:
            answers.append(mapped)
        if data:
            try:
                resolved.append(str(ipaddress.ip_address(data)))
            except ValueError:
                pass
    _put(document, "dns.answers", answers)
    _put(document, "dns.resolved_ip", list(dict.fromkeys(resolved)))
    label = "response" if kind and kind.lower() in ("answer", "response") else "query"
    message = f"DNS {label}"
    if query_type or name:
        message += " " + " ".join(_short(value) or "" for value in (query_type, name) if value)
    if response_code:
        message += f" ({response_code})"
    if answers:
        values = [answer["data"] for answer in answers if answer.get("data")]
        if values:
            message += f": {', '.join(_short(value, 120) or '' for value in values)}"
    return message


def network_event(
    raw: dict,
    capture_host: str,
    interface: str,
    event_id: str,
    origin: str,
    job: str | None = None,
    step: str | None = None,
    tied_by: str | None = None,
    engine: dict | None = None,
) -> dict:
    """One validated Suricata flow or protocol record as a packet-sensor ECS event."""

    if not isinstance(raw, dict):
        raise ConversionError("a Suricata line is not an object")
    kind = raw.get("event_type")
    if kind not in NETWORK_EVENT_TYPES or not isinstance(raw.get(kind), dict):
        raise ConversionError(f"a Suricata line is not a supported network event: {kind!r}")
    host = _required_keyword(capture_host, "capture host")
    device = _required_keyword(interface, "capture interface")
    identity = _required_keyword(event_id, "network event id")
    document: dict = {"@timestamp": iso(_suricata_moment(raw.get("timestamp"), "timestamp"))}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "event")
    _put(document, "event.id", identity)
    _put(document, "event.dataset", "suricata.eve")
    _put(document, "event.module", "suricata")
    _put(document, "event.category", ["network"])
    _put(document, "event.type", ["connection" if kind == "flow" else "protocol"])
    _put(document, "host.name", host)
    _put(document, "observer.name", host)
    _put(document, "observer.vendor", "OISF")
    _put(document, "observer.product", "Suricata")
    _put(document, "observer.type", "ids")
    _put(document, "observer.version", _engine_version(engine))
    _put(document, "observer.ingress.interface.name", device)
    endpoints = _network_fields(raw, document)
    if kind == "flow":
        message = _flow_fields(raw, document, endpoints)
    elif kind == "http":
        message = _http_fields(raw, document)
    elif kind == "tls":
        message = _tls_fields(raw, document)
    elif kind == "ssh":
        message = _ssh_fields(raw)
    else:
        message = _dns_fields(raw, document)
    _put(document, "message", _bounded_message(message))
    _labels(
        document,
        origin,
        job,
        "pcap",
        sensor=f"packet-capture-{host}",
        step_id=step,
        tied_by=tied_by,
    )
    document["suricata"] = copy.deepcopy(raw)
    return checked(document)


def network_alert(
    raw_alert: dict,
    event_document: dict,
    rule_set: str,
    engine: dict | None = None,
) -> dict:
    """One Suricata rule match tied to the exact canonical packet event it matched."""

    if not isinstance(raw_alert, dict) or raw_alert.get("event_type") != "alert":
        raise ConversionError("a Suricata alert line is not an alert object")
    alert = raw_alert.get("alert")
    if not isinstance(alert, dict):
        raise ConversionError("a Suricata alert line has no alert object")
    if not isinstance(event_document, dict):
        raise ConversionError("a Suricata alert's event is not an ECS object")
    parent_event = event_document.get("event")
    parent_labels = event_document.get("labels")
    if not isinstance(parent_event, dict) or not isinstance(parent_labels, dict):
        raise ConversionError("a Suricata alert's event has no ECS identity or labels")
    event_id = _required_keyword(parent_event.get("id"), "parent event id")
    if not all(isinstance(value, str) for value in parent_labels.values()):
        raise ConversionError("a Suricata alert's parent labels are not keywords")
    if not parent_labels.get("sensor"):
        raise ConversionError("a Suricata alert's parent event has no packet sensor")
    ruleset = _required_keyword(rule_set, "rule set name")
    signature_id = _counter(alert, "signature_id", "alert.signature_id")
    if signature_id is None:
        raise ConversionError("a Suricata alert has no signature_id")
    generator_id = _counter(alert, "gid", "alert.gid")
    revision = _counter(alert, "rev", "alert.rev")
    priority = _counter(alert, "severity", "alert.severity")
    if priority is None:
        raise ConversionError("a Suricata alert has no severity")
    signature = _required_keyword(alert.get("signature"), "alert signature")
    rule_id = f"{generator_id if generator_id is not None else 1}:{signature_id}"
    action = _optional_keyword(alert.get("action"), "alert action")
    lowered_action = action.lower() if action else ""
    if lowered_action in ("allowed", "pass", "passed"):
        event_type = "allowed"
    elif lowered_action in ("blocked", "deny", "denied", "drop", "dropped", "reject", "rejected"):
        event_type = "denied"
    else:
        event_type = "info"
    level = {1: "high", 2: "medium", 3: "low"}.get(priority, "informational")

    document: dict = {"@timestamp": iso(_suricata_moment(raw_alert.get("timestamp"), "timestamp"))}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "alert")
    _put(document, "event.dataset", "suricata.alert")
    _put(document, "event.module", "suricata")
    _put(document, "event.category", ["network", "intrusion_detection"])
    _put(document, "event.type", [event_type])
    _put(document, "event.action", action)
    _put(document, "event.severity", priority)
    for name in (
        "host",
        "observer",
        "source",
        "destination",
        "network",
        "related",
        "http",
        "url",
        "user_agent",
        "tls",
        "dns",
    ):
        if name in event_document:
            document[name] = copy.deepcopy(event_document[name])
    version = _engine_version(engine)
    if version:
        document.setdefault("observer", {})["version"] = version
    _put(document, "rule.id", rule_id)
    _put(document, "rule.name", signature)
    _put(document, "rule.description", _optional_keyword(alert.get("category"), "alert category"))
    _put(document, "rule.ruleset", ruleset)
    _put(document, "rule.version", str(revision) if revision is not None else None)
    source = document.get("source") or {}
    destination = document.get("destination") or {}
    transport = str((document.get("network") or {}).get("transport") or "network").upper()
    endpoints = (
        f"{_endpoint(str(source['ip']), source.get('port'))} to "
        f"{_endpoint(str(destination['ip']), destination.get('port'))}"
        if source.get("ip") and destination.get("ip")
        else "the linked packet event"
    )
    _put(document, "message", _bounded_message(f"{signature} ({rule_id}) on {transport} {endpoints}"))
    document["labels"] = {
        **copy.deepcopy(parent_labels),
        "event_id": event_id,
        "level": level,
    }
    document["suricata"] = copy.deepcopy(raw_alert)
    return checked(document)


def nanoseconds(value: int) -> str:
    """A time in nanoseconds since the epoch, to the microsecond, as ECS writes a date."""

    seconds, rest = divmod(int(value), 1_000_000_000)
    return iso(datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(microseconds=rest // 1000))


# A step whose record holds daemon times with the end before the start. The executor times such a step by the
# engine's clock; a manifest that still holds them is read with this label, and its times are not used.
END_BEFORE_START = "daemon, its end before its start"


def step_clock(record: dict) -> str | None:
    """The clock of a step's times: its `time_source`, or END_BEFORE_START for daemon times out of order."""

    source = record.get("time_source")
    started, ended = record.get("started_ns"), record.get("ended_ns")
    if source == "daemon" and started is not None and ended is not None and int(ended) < int(started):
        return END_BEFORE_START
    return source


def step(record: dict) -> dict:
    """One step of the path as an ECS event: its times, host, account, test, exit code and outcome.

    `record` is the step as the manifest's `path` holds it, with `visibility`
    and `outcome` from the score when the run was scored. A step is never
    written with its end before its start.
    """

    technique = str(record.get("technique") or "")
    started, ended = record.get("started_ns"), record.get("ended_ns")
    source = step_clock(record)
    if started is not None:
        stamp = nanoseconds(started)
    else:
        # The attack did not start: the engine's time of the step, labelled.
        stamp = str(record.get("handled") or "")
    argv = [str(part) for part in record.get("argv") or []]
    document: dict = {"@timestamp": stamp}
    _put(document, "ecs.version", VERSION)
    _put(document, "event.kind", "event")
    _put(document, "event.id", record.get("id"))
    _put(document, "event.dataset", "bluefire.steps")
    _put(document, "event.module", "bluefire-lab")
    _put(document, "event.action", "published test")
    _put(document, "event.category", ["process"])
    _put(document, "event.type", ["info"])
    _put(document, "event.outcome", STEP_OUTCOMES.get(record.get("happened"), "unknown"))
    _put(document, "event.reason", record.get("why"))
    if started is not None and ended is not None and int(ended) >= int(started):
        _put(document, "event.start", stamp)
        _put(document, "event.end", nanoseconds(ended))
        _put(document, "event.duration", int(ended) - int(started))
    _put(document, "host.name", record.get("host"))
    _put(document, "related.hosts", list(dict.fromkeys([record.get("host"), *(record.get("to") or [])])))
    _put(document, "user.name", record.get("account"))
    _put(document, "related.user", [record.get("account")] if record.get("account") else None)
    _put(document, "process.args", argv)
    _put(document, "process.command_line", argv[-1] if argv else None)
    _put(document, "process.working_directory", record.get("workdir"))
    exit_code = record.get("exit_code")
    _put(document, "process.exit_code", exit_code if isinstance(exit_code, int) else None)
    if technique:
        _put(document, "threat.framework", FRAMEWORK)
        _put(document, "threat.technique.id", [technique.split(".")[0]])
        _put(document, "threat.technique.subtechnique.id", [technique] if "." in technique else None)
    _labels(
        document,
        "step",
        None,
        source if source in ("daemon", END_BEFORE_START) else "engine clock",
        step_id=record.get("id"),
        test_guid=record.get("guid"),
        test_name=record.get("name"),
        happened=record.get("happened"),
        check=(record.get("check") or {}).get("result") or "not run",
        visibility=record.get("visibility"),
        outcome=record.get("outcome"),
    )
    return checked(document)


def names(document: dict, prefix: str = "") -> list[str]:
    """Dotted field names, leaves only; labels and each sensor's raw line are one opaque name."""

    found = []
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and name not in ("labels", "wazuh", "suricata"):
            found += names(value, name + ".")
        else:
            found.append(name)
    return found


def checked(document: dict) -> dict:
    """Refuse a line without @timestamp, event.kind or labels.origin, or with a field the mapper does not declare."""

    for name, value in (
        ("@timestamp", document.get("@timestamp")),
        ("event.kind", (document.get("event") or {}).get("kind")),
        ("labels.origin", (document.get("labels") or {}).get("origin")),
    ):
        if not value:
            raise ConversionError(f"an ECS line would be written without {name}")
    unknown = sorted(
        n for n in names(document) if n not in FIELDS and n not in ("labels", "wazuh", "suricata")
    )
    if unknown:
        raise ConversionError(
            f"an ECS line would hold fields the mapper does not declare: {', '.join(unknown)}"
        )
    if not all(isinstance(value, str) for value in document["labels"].values()):
        raise ConversionError("labels holds keyword values only")
    return document


def read(paths: list[Path]) -> tuple[list[dict], list[str]]:
    """Every line of Wazuh JSON log files (plain or gzipped), in the order given, and where each one is.

    A line is the text up to each newline; only the empty text after the last
    newline of a file is not a line. A line that is not a JSON object, or
    whose parts that Wazuh writes as objects are not, is refused.
    """

    found, where = [], []
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", encoding="utf-8", newline="\n") as lines:
                text = lines.read()
        except (OSError, UnicodeDecodeError) as error:
            raise ConversionError(f"{path.name} cannot be read: {error}") from error
        pieces = text.split("\n")
        if pieces and pieces[-1] == "":
            pieces.pop()
        for number, line in enumerate(pieces, 1):
            try:
                value = json.loads(line)
            except ValueError as error:
                raise ConversionError(f"line {number} of {path.name} cannot be parsed: {error}") from error
            if not isinstance(value, dict):
                raise ConversionError(f"line {number} of {path.name} is not a JSON object")
            wrong = [key for key in OBJECTS if key in value and not isinstance(value[key], dict)]
            if wrong:
                raise ConversionError(
                    f"line {number} of {path.name}: {', '.join(wrong)} is not a JSON object"
                )
            found.append(value)
            where.append(f"line {number} of {path.name}")
    return found, where


def write(path: Path, documents: list[dict]) -> int:
    """Write the ECS lines, then count the lines of the file as written."""

    with path.open("w", encoding="utf-8", newline="\n") as target:
        for document in documents:
            target.write(json.dumps(document, separators=(",", ":")) + "\n")
    with path.open(encoding="utf-8", newline="\n") as written:
        return sum(1 for _ in written)

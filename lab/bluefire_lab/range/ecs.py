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
# `labels` and `wazuh` is refused, so this list is the whole of what the mapper can write.
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
    "log.file.path": "keyword",
    "source.ip": "ip",
    "source.port": "long",
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
    "url.original": "wildcard",
    "rule.id": "keyword",
    "rule.description": "keyword",
    "rule.name": "keyword",
    "rule.ruleset": "keyword",
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
    "event.category": ("authentication", "file", "process", "web"),
    "event.type": ("info", "creation", "change", "deletion", "start", "access"),
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
    """The dotted names of the fields of a document, leaves only; `labels` and `wazuh` as one name each."""

    found = []
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and name not in ("labels", "wazuh"):
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
    unknown = sorted(n for n in names(document) if n not in FIELDS and n not in ("labels", "wazuh"))
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

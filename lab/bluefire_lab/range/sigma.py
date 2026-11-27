"""Public Sigma rules over a recorded run's host events, evaluated after the run by the rule engine.

The engine is Zircolite, the program the one-host bench runs (`evaluate`), a
separate program given by its path. Each rule of a fetched folder is given the
events of the Sigma log source it names, and no others:

- `product: linux`, `category: process_creation`: the program starts snoopy
  logged, as `Image` (the file the exec call named), `CommandLine`, `User`
  (the login name snoopy recorded, which is not always the account the
  program runs as) and `CurrentDirectory`. The lab's snoopy line names no
  parent program, so `ParentImage`, `ParentCommandLine` and `LogonId` are not
  given. A run made before snoopy's line held the program's path has no
  `Image`.
- `product: linux`, `category: file_event`: the files the agents' file
  integrity monitoring saw added or changed, as `TargetFilename`. The sensor
  does not know which program wrote a file, so `Image` is not given.
- `category: webserver`: the lines of nginx's access log, as `cs-method`,
  `cs-uri-query` (the request's path and query as the line holds them),
  `sc-status`, `cs-user-agent`, `cs-referer` and `c-ip`, with the line itself
  for the rules that look for a word anywhere in it.
- `product: linux` with no category, the rules that look for words in a log
  line: every line of a log file the agents collect. A rule that names a
  `service` is given that service's lines only (`SERVICES`), and a rule for a
  service the range has no line of is given nothing.

A rule of any other log source is given nothing, and the counts say so.
Events of every origin are given (a step's, a job's, the engine's own,
unattributed): `score` decides what a match is from the event it is on.

The engine names a column by the letters and digits of a field's name, and
reads a rule's field names as written. So for a field whose name holds another
character, as `cs-method` does, the engine reads a copy of the rule in which
that name is written without it (`engine_copy`); nothing else of a rule is
changed, and the fetched files stay as the lock has them. For each folder and
log source the run records how many rules there are, how many the engine says
it loaded, how many events it was given and how many it read: the engine skips
a rule it cannot convert and still succeeds, so its own counts are the ones
that say what was evaluated. When it can convert none of a folder's rules it
stops with an error instead, and that folder counts as none loaded.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from .. import evaluate
from . import activity, ecs

ENGINE = "Zircolite"
LEVELS = ("informational", "low", "medium", "high", "critical")
# The levels at which a match counts as an alert, as everywhere in the lab: high and critical.
ALERT_LEVELS = evaluate.ALERT_LEVELS
ENGINE_SECONDS = 900
# What the engine writes in its log, and then exits 1, when it could convert none of the rules.
NONE_CONVERTED = "No rules to execute"
# What snoopy writes for a value it does not have.
UNKNOWN = ("", "(unknown)", "(undefined)", "(none)")
# A line of nginx's access log in the combined format: the client's address, the request, the
# status, the referer and the user agent.
ACCESS = re.compile(r'(\S+) \S+ \S+ \[[^\]]*\] "([^"]*)" ([0-9]{3}) \S+ "([^"]*)" "([^"]*)"')
FIM_WRITES = ("added", "modified")


class EngineError(RuntimeError):
    """The rule engine could not be run, failed, or answered with something other than what it was given."""


def _process(event: dict) -> dict | None:
    data = event.get("data") or {}
    if event.get("location") != activity.SNOOPY_LOG or "command" not in data:
        return None
    row = {"Image": ecs.executable(data), "CommandLine": data.get("command"), "User": data.get("login")}
    row["CurrentDirectory"] = data.get("cwd")
    return {name: value for name, value in row.items() if isinstance(value, str) and value not in UNKNOWN}


def _file(event: dict) -> dict | None:
    syscheck = event.get("syscheck") or {}
    if event.get("location") != "syscheck" or syscheck.get("event") not in FIM_WRITES:
        return None
    return {"TargetFilename": syscheck["path"]} if isinstance(syscheck.get("path"), str) else None


def _web(event: dict) -> dict | None:
    if event.get("location") != activity.NGINX_ACCESS:
        return None
    line = str(event.get("full_log") or "")
    row: dict = {"message": line}
    found = ACCESS.match(line)
    if not found:
        return row
    row["c-ip"], request, row["sc-status"] = found.group(1), found.group(2).split(" "), int(found.group(3))
    if len(request) == 3:
        row["cs-method"], row["cs-uri-query"] = request[0], request[1]
    # nginx writes - for a request without the header.
    for name, value in (("cs-referer", found.group(4)), ("cs-user-agent", found.group(5))):
        if value != "-":
            row[name] = value
    return row


def _program(event: dict) -> str:
    return str((event.get("predecoder") or {}).get("program_name") or "")


def _line(of: Callable[[dict], bool]) -> Callable[[dict], dict | None]:
    def row(event: dict) -> dict | None:
        location, line = str(event.get("location") or ""), event.get("full_log")
        if not location.startswith("/") or not isinstance(line, str) or not of(event):
            return None
        return {"message": line}

    return row


@dataclass(frozen=True)
class Source:
    """A Sigma log source the lab gives a run's events to: what the events are, the fields a row carries,
    the one by which a match is checked against the row it was given, and the row of an archived event."""

    name: str
    events: str
    fields: tuple[str, ...]
    check: str
    row: Callable[[dict], dict | None]


PROCESS = Source(
    "linux process_creation",
    "program starts snoopy logged",
    ("Image", "CommandLine", "User", "CurrentDirectory"),
    "CommandLine",
    _process,
)
FILE = Source(
    "linux file_event",
    "files added or changed in a folder watched in real time",
    ("TargetFilename",),
    "TargetFilename",
    _file,
)
WEB = Source(
    "webserver",
    "lines of nginx's access log",
    ("cs-method", "cs-uri-query", "sc-status", "cs-user-agent", "cs-referer", "c-ip"),
    "message",
    _web,
)
LINES = Source("linux", "lines of the collected log files", (), "message", _line(lambda event: True))
# The lines a keyword rule for a service is given: by the program the syslog line names, by its
# log file, or, for syslog, every line with a syslog header.
SERVICES = {
    "sshd": ("lines sshd wrote", lambda event: _program(event) == "sshd"),
    "sudo": ("lines sudo wrote", lambda event: _program(event) == "sudo"),
    "cron": ("lines cron and crontab wrote", lambda event: _program(event).lower() in ("cron", "crontab")),
    "auth": (f"lines of {activity.AUTH_LOG}", lambda event: event.get("location") == activity.AUTH_LOG),
    "syslog": ("lines with a syslog header", lambda event: bool(_program(event))),
}


def source_of(logsource: dict) -> Source | str:
    """The log source of a rule as the lab gives it, or why the rule is given nothing."""

    product, category, service = (logsource.get(key) for key in ("product", "category", "service"))
    if product == "linux" and category == "process_creation" and not service:
        return PROCESS
    if product == "linux" and category == "file_event" and not service:
        return FILE
    if category == "webserver" and product in (None, "linux") and not service:
        return WEB
    if product == "linux" and not category:
        if not service:
            return LINES
        if service in SERVICES:
            words, of = SERVICES[service]
            return Source(f"linux {service}", words, (), "message", _line(of))
        return f"the lab gives no lines for the service {service}"
    named = ", ".join(f"{key}: {value}" for key, value in sorted(logsource.items()))
    return f"the lab gives no events for the log source {named or 'that names nothing'}"


def fields_named(detection: object) -> list[str]:
    """The field names a rule's detection asks for, without their modifiers; a word list names none."""

    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            found.update(str(key).split("|")[0] for key in node)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name, selection in (detection if isinstance(detection, dict) else {}).items():
        if name not in ("condition", "timeframe"):
            walk(selection)
    return sorted(found - {""})


def read_rule(text: str, file: str) -> dict | str:
    """What the lab needs of the one Sigma rule a file holds, or why the file is not one."""

    try:
        documents = [found for found in yaml.safe_load_all(text) if found is not None]
    except yaml.YAMLError:
        return "not readable as YAML"
    rule = documents[0] if len(documents) == 1 else None
    if (
        not isinstance(rule, dict)
        or "id" not in rule
        or "detection" not in rule
        or not isinstance(rule.get("logsource"), dict)
    ):
        return "not one Sigma rule with an id, a log source and a detection"
    author = rule.get("author")
    level = str(rule.get("level") or "").lower()
    return {
        "id": str(rule["id"]),
        "title": str(rule.get("title") or rule["id"]),
        # The engine reads a rule without a level as informational, and so does the lab.
        "level": level if level in LEVELS else LEVELS[0],
        "author": ", ".join(str(name) for name in author) if isinstance(author, list) else str(author or ""),
        "file": file,
        "logsource": {
            key: str(value).lower()
            for key, value in rule["logsource"].items()
            if key in ("product", "category", "service")
        },
        "fields": fields_named(rule["detection"]),
    }


def column(name: str) -> str:
    """A field's name as the engine names its column: its letters and digits."""

    return re.sub(r"[^A-Za-z0-9]", "", name)


def engine_copy(text: str, fields: tuple[str, ...]) -> str:
    """A rule's text for the engine: each given field whose name holds a character other than a letter or
    a digit is written, where it is a key of the rule, as the engine names its column."""

    for name in fields:
        if column(name) != name:
            text = re.sub(rf"(?m)^(\s*(?:- )?){re.escape(name)}(?=[|:])", rf"\g<1>{column(name)}", text)
    return text


def engine_version(engine: Path) -> str | None:
    try:
        done = subprocess.run(
            [str(Path(engine).resolve()), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EngineError(f"the rule engine {Path(engine).name} could not be started: {error}") from error
    found = re.search(r"v(\d+\.\d+\.\d+)", done.stdout + done.stderr)
    return found.group(1) if found else None


def run_engine(engine: Path, work: Path, name: str, rules: Path, rows: list[dict]) -> tuple[list, int, int]:
    """Have the engine evaluate a folder of rules over rows, one JSON object a line; its matches, and how
    many rules it says it loaded and how many events it read."""

    (work / f"{name}.json").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    output, log = work / f"{name}-matches.json", work / f"{name}-engine.txt"
    # The engine adds to an existing log, and its counts are read from the log.
    output.unlink(missing_ok=True)
    log.unlink(missing_ok=True)
    try:
        done = subprocess.run(
            [
                str(Path(engine).resolve()),
                "--events", f"{name}.json",
                "--jsonl",
                "--no-event-filter",
                "--ruleset", str(rules.resolve()),
                "--outfile", output.name,
                "--logfile", log.name,
            ],
            cwd=work,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=ENGINE_SECONDS,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EngineError(f"the rule engine could not evaluate {name}: {error}") from error
    said = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    loaded, read = evaluate.engine_counts(said)
    if done.returncode != 0 and NONE_CONVERTED in said and loaded is None:
        # The engine stops when it can convert none of the rules it was given: none was evaluated.
        return [], 0, 0
    if done.returncode != 0 or loaded is None or read is None:
        last = (done.stderr.strip() or done.stdout.strip() or said.strip()).splitlines()[-1:]
        raise EngineError(
            f"the rule engine failed on {name} (exit code {done.returncode}): {' '.join(last)[:300]}"
        )
    try:
        matches = json.loads(output.read_text(encoding="utf-8")) if output.exists() else []
    except ValueError as error:
        raise EngineError(f"the rule engine's matches for {name} cannot be read: {error}") from error
    if not isinstance(matches, list) or not all(
        isinstance(entry, dict)
        and isinstance(entry.get("matches") or [], list)
        and all(isinstance(match, dict) for match in entry.get("matches") or [])
        for entry in matches
    ):
        raise EngineError(
            f"the rule engine's matches for {name} are not a list of rules, each with its matches"
        )
    return matches, loaded, read


def evaluate_set(engine: Path, folder: Path, folders: list[str], events: list[dict], work: Path) -> dict:
    """Give the rules under `folder` to the engine, each of its `folders` by log source, over the events.

    `folder` holds a fetched rule set at its repository's paths and `events` the
    manager's archive lines in order. Returns the engine's name and version, a
    row of counts for each folder and log source (`groups`), the files that are
    not a rule, and the matches: each the rule and the place of its event.
    """

    version = engine_version(engine)
    work.mkdir(parents=True, exist_ok=True)
    groups, matches, left_out = [], [], []
    for number, name in enumerate(folders, start=1):
        by_source: dict[str, tuple[Source | None, list[dict]]] = {}
        seen: set[str] = set()
        for path in sorted((folder / name).rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            file = path.relative_to(folder).as_posix()
            rule = read_rule(path.read_text(encoding="utf-8", errors="replace"), file)
            if not isinstance(rule, str) and rule["id"] in seen:
                rule = "its id is that of another rule of the folder"
            if isinstance(rule, str):
                left_out.append({"file": file, "why": rule})
                continue
            seen.add(rule["id"])
            source = source_of(rule["logsource"])
            key = source if isinstance(source, str) else source.name
            by_source.setdefault(key, (None if isinstance(source, str) else source, []))[1].append(rule)
        for place, (key, (source, rules)) in enumerate(by_source.items(), start=1):
            group: dict = {"folder": name, "log source": key, "rules": len(rules), "loaded": 0}
            group.update({"given": 0, "read": 0, "matches": 0, "rules that matched": 0})
            groups.append(group)
            if source is None:
                group["log source"], group["not evaluated"] = "none the lab gives", key
                continue
            group["events"] = source.events
            rows = [(index, row) for index, event in enumerate(events) if (row := source.row(event))]
            group["given"] = len(rows)
            given = sorted({field for _, row in rows for field in row} & set(source.fields))
            group["fields given"] = given
            asked = Counter(field for rule in rules for field in rule["fields"] if field not in given)
            group["fields the rules name that are not given"] = dict(sorted(asked.items()))
            if not rows:
                group["not evaluated"] = "the run holds no such event"
                continue
            slug = f"{number:02d}-{place:02d}-" + re.sub(r"[^a-z0-9]+", "-", f"{name} {key}".lower()).strip(
                "-"
            )
            copies = work / f"{slug}-rules"
            copies.mkdir(exist_ok=True)
            for old in copies.iterdir():
                old.unlink()
            for count, rule in enumerate(rules, start=1):
                text = (folder / rule["file"]).read_text(encoding="utf-8", errors="replace")
                (copies / f"{count:04d}-{Path(rule['file']).name}").write_text(
                    engine_copy(text, source.fields), encoding="utf-8"
                )
            found, group["loaded"], group["read"] = run_engine(
                engine, work, slug, copies, [row for _, row in rows]
            )
            by_id = {rule["id"]: rule for rule in rules}
            for entry in found:
                rule = by_id.get(str(entry.get("id")))
                if rule is None:
                    raise EngineError(
                        f"the rule engine names the rule {entry.get('id')}, which {slug} does not hold"
                    )
                for match in entry.get("matches") or []:
                    try:
                        index, row = rows[int(match["row_id"]) - 1]
                    except (KeyError, ValueError, IndexError, TypeError) as error:
                        raise EngineError(f"the rule engine names a row {slug} does not hold") from error
                    if match.get(column(source.check)) != row.get(source.check):
                        raise EngineError(
                            f"the rule engine's row {match['row_id']} of {slug} is not the row it was given there"
                        )
                    matches.append({"rule": rule, "event": index})
                group["matches"] += len(entry.get("matches") or [])
                group["rules that matched"] += 1
    matches.sort(key=lambda match: (match["event"], match["rule"]["id"]))
    return {
        "engine": {"name": ENGINE, "version": version},
        "groups": groups,
        "files that are not a rule": left_out,
        "rules": sum(group["rules"] for group in groups),
        "loaded": sum(group["loaded"] or 0 for group in groups),
        "matches": matches,
    }

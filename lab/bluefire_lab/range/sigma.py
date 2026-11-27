"""Public Sigma rules over a recorded run's host events, evaluated after the run by the rule engine.

The engine is Zircolite, the program the one-host bench runs (`evaluate`), a
separate program given by its path. Each rule of a fetched folder is given the
events of the Sigma log source it names, and no others:

- `category: process_creation` (with `product: linux` or no product): the program starts snoopy
  logged, as `Image` (the file the exec call named), `CommandLine`, `User`
  (the login name snoopy recorded, which is not always the account the
  program runs as) and `CurrentDirectory`. The lab's snoopy line names no
  parent program, so `ParentImage`, `ParentCommandLine` and `LogonId` are not
  given. A run made before snoopy's line held the program's path has no
  `Image`.
- `category: file_event` (with `product: linux` or no product): the files the agents' file
  integrity monitoring saw added or changed, as `TargetFilename`. The sensor
  does not know which program wrote a file, so `Image` is not given.
- `category: webserver`: the lines of nginx's access log, as `cs-method`,
  `cs-uri-stem` (the request's path), `cs-uri-query` (the request's path and
  query as the line holds them),
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
that name is written without it (`engine_copy`); the fetched files stay as the
lock has them.

Sigma correlations and all their dependencies run together in one database.
Each row carries its ISO event time, host, stable archive-event id and Sigma
source. An engine-only copy of every atomic dependency requires that source,
so a rule cannot see another source's rows even though Zircolite otherwise
treats `logsource` as metadata. A correlation match is anchored to its latest
real archived event and also returns the time-ordered unique archive indices and
stable ids of all its evidence.

For each atomic log source and correlation folder the run records how many
rules there are, which identities appear in the engine's saved converted
ruleset, how many events it was given and how many it read. Conversion errors
and correlations rejected before conversion keep their per-rule reasons.
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
PROVENANCE_FILES = {"SHA256SUMS", "SOURCE"}
# What snoopy writes for a value it does not have.
UNKNOWN = ("", "(unknown)", "(undefined)", "(none)")
# A line of nginx's access log in the combined format: the client's address, the request, the
# status, the referer and the user agent.
ACCESS = re.compile(r'(\S+) \S+ \S+ \[[^\]]*\] "([^"]*)" ([0-9]{3}) \S+ "([^"]*)" "([^"]*)"')
FIM_WRITES = ("added", "modified")
TIME_FIELD = "UtcTime"
HOST_FIELD = "Computer"
EVENT_FIELD = "BlueFireEventId"
SOURCE_FIELD = "BlueFireSource"
CONTEXT_FIELDS = (TIME_FIELD, HOST_FIELD)
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
PLACEHOLDER = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


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
        target = request[1]
        row["cs-method"], row["cs-uri-query"] = request[0], target
        row["cs-uri-stem"] = target.partition("?")[0]
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
    (
        "cs-method",
        "cs-uri-query",
        "cs-uri-stem",
        "sc-status",
        "cs-user-agent",
        "cs-referer",
        "c-ip",
    ),
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
    if product in (None, "linux") and category == "process_creation" and not service:
        return PROCESS
    if product in (None, "linux") and category == "file_event" and not service:
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


def _author(rule: dict) -> str:
    author = rule.get("author")
    return ", ".join(str(name) for name in author) if isinstance(author, list) else str(author or "")


def _level(rule: dict) -> str:
    level = str(rule.get("level") or "").lower()
    return level if level in LEVELS else LEVELS[0]


def read_rule(text: str, file: str) -> dict | str:
    """What the lab needs of one atomic or correlation Sigma rule, or why the file is not one."""

    try:
        documents = [found for found in yaml.safe_load_all(text) if found is not None]
    except yaml.YAMLError:
        return "not readable as YAML"
    rule = documents[0] if len(documents) == 1 else None
    if not isinstance(rule, dict):
        return "not one Sigma atomic rule or correlation the lab can evaluate"
    identifier = rule.get("id") or rule.get("name")
    if identifier and "detection" in rule and isinstance(rule.get("logsource"), dict):
        return {
            "kind": "atomic",
            "id": str(identifier),
            "name": str(rule.get("name") or ""),
            "title": str(rule.get("title") or identifier),
            # The engine reads a rule without a level as informational, and so does the lab.
            "level": _level(rule),
            "author": _author(rule),
            "file": file,
            "logsource": {
                key: str(value).lower()
                for key, value in rule["logsource"].items()
                if key in ("product", "category", "service")
            },
            "fields": fields_named(rule["detection"]),
        }
    correlation = rule.get("correlation")
    references = correlation.get("rules") if isinstance(correlation, dict) else None
    if (
        identifier
        and isinstance(references, list)
        and references
        and all(isinstance(name, str) for name in references)
    ):
        group_by = correlation.get("group-by") or []
        if isinstance(group_by, str):
            group_by = [group_by]
        condition = correlation.get("condition")
        value = condition.get("field") if isinstance(condition, dict) else None
        if value is None:
            value = correlation.get("field")
        fields = [str(name) for name in group_by if isinstance(name, str)]
        if isinstance(value, str):
            fields.append(value)
        return {
            "kind": "correlation",
            "id": str(identifier),
            "name": str(rule.get("name") or ""),
            "title": str(rule.get("title") or identifier),
            "level": _level(rule),
            "author": _author(rule),
            "file": file,
            "type": str(correlation.get("type") or ""),
            "references": list(references),
            "fields": sorted(set(fields)),
        }
    return "not one Sigma atomic rule or correlation the lab can evaluate"


def column(name: str) -> str:
    """A field's name as the engine names its column: its letters and digits."""

    return re.sub(r"[^A-Za-z0-9]", "", name)


def pipeline_values(text: str, file: str) -> dict[str, list[str]]:
    """Values of one public pySigma value-placeholder pipeline, or why it cannot be applied."""

    try:
        documents = [document for document in yaml.safe_load_all(text) if document is not None]
    except yaml.YAMLError as error:
        raise EngineError(f"the Sigma pipeline {file} is not readable as YAML: {error}") from error
    pipeline = documents[0] if len(documents) == 1 else None
    transformations = pipeline.get("transformations") if isinstance(pipeline, dict) else None
    if (
        not isinstance(transformations, list)
        or not transformations
        or any(
            not isinstance(item, dict) or item.get("type") != "value_placeholders" for item in transformations
        )
    ):
        raise EngineError(
            f"the Sigma pipeline {file} is not solely a value-placeholder pipeline the lab can apply"
        )
    variables = pipeline.get("vars")
    if not isinstance(variables, dict) or not variables:
        raise EngineError(f"the Sigma pipeline {file} defines no placeholder values")
    found: dict[str, list[str]] = {}
    for name, values in variables.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            or not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            raise EngineError(
                f"the Sigma pipeline {file} must give each plainly named placeholder distinct string values"
            )
        found[name] = list(values)
    return found


def _expand_placeholders(value: object, placeholders: dict[str, list[str]]) -> object:
    """Replace pySigma value placeholders in a detection, flattening one inside a value list."""

    if isinstance(value, str):
        found = PLACEHOLDER.fullmatch(value)
        if found:
            name = found.group(1)
            if name not in placeholders:
                raise EngineError(f"a Sigma rule names the placeholder {name}, which no pipeline defines")
            return list(placeholders[name])
        unresolved = PLACEHOLDER.search(value)
        if unresolved:
            raise EngineError(
                f"a Sigma rule uses the placeholder {unresolved.group(1)} as part of another value"
            )
        return value
    if isinstance(value, list):
        expanded = []
        for item in value:
            made = _expand_placeholders(item, placeholders)
            if isinstance(item, str) and PLACEHOLDER.fullmatch(item):
                expanded.extend(made)
            else:
                expanded.append(made)
        return expanded
    if isinstance(value, dict):
        return {key: _expand_placeholders(item, placeholders) for key, item in value.items()}
    return value


def engine_copy(
    text: str,
    fields: tuple[str, ...],
    source: Source | None = None,
    *,
    placeholders: dict[str, list[str]] | None = None,
    correlation: bool = False,
) -> str:
    """A rule's text for the engine: each given field whose name holds a character other than a letter or
    a digit is written as the engine names it. With a source, a mandatory selector keeps the rule on rows
    of that Sigma log source when correlations join several sources in one database. A configured public
    value-placeholder pipeline is applied to detection values, and correlation field names are normalized."""

    for name in fields:
        if column(name) != name:
            text = re.sub(rf"(?m)^(\s*(?:- )?){re.escape(name)}(?=[|:])", rf"\g<1>{column(name)}", text)
    expands = placeholders is not None and PLACEHOLDER.search(text) is not None
    if source is None and not correlation and not expands:
        return text
    try:
        documents = [document for document in yaml.safe_load_all(text) if document is not None]
    except yaml.YAMLError as error:
        raise EngineError(f"a rule copied for the engine is not readable as YAML: {error}") from error
    rule = documents[0] if len(documents) == 1 else None
    detection = rule.get("detection") if isinstance(rule, dict) else None
    if not isinstance(detection, dict):
        if source is not None or expands:
            raise EngineError("an atomic rule copied for the engine has no detection")
    elif expands:
        rule["detection"] = detection = _expand_placeholders(detection, placeholders)
    if correlation:
        specification = rule.get("correlation") if isinstance(rule, dict) else None
        if not isinstance(specification, dict):
            raise EngineError("a correlation copied for the engine has no correlation specification")
        group_by = specification.get("group-by")
        if isinstance(group_by, str):
            specification["group-by"] = column(group_by)
        elif isinstance(group_by, list):
            specification["group-by"] = [column(name) if isinstance(name, str) else name for name in group_by]
        condition = specification.get("condition")
        if isinstance(condition, dict) and isinstance(condition.get("field"), str):
            condition["field"] = column(condition["field"])
        if isinstance(specification.get("field"), str):
            specification["field"] = column(specification["field"])
    if source is None:
        return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
    condition = detection.get("condition")
    if (
        not isinstance(condition, (str, list))
        or isinstance(condition, list)
        and not all(isinstance(item, str) for item in condition)
    ):
        raise EngineError("an atomic rule copied for a correlation has no plain condition")
    selector = "bluefire_source"
    while selector in detection:
        selector += "_"
    detection[selector] = {SOURCE_FIELD: source.name}
    if isinstance(condition, str):
        detection["condition"] = f"({condition}) and {selector}"
    else:
        detection["condition"] = [f"({item}) and {selector}" for item in condition]
    text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
    return text


def event_rows(source: Source, events: list[dict]) -> list[tuple[int, dict]]:
    """Rows of one Sigma log source, with time, host and a stable id used only to return evidence."""

    rows = []
    for index, event in enumerate(events):
        row = source.row(event)
        if row is None:
            continue
        try:
            moment, _ = ecs.chosen_time(event)
        except ecs.ConversionError as error:
            raise EngineError(
                f"archived event {index + 1} has no time a correlation can read: {error}"
            ) from error
        made = dict(row)
        made[TIME_FIELD] = ecs.iso(moment)
        host = (event.get("agent") or {}).get("name")
        if isinstance(host, str) and host:
            made[HOST_FIELD] = host
        made[EVENT_FIELD] = f"archive-{index + 1}"
        made[SOURCE_FIELD] = source.name
        rows.append((index, made))
    return rows


def _plain_error(text: str) -> str:
    return re.sub(r"\[[^\]]*\]", "", text).strip()


def conversion_errors(text: str) -> list[dict]:
    """Per-rule reasons from a Zircolite debug log, without paths or the engine's object dump."""

    found = []
    for line in text.splitlines():
        if "Cannot convert correlation rule '" in line:
            rest = line.partition("Cannot convert correlation rule '")[2]
            title, _, reason = rest.partition("' : ")
        elif "Cannot convert rule '" in line:
            title_match = re.search(r"title='([^']+)'", line)
            title = title_match.group(1) if title_match else "rule whose title the engine did not give"
            _, _, reason = line.rpartition("' : ")
        else:
            continue
        found.append({"rule": _plain_error(title), "reason": _plain_error(reason)[:500]})
    return found


def _run(
    engine: Path,
    work: Path,
    name: str,
    rules: Path,
    output: Path,
    log: Path,
    *,
    debug: bool = False,
    save_ruleset: bool = False,
) -> subprocess.CompletedProcess:
    arguments = [
        str(Path(engine).resolve()),
        "--events",
        f"{name}.json",
        "--jsonl",
        "--no-event-filter",
        "--ruleset",
        str(rules.resolve()),
        "--timefield",
        TIME_FIELD,
        "--unified-db",
        "--outfile",
        output.name,
        "--logfile",
        log.name,
    ]
    if debug:
        arguments.append("--debug")
    if save_ruleset:
        arguments.append("--save-ruleset")
    return subprocess.run(
        arguments,
        cwd=work,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        timeout=ENGINE_SECONDS,
    )


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


def run_engine(
    engine: Path, work: Path, name: str, rules: Path, rows: list[dict]
) -> tuple[list, int, int, list[dict], list[dict]]:
    """Evaluate rules and return matches, engine counts, errors and the converted rule identities."""

    (work / f"{name}.json").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    output, log = work / f"{name}-matches.json", work / f"{name}-engine.txt"
    output.unlink(missing_ok=True)
    log.unlink(missing_ok=True)
    for old in work.glob("ruleset-*.json"):
        old.unlink()
    try:
        done = _run(engine, work, name, rules, output, log, save_ruleset=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EngineError(f"the rule engine could not evaluate {name}: {error}") from error
    said = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    loaded, read = evaluate.engine_counts(said)
    failure_match = re.search(r"\(([0-9]+) failed\)", said)
    failures = int(failure_match.group(1)) if failure_match else 0
    errors = []
    if failures:
        debug_output, debug_log = work / f"{name}-debug-matches.json", work / f"{name}-debug-engine.txt"
        debug_output.unlink(missing_ok=True)
        debug_log.unlink(missing_ok=True)
        try:
            _run(engine, work, name, rules, debug_output, debug_log, debug=True)
            debug_text = debug_log.read_text(encoding="utf-8", errors="replace") if debug_log.exists() else ""
            errors = conversion_errors(debug_text)
        except (OSError, subprocess.TimeoutExpired):
            errors = [{"rule": "unknown", "reason": f"{failures} rules failed conversion"}]
        finally:
            debug_output.unlink(missing_ok=True)
            debug_log.unlink(missing_ok=True)
    converted = []
    saved = list(work.glob("ruleset-*.json"))
    try:
        for path in saved:
            ruleset = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(ruleset, list) or not all(isinstance(rule, dict) for rule in ruleset):
                raise EngineError(f"the rule engine's converted ruleset {path.name} is not a list of rules")
            converted.extend(ruleset)
    except ValueError as error:
        raise EngineError(f"the rule engine's converted ruleset cannot be read: {error}") from error
    finally:
        for path in saved:
            path.unlink(missing_ok=True)
    if done.returncode != 0 and NONE_CONVERTED in said and loaded is None:
        return [], 0, 0, errors, []
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
    if loaded and not converted:
        raise EngineError(f"the rule engine loaded {loaded} rules for {name} but saved no rule identities")
    return matches, loaded, read, errors, converted


def _rule_for(entry: dict, rules: list[dict], name: str) -> dict:
    identifier = str(entry.get("id") or "")
    title = str(entry.get("title") or "")
    found = next(
        (rule for rule in rules if rule["id"] == identifier or not identifier and rule["title"] == title),
        None,
    )
    if found is None:
        raise EngineError(f"the rule engine names the rule {identifier or title}, which {name} does not hold")
    return found


def _evidence(match: dict, rows: list[tuple[int, dict]], name: str) -> tuple[int, list[int], list[str]]:
    evidence = match.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise EngineError(f"a correlation match of {name} names no evidence event")
    found = []
    for item in evidence:
        event = item.get("event") if isinstance(item, dict) else None
        try:
            place = int(event["row_id"]) - 1
            if not 0 <= place < len(rows):
                raise IndexError(place)
            index, row = rows[place]
        except (KeyError, ValueError, IndexError, TypeError) as error:
            raise EngineError(
                f"a correlation match of {name} names an event the engine was not given"
            ) from error
        if event.get(EVENT_FIELD) != row[EVENT_FIELD]:
            raise EngineError(f"a correlation match of {name} changed an evidence event's stable id")
        found.append((index, row))
    unique: dict[int, dict] = {}
    for index, row in found:
        unique.setdefault(index, row)
    terminal = max(unique.items(), key=lambda item: (item[1][TIME_FIELD], item[0]))[0]
    evidence = sorted(unique, key=lambda index: (unique[index][TIME_FIELD], index))
    return terminal, evidence, [unique[index][EVENT_FIELD] for index in evidence]


def _dependencies(
    rule: dict, by_reference: dict[str, dict], ambiguous: set[str]
) -> tuple[list[dict], str | None]:
    """A correlation and all rules it refers to, or why its collection cannot be made."""

    found: dict[str, dict] = {}

    def visit(current: dict, trail: tuple[str, ...]) -> str | None:
        if current["file"] in trail:
            return f"the correlation dependency through {current['title']} is a cycle"
        found[current["file"]] = current
        if current["kind"] == "atomic":
            return None
        if current["type"] not in CORRELATION_TYPES:
            return f"the lab does not evaluate the correlation type {current['type'] or 'that names nothing'}"
        for reference in current["references"]:
            if reference in ambiguous:
                return f"the correlation reference {reference} names more than one rule"
            dependency = by_reference.get(reference)
            if dependency is None:
                return f"the correlation reference {reference} names no rule in the set"
            why = visit(dependency, (*trail, current["file"]))
            if why:
                return why
        return None

    why = visit(rule, ())
    return list(found.values()), why


def _was_converted(rule: dict, converted: list[dict], kind: str) -> bool:
    """Whether the engine's saved compiled ruleset identifies this atomic rule or correlation."""

    for made in converted:
        correlation = made.get("result_type") == "correlation" or made.get("correlation") is True
        if correlation != (kind == "correlation"):
            continue
        if str(made.get("id") or "") == rule["id"] or str(made.get("title") or "") == rule["title"]:
            return True
    return False


def _not_loaded(rule: dict, conversion: list[dict]) -> dict:
    reason = next(
        (error["reason"] for error in conversion if error.get("rule") == rule["title"]),
        "the engine did not include it in its saved converted ruleset",
    )
    return {"rule": rule["id"], "title": rule["title"], "why": reason}


def evaluate_set(
    engine: Path,
    folder: Path,
    folders: list[str],
    events: list[dict],
    work: Path,
    pipelines: tuple[str, ...] = (),
) -> dict:
    """Give the rules under `folder` to the engine, each of its `folders` by log source, over the events.

    `folder` holds a fetched rule set at its repository's paths and `events` the
    manager's archive lines in order. Returns the engine's name and version, a
    row of counts for each folder and log source (`groups`), the files that are
    not a rule, and the matches. Every match's `event` is a real archived-event
    index; for a correlation it is the latest evidence event, and `evidence`
    is the time-ordered unique archived-event indices including that terminal event.
    """

    version = engine_version(engine)
    work.mkdir(parents=True, exist_ok=True)
    groups, matches, left_out, errors = [], [], [], []
    placeholders: dict[str, list[str]] = {}
    for relative in pipelines:
        path = folder / relative
        try:
            values = pipeline_values(path.read_text(encoding="utf-8"), relative)
        except OSError as error:
            raise EngineError(f"the Sigma pipeline {relative} cannot be read: {error}") from error
        overlap = sorted(set(placeholders) & set(values))
        if overlap:
            raise EngineError(f"the Sigma pipelines define {', '.join(overlap[:5])} more than once")
        placeholders.update(values)

    records: list[dict] = []
    by_folder: dict[str, list[dict]] = {name: [] for name in folders}

    # Read the complete configured set before running anything. Correlations may refer to an atomic rule
    # in another configured folder, and those references must resolve against the same collection.
    for name in folders:
        seen: set[str] = set()
        for path in sorted((folder / name).rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if path.name in PROVENANCE_FILES:
                continue
            file = path.relative_to(folder).as_posix()
            if file in pipelines:
                continue
            rule = read_rule(path.read_text(encoding="utf-8", errors="replace"), file)
            if not isinstance(rule, str) and rule["id"] in seen:
                rule = "its id is that of another rule of the folder"
            if isinstance(rule, str):
                left_out.append({"file": file, "why": rule})
                continue
            seen.add(rule["id"])
            record = {**rule, "folder": name}
            records.append(record)
            by_folder[name].append(record)

    by_reference: dict[str, dict] = {}
    ambiguous: set[str] = set()
    for rule in records:
        for reference in {rule["id"], rule["name"]} - {""}:
            if reference in by_reference and by_reference[reference]["file"] != rule["file"]:
                ambiguous.add(reference)
            else:
                by_reference[reference] = rule

    # Atomic rules retain the old execution contract: each folder/log-source group gets only its own rows.
    for number, name in enumerate(folders, start=1):
        by_source: dict[str, tuple[Source | None, list[dict]]] = {}
        for rule in by_folder[name]:
            if rule["kind"] != "atomic":
                continue
            source = source_of(rule["logsource"])
            key = source if isinstance(source, str) else source.name
            by_source.setdefault(key, (None if isinstance(source, str) else source, []))[1].append(rule)
        for place, (key, (source, rules)) in enumerate(by_source.items(), start=1):
            group: dict = {
                "folder": name,
                "kind": "atomic",
                "log source": key,
                "rules": len(rules),
                "rules loaded": [],
                "atomic rules": len(rules),
                "correlations": 0,
                "loaded": 0,
                "atomic loaded": 0,
                "correlations loaded": 0,
                "given": 0,
                "read": 0,
                "matches": 0,
                "rules that matched": 0,
            }
            groups.append(group)
            if source is None:
                group["log source"], group["not evaluated"] = "none the lab gives", key
                continue
            group["events"] = source.events
            rows = event_rows(source, events)
            group["given"] = len(rows)
            given = sorted(
                {field for _, row in rows for field in row} & set((*source.fields, *CONTEXT_FIELDS))
            )
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
                    engine_copy(
                        text,
                        source.fields,
                        placeholders=placeholders if pipelines else None,
                    ),
                    encoding="utf-8",
                )
            found, engine_loaded, group["read"], conversion, converted = run_engine(
                engine, work, slug, copies, [row for _, row in rows]
            )
            group["engine collection loaded"] = engine_loaded
            loaded_rules = [rule for rule in rules if _was_converted(rule, converted, "atomic")]
            group["rules loaded"] = [{"rule": rule["id"], "title": rule["title"]} for rule in loaded_rules]
            group["loaded"] = group["atomic loaded"] = len(loaded_rules)
            not_loaded = [_not_loaded(rule, conversion) for rule in rules if rule not in loaded_rules]
            if not_loaded:
                group["rules not loaded"] = not_loaded
            if conversion:
                group["conversion errors"] = conversion
                errors.extend({"folder": name, "kind": "atomic", **error} for error in conversion)
            for entry in found:
                if entry.get("result_type") == "correlation":
                    raise EngineError(f"the atomic rule group {slug} returned a correlation")
                rule = _rule_for(entry, rules, slug)
                for match in entry.get("matches") or []:
                    try:
                        place = int(match["row_id"]) - 1
                        if not 0 <= place < len(rows):
                            raise IndexError(place)
                        index, row = rows[place]
                    except (KeyError, ValueError, IndexError, TypeError) as error:
                        raise EngineError(f"the rule engine names a row {slug} does not hold") from error
                    if match.get(column(source.check)) != row.get(source.check):
                        raise EngineError(
                            f"the rule engine's row {match['row_id']} of {slug} is not the row it was given there"
                        )
                    matches.append({"rule": rule, "event": index})
                group["matches"] += len(entry.get("matches") or [])
                group["rules that matched"] += 1

    # A correlation and every atomic rule it refers to share one database. Engine-only copies of the atomic
    # rules require BlueFireSource, so Zircolite cannot apply a rule to rows of a different Sigma log source.
    for number, name in enumerate(folders, start=1):
        correlations = [rule for rule in by_folder[name] if rule["kind"] == "correlation"]
        if not correlations:
            continue
        group = {
            "folder": name,
            "kind": "correlation",
            "log source": "correlation",
            "rules": len(correlations),
            "rules loaded": [],
            "atomic rules": 0,
            "correlations": len(correlations),
            "loaded": 0,
            "atomic loaded": 0,
            "correlations loaded": 0,
            "given": 0,
            "read": 0,
            "matches": 0,
            "rules that matched": 0,
        }
        groups.append(group)
        accepted: list[dict] = []
        collection: dict[str, dict] = {}
        rejected = []
        for rule in correlations:
            dependencies, why = _dependencies(rule, by_reference, ambiguous)
            if why is None:
                for dependency in dependencies:
                    if dependency["kind"] != "atomic":
                        continue
                    source = source_of(dependency["logsource"])
                    if isinstance(source, str):
                        why = f"{dependency['title']}: {source}"
                        break
            if why:
                rejected.append({"rule": rule["id"], "title": rule["title"], "why": why})
                continue
            accepted.append(rule)
            collection.update({dependency["file"]: dependency for dependency in dependencies})
        if rejected:
            group["rules not loaded"] = rejected
        if not accepted:
            group["not evaluated"] = "none of its correlations has dependencies the lab can evaluate"
            continue

        sources: dict[str, Source] = {}
        for rule in collection.values():
            if rule["kind"] == "atomic":
                source = source_of(rule["logsource"])
                if isinstance(source, Source):
                    sources[source.name] = source
        rows = [row for key in sorted(sources) for row in event_rows(sources[key], events)]
        group["events"] = "events of the referenced rules, each restricted to its Sigma log source"
        group["given"] = len(rows)
        given = sorted(
            {field for _, row in rows for field in row if field not in (EVENT_FIELD, SOURCE_FIELD)}
        )
        group["fields given"] = given
        asked = Counter(field for rule in accepted for field in rule["fields"] if field not in given)
        group["fields the rules name that are not given"] = dict(sorted(asked.items()))
        if not rows:
            group["not evaluated"] = "the run holds no event of a referenced log source"
            continue

        slug = f"{number:02d}-correlation-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        copies = work / f"{slug}-rules"
        copies.mkdir(exist_ok=True)
        for old in copies.iterdir():
            old.unlink()
        ordered = sorted(collection.values(), key=lambda rule: (rule["kind"] != "atomic", rule["file"]))
        for count, rule in enumerate(ordered, start=1):
            text = (folder / rule["file"]).read_text(encoding="utf-8", errors="replace")
            if rule["kind"] == "atomic":
                source = source_of(rule["logsource"])
                if not isinstance(source, Source):
                    raise EngineError(f"the source of {rule['file']} changed while making its correlation")
                text = engine_copy(
                    text,
                    source.fields,
                    source,
                    placeholders=placeholders if pipelines else None,
                )
            else:
                text = engine_copy(
                    text,
                    tuple(rule["fields"]),
                    placeholders=placeholders if pipelines else None,
                    correlation=True,
                )
            (copies / f"{count:04d}-{Path(rule['file']).name}").write_text(text, encoding="utf-8")
        found, engine_loaded, group["read"], conversion, converted = run_engine(
            engine, work, slug, copies, [row for _, row in rows]
        )
        group["engine collection loaded"] = engine_loaded
        loaded_correlations = [rule for rule in accepted if _was_converted(rule, converted, "correlation")]
        group["rules loaded"] = [{"rule": rule["id"], "title": rule["title"]} for rule in loaded_correlations]
        group["loaded"] = group["correlations loaded"] = len(loaded_correlations)
        failed = [_not_loaded(rule, conversion) for rule in accepted if rule not in loaded_correlations]
        if failed:
            group.setdefault("rules not loaded", []).extend(failed)
        if conversion:
            group["conversion errors"] = conversion
            errors.extend({"folder": name, "kind": "correlation", **error} for error in conversion)
        for entry in found:
            identifier, title = str(entry.get("id") or ""), str(entry.get("title") or "")
            rule = next(
                (
                    candidate
                    for candidate in accepted
                    if candidate["id"] == identifier or not identifier and candidate["title"] == title
                ),
                None,
            )
            # A nested correlation can be a dependency of one in this folder. Its own generated result is
            # scored only in the configured folder where that correlation is a top-level rule.
            if rule is None:
                continue
            if entry.get("result_type") != "correlation":
                raise EngineError(f"the correlation rule {identifier or title} returned an atomic result")
            for match in entry.get("matches") or []:
                index, evidence, evidence_ids = _evidence(match, rows, slug)
                matches.append(
                    {"rule": rule, "event": index, "evidence": evidence, "evidence ids": evidence_ids}
                )
            group["matches"] += len(entry.get("matches") or [])
            group["rules that matched"] += 1

    matches.sort(key=lambda match: (match["event"], match["rule"]["id"]))
    return {
        "engine": {"name": ENGINE, "version": version},
        "pipelines": list(pipelines),
        "groups": groups,
        "files that are not a rule": left_out,
        "rules": len(records),
        "loaded": sum(group["atomic loaded"] or 0 for group in groups)
        + sum(group["correlations loaded"] or 0 for group in groups),
        "atomic rules": sum(rule["kind"] == "atomic" for rule in records),
        "atomic loaded": sum(group["atomic loaded"] or 0 for group in groups),
        "correlations": sum(rule["kind"] == "correlation" for rule in records),
        "correlations loaded": sum(group["correlations loaded"] or 0 for group in groups),
        "conversion errors": errors,
        "matches": matches,
    }

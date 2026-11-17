"""Read what auditd wrote to its log.

auditd writes one record per line: "type=<kind> msg=audit(<seconds>.<ms>:<serial>):
<fields>". The records of one event share its serial. In the default enriched
format a record's fields are followed by a group separator and the same fields
interpreted, with names in upper case (AUID="bluefire-lab"); the rule engine
reads both.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

# What auditd reports for a process the kernel has no audit session for.
NO_SESSION = "4294967295"

_RECORD = re.compile(r"type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\): ?")
_FIELD = re.compile(r'([\w-]+)=("[^"]*"|\S*)')


def utc(seconds: str, fraction: str) -> str:
    """The time as Sysmon for Linux writes it, so that the two sensors' times compare."""

    moment = datetime.fromtimestamp(int(seconds), timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S") + "." + fraction[:3].ljust(3, "0")


def fields(text: str) -> dict[str, str]:
    return {name: value[1:-1] if value.startswith('"') else value for name, value in _FIELD.findall(text)}


def read(path: Path) -> list[dict]:
    """The records of the log in their order, each with its line as the rule engine reads it."""

    records = []
    for line in path.read_bytes().decode("utf-8", "replace").split("\n"):
        found = _RECORD.match(line)
        if found is None:
            continue
        raw, _, interpreted = line[found.end() :].partition("\x1d")
        records.append(
            {
                "type": found.group(1),
                "time": utc(found.group(2), found.group(3)),
                "serial": found.group(4),
                "fields": fields(raw),
                "interpreted": fields(interpreted),
                "line": line,
            }
        )
    return records


def command_line(value: str) -> str:
    """A PROCTITLE record's command line: hex, with NUL between the arguments."""

    try:
        return bytes.fromhex(value).replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except ValueError:
        return value  # auditd writes it as plain text when it has no unusual characters


def events(records: list[dict]) -> list[dict]:
    """The events of the log: the records that share a serial, joined."""

    joined: dict[str, dict] = {}
    for record in records:
        event = joined.setdefault(
            record["serial"],
            {"serial": record["serial"], "time": record["time"], "types": [], "call": {}, "names": {},
             "paths": [], "command": ""},
        )  # fmt: skip
        event["types"].append(record["type"])
        if record["type"] == "SYSCALL":
            event["call"], event["names"] = record["fields"], record["interpreted"]
        elif record["type"] == "PATH" and record["fields"].get("nametype") != "PARENT":
            event["paths"].append(record["fields"].get("name", ""))
        elif record["type"] == "PROCTITLE":
            event["command"] = command_line(record["fields"].get("proctitle", ""))
    return list(joined.values())


def status(text: str) -> dict[str, str]:
    """What "auditctl -s" printed, by name: enabled, lost, backlog and the rest."""

    return dict(line.strip().split(None, 1) for line in text.splitlines() if len(line.split()) > 1)

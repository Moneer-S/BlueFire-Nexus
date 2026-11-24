"""Read what the range's Wazuh pieces wrote: the manager's archive, its state files and its tools' output.

The functions here read files copied out of the range and the output of
commands the engine ran there; running those commands is the job of `engine`.
"""

from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

ARCHIVES = "/var/ossec/logs/archives/archives.json"
ALERTS = "/var/ossec/logs/alerts/alerts.json"
AGENT_STATE = "/var/ossec/var/run/wazuh-agentd.state"
OSSEC_LOG = "/var/ossec/logs/ossec.log"
REALTIME_STARTED = "Real-time file integrity monitoring started"
# Errors of the agent's file monitoring after which a folder is not watched in real time, although the
# line above is logged all the same: inotify could not be set up, or the limit of inotify watches
# (fs.inotify.max_user_watches) was reached while a folder was added.
REALTIME_ERRORS = ("(6607): ", "(6618): ", "(6700): ")
# Lines of an agent's own log that say events may have been lost, by what they count.
LOST_WARNINGS = {
    "agent buffer full": "buffer is full",
    "real-time inotify queue full": "inotify kernel queue is full",
}
VERSION = re.compile(r"Wazuh v([0-9]+\.[0-9]+\.[0-9]+)")


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DAILY = re.compile(r"ossec-(?:archive|alerts)-([0-9]{2})\.json(?:\.gz)?\Z")


def daily_files(folder: Path) -> list[Path]:
    """A copied logs/archives or logs/alerts folder: its daily files, oldest first.

    Wazuh writes each day to <year>/<month>/ossec-archive-<day>.json, compresses
    it when the day is over, and keeps archives.json as a link to the current
    day's file. Reading the daily files reads each event once, including days
    rotated during the run. A folder without them gives its archives.json or
    alerts.json.
    """

    found = []
    for path in folder.rglob("ossec-*.json*"):
        match = DAILY.match(path.name)
        parts = path.relative_to(folder).parts
        if match and len(parts) == 3 and parts[0].isdigit() and parts[1] in MONTHS:
            found.append(((int(parts[0]), MONTHS.index(parts[1]), int(match.group(1))), path))
    if found:
        return [path for _, path in sorted(found)]
    return sorted(p for p in folder.glob("*.json*") if p.name.split(".")[0] in ("archives", "alerts"))[:1]


def events(paths: list[Path]) -> list[dict]:
    """The events of Wazuh JSON log files (archives or alerts), plain or gzipped, in the order given."""

    found = []
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as lines:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    found.append(json.loads(line))
                except ValueError:
                    continue
    return found


def timestamp(value: str) -> float:
    """Seconds since the epoch of a Wazuh `timestamp`, such as 2026-11-23T17:29:20.870+0000."""

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def state(text: str) -> dict:
    """A Wazuh .state file: key='value' lines with comments, or JSON (logcollector's)."""

    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError:
            return {}
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        found[key.strip()] = value.strip().strip("'")
    return found


def drops(states: dict[str, dict]) -> dict[str, dict[str, str]]:
    """Wazuh's own counters of lost or discarded events, by state file.

    analysisd and remoted count them in keys named so; logcollector counts the
    lines it could not hand on, per file, from its start to the time it last
    wrote the file, which is given as `counted until`.
    """

    found = {}
    for name, values in states.items():
        if isinstance(values.get("global"), dict):
            found[name] = {
                f"{entry.get('location')} drops": str(
                    sum(t.get("drops", 0) for t in entry.get("targets") or [])
                )
                for entry in values["global"].get("files") or []
            }
            found[name]["counted until"] = str(values["global"].get("end"))
        else:
            found[name] = {k: v for k, v in values.items() if "drop" in k or "discard" in k}
    return found


def dropped(counters: dict[str, dict[str, str]]) -> bool:
    """True when any of Wazuh's own counters of lost events is above zero."""

    return any(
        value.isdigit() and int(value) > 0 for values in counters.values() for value in values.values()
    )


def state_time(value: str) -> float | None:
    """Seconds since the epoch of the time in a logcollector state file, written in UTC as 2026-11-23 20:03:08."""

    try:
        return datetime.strptime(value + " +0000", "%Y-%m-%d %H:%M:%S %z").timestamp()
    except ValueError:
        return None


def lost_warnings(ossec_log: str) -> dict[str, str]:
    """How often an agent's own log says events may have been lost: its buffer or the inotify queue was full."""

    lines = ossec_log.lower().split("\n")
    return {name: str(sum(1 for line in lines if text in line)) for name, text in LOST_WARNINGS.items()}


def agents(output: str) -> dict[str, dict[str, str]]:
    """`agent_control -l` output: each agent's ID and status, by name. The manager itself (000) is left out."""

    found = {}
    for match in re.finditer(r"ID: ([0-9]+), Name: ([^,]+), IP: [^,]+, (\S+)", output):
        identifier, name, status = match.groups()
        if identifier != "000":
            found[name.strip()] = {"id": identifier, "status": status}
    return found


def agent_info(output: str) -> dict[str, str | None]:
    """`agent_control -i <id>` output: the agent's status and version."""

    status = re.search(r"Status:\s+(\S+)", output)
    version = VERSION.search(output)
    return {"status": status.group(1) if status else None, "version": version.group(1) if version else None}


def find(found: list[dict], text: str, agent: str | None = None, location: str | None = None) -> list[dict]:
    """The events whose full_log holds `text`, from one agent and one location when given."""

    return [
        event
        for event in found
        if text in (event.get("full_log") or "")
        and (agent is None or (event.get("agent") or {}).get("name") == agent)
        and (location is None or event.get("location") == location)
    ]


def lines_of(content: str) -> list[str]:
    """A log file's lines, split as the engine counts them in the host: at each newline, and nowhere else."""

    lines = content.split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def delivery(
    agent: str,
    logs: dict[str, list[str] | None],
    windows: dict[str, tuple[int, int] | None],
    found: list[dict],
) -> list[dict]:
    """For each log file of one agent host: its lines in the window, and how many reached the archive.

    `logs` holds each file's lines as copied out of the host after the run (None
    when it was not copied), and `windows` the line numbers the engine read in
    the same command that logged the ready nonce, and later the end nonce: the
    window is the lines between them. A line is delivered when
    an event of this agent and this location in the archive has it as its full
    log; each event counts once, and the events that the file's lines before and
    after the window account for are taken out first, so that an identical line
    outside the window never counts as delivered inside it. A file that was not
    copied, or that has fewer lines than its window, is not counted: its row
    says why, and `missing` is None.

    The archive's order is not used: the manager receives each file's lines on
    their own, so its events of one file can come after another file's end
    nonce.
    """

    ordered = [event for event in found if (event.get("agent") or {}).get("name") == agent]
    rows = []
    for path, lines in logs.items():
        row = {"source": path, "lines": None, "delivered": None, "missing": None}
        rows.append(row)
        if windows.get(path) is None:
            row["not counted"] = "the engine read no line count of the file at the ready or the end nonce"
            continue
        start, end = windows[path]
        if lines is None:
            row["not counted"] = "the file was not copied out of the host"
            continue
        if end < start or len(lines) < end:
            row["not counted"] = (
                f"the copied file has {len(lines)} lines, and the window is its lines {start} to {end}"
            )
            continue
        window = lines[start:end]
        archived = Counter(event.get("full_log") for event in ordered if event.get("location") == path)
        archived.subtract(Counter(lines[:start]) + Counter(lines[end:]))
        delivered = sum(min(count, max(0, archived[line])) for line, count in Counter(window).items())
        row.update(lines=len(window), delivered=delivered, missing=len(window) - delivered)
    return rows


def window_counts(output: str) -> tuple[dict[str, int], float | None]:
    """The line counts and the time the engine's ready or end command printed before it logged its nonce."""

    counts, logged = {}, None
    for line in output.splitlines():
        kind, _, rest = line.partition("\t")
        if kind == "lines":
            path, _, number = rest.rpartition("\t")
            if number.isdigit():
                counts[path] = int(number)
        elif kind == "time":
            try:
                logged = float(rest)
            except ValueError:
                logged = None
    return counts, logged


def summary(manifest: dict, seal_passed: bool) -> str:
    """The defense of a run as Markdown, for a CI job's summary."""

    defense = manifest.get("defense") or {}
    gap = defense.get("delivery_gap")
    title = {True: "delivery gap", False: "no delivery gap"}.get(gap, "delivery not counted")
    lines = [
        f"### Defense of {manifest.get('range')}: {title}",
        "",
        f"Wazuh {defense.get('wazuh_version')}, manager and agents. Seal {'passed' if seal_passed else 'failed'}. "
        f"Result: {manifest.get('result')} (exit code {manifest.get('exit_code')}). "
        f"{manifest.get('environment')}, Docker {manifest.get('docker', {}).get('server', '?')}.",
        "",
    ]
    if manifest.get("reason"):
        lines += [f"Reason: {manifest['reason']}", ""]
    if defense.get("delivery_findings"):
        lines += [f"{title.capitalize()}: " + "; ".join(defense["delivery_findings"]) + ".", ""]
    ready = defense.get("ready") or {}
    if ready:
        lines += ["| Ready | Seconds after the containers started |", "|---|---|"]
        for part, value in ready.get("parts", {}).items():
            lines.append(f"| {part} | {value if value is not None else 'not reached'} |")
        lines.append("")
        nonces = ready.get("nonces") or {}
        if nonces:
            lines += ["| Host | Ready nonce from logger to the manager's archive (s) |", "|---|---|"]
            lines += [f"| {host} | {item.get('delay_seconds')} |" for host, item in nonces.items()]
            lines.append("")
    marks = defense.get("marks") or []
    if marks:
        lines += ["| Mark | Host | Source | In the archive | Seconds |", "|---|---|---|---|---|"]
        lines += [
            f"| {m['mark']} | {m['host']} | {m['source']} | "
            f"{('yes' if m['archived'] else 'no') if m['made'] else 'not made'} | "
            f"{m.get('delay_seconds') if m.get('delay_seconds') is not None else ''} |"
            for m in marks
        ]
        lines.append("")
    rows = defense.get("delivery") or {}
    if rows:
        lines += [
            "| Host | Log | Lines from the ready nonce to the end | Of them in the archive | Missing |",
            "|---|---|---|---|---|",
        ]
        for host, sources in rows.items():
            for row in sources:
                if row["missing"] is None:
                    counts = f"not counted: {row.get('not counted')} | | "
                elif not row["lines"]:
                    counts = "0 | | not shown: no line in the window"
                else:
                    counts = f"{row['lines']} | {row['delivered']} | {row['missing']}"
                lines.append(f"| {host} | {row['source']} | {counts} |")
        lines.append("")
    counters = defense.get("drops") or {}
    if counters:
        lines += ["| Wazuh's own counters of lost events | Values |", "|---|---|"]
        for name, values in counters.items():
            shown = ", ".join(f"{key} {value}" for key, value in values.items()) or "none in the file"
            lines.append(f"| {name} | {shown} |")
        lines.append("")
    snoopy = defense.get("snoopy_tag")
    if snoopy:
        lines += [
            f"snoopy's tag field: {'recorded' if snoopy.get('works') else 'not recorded'} "
            f"(the mark's program start was decoded with tag {snoopy.get('seen')!r}).",
            "",
        ]
    return "\n".join(lines)

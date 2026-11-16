"""Read what Sysmon for Linux wrote to the journal.

Sysmon writes one XML event per line. Besides events it logs a few lines of
plain text, among them its own count of lost events when it stops.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path

PROCESS_START, NETWORK, PROCESS_END, FILE_CREATED, FILE_DELETED = "1", "3", "5", "11", "23"
KINDS = {
    PROCESS_START: "process start",
    NETWORK: "network connection",
    PROCESS_END: "process end",
    FILE_CREATED: "file created",
    FILE_DELETED: "file deleted",
}

# What Sysmon reports when the kernel has no audit session for a process, and
# when it does not know a process's parent.
NO_SESSION = "4294967295"
NO_PARENT = "{00000000-0000-0000-0000-000000000000}"

_LOST = re.compile(r"Lost events: (\d+), in (\d+) notifications")
_BAD = re.compile(r"Total events: (\d+), bad events: (\d+)")


def parse_line(line: str) -> dict[str, str] | None:
    """Return the fields of the event on this line, or None if it holds no event."""

    start, end = line.find("<Event>"), line.rfind("</Event>")
    if start < 0 or end < 0:
        return None
    try:
        root = ElementTree.fromstring(line[start : end + len("</Event>")])
    except ElementTree.ParseError:
        return None
    event = {data.get("Name", ""): data.text or "" for data in root.iter("Data")}
    event["EventID"] = root.findtext("System/EventID") or ""
    event["EventRecordID"] = root.findtext("System/EventRecordID") or ""
    return event


def read(path: Path) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Return the events, the raw line of each event, and the lines without an event."""

    events, raw, other = [], [], []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            event = parse_line(line)
            if event is None:
                other.append(line)
            else:
                events.append(event)
                raw.append(line)
    return events, raw, other


def loss(events: list[dict[str, str]], other: list[str]) -> dict[str, object]:
    """Say whether events were lost between the kernel and the exported file.

    Two things are checked. Sysmon prints how many events it failed to read
    from the kernel when it stops. And it numbers the records it writes, so a
    record that the journal dropped leaves a hole in the numbers.
    """

    text = "\n".join(other)
    lost, bad = _LOST.search(text), _BAD.search(text)
    numbers = sorted({int(event["EventRecordID"]) for event in events if event["EventRecordID"]})
    missing = (numbers[-1] - numbers[0] + 1 - len(numbers)) if numbers else 0
    return {
        "sensor_reported": lost is not None,
        "lost_events": int(lost.group(1)) if lost else None,
        "bad_events": int(bad.group(2)) if bad else None,
        "records": len(numbers),
        "missing_records": missing,
    }

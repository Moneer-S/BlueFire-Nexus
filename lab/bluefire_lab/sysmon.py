"""Read what Sysmon for Linux wrote to the journal.

Sysmon writes one XML event per message, and the journal prints one message
per line, unless the event's text itself holds a line break: a test's command
line can. Besides events Sysmon logs a few lines of plain text, among them its
own count of lost events when it stops.
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
    """Return the events, the raw text of each event, and the lines without an event.

    An event whose text holds a line break spans several lines: they are joined.
    Sysmon escapes "<" in event text, so a closing tag in the middle of an
    event cannot occur.
    """

    events, raw, other = [], [], []
    pending: str | None = None
    with open(path, encoding="utf-8", errors="replace", newline="\n") as handle:
        for line in handle:
            line = line.removesuffix("\n")
            if pending is not None:
                line, pending = pending + "\n" + line, None
            if line.startswith("<Event>") and "</Event>" not in line:
                pending = line
                continue
            event = parse_line(line)
            if event is None:
                other.append(line)
            else:
                events.append(event)
                raw.append(line)
    if pending is not None:
        other.append(pending)  # an event cut short at the end of the export
    return events, raw, other


def one_line(text: str) -> str:
    """The event's text on one line, for tools that read one event per line.

    A line break inside the XML text becomes a character reference, which an
    XML parser reads back as the same line break.
    """

    return text.replace("\r", "&#13;").replace("\n", "&#10;")


def loss(events: list[dict[str, str]], other: list[str]) -> dict[str, object]:
    """Say whether events were lost between the kernel and the exported file.

    Three things are checked. Sysmon prints how many events it failed to read
    from the kernel when it stops. It numbers the records it writes, so a
    record that the journal dropped leaves a hole in the numbers. And it
    records its own start, so a restart in the middle of a run shows.
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
        "sensor_starts": sum(
            1 for event in events if event["EventID"] == "4" and event.get("State") == "Started"
        ),
    }

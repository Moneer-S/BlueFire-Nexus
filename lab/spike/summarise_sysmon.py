#!/usr/bin/env python3
"""Print what Sysmon for Linux recorded for the spike's probe commands.

Usage: summarise_sysmon.py <file with one syslog or journal message per line> <nonce>
"""

from __future__ import annotations

import collections
import sys
import xml.etree.ElementTree as ElementTree


def parse(line: str) -> dict[str, str] | None:
    start, end = line.find("<Event>"), line.rfind("</Event>")
    if start < 0 or end < 0:
        return None
    try:
        root = ElementTree.fromstring(line[start : end + len("</Event>")])
    except ElementTree.ParseError:
        return None
    event = {data.get("Name", "?"): data.text or "" for data in root.iter("Data")}
    event["EventID"] = root.findtext("System/EventID") or "?"
    return event


def main() -> int:
    path, nonce = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    events, unparsed = [], []
    for line in lines:
        event = parse(line)
        (events if event else unparsed).append(event or line)
    print(f"{path}: {len(lines)} lines, {len(events)} events, {len(unparsed)} lines without a whole event")
    print("longest line:", max((len(line) for line in lines), default=0), "characters")
    for line in unparsed[:5]:
        print("  not an event:", line[:300])
    print("events by id:", dict(sorted(collections.Counter(e["EventID"] for e in events).items())))

    shown = set()
    for event in events:
        if event["EventID"] not in shown:
            shown.add(event["EventID"])
            print(f"\nfields of event {event['EventID']}:", ", ".join(event))
            print("  example:", {key: value[:120] for key, value in event.items()})

    print("\nprobe events:")
    for event in events:
        text = event.get("CommandLine", "") + event.get("TargetFilename", "")
        if nonce not in text:
            continue
        print(
            "  id={EventID} time={UtcTime} pid={ProcessId} image={Image}".format_map(
                collections.defaultdict(str, event)
            ),
            f"commandline_length={len(event.get('CommandLine', ''))}",
            f"target={event.get('TargetFilename', '')}",
            f"commandline={event.get('CommandLine', '')[:100]!r}",
            f"parent={event.get('ParentProcessId', '')} {event.get('ParentImage', '')}",
            f"parent_commandline={event.get('ParentCommandLine', '')[:100]!r}",
            sep="\n      ",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

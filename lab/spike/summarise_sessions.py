#!/usr/bin/env python3
"""Print the processes Sysmon recorded for each audit session, as a tree.

Usage: summarise_sessions.py <file with one Sysmon event per line> [<sessions file>]
The sessions file holds one "<label> <session id>" line per step that was run.
"""

from __future__ import annotations

import collections
import sys

from summarise_sysmon import parse

UNSET = "4294967295"


def main() -> int:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        events = [event for event in map(parse, handle) if event]
    labels = {}
    if len(sys.argv) > 2:
        with open(sys.argv[2], encoding="utf-8") as handle:
            labels = {line.split()[1]: line.split()[0] for line in handle if line.strip()}

    creates = sorted((e for e in events if e["EventID"] == "1"), key=lambda e: e["UtcTime"])
    by_guid = {event["ProcessGuid"]: event for event in creates}
    others: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for event in events:
        if event["EventID"] != "1":
            others[event.get("ProcessGuid", "")][event["EventID"]] += 1

    sessions = collections.defaultdict(list)
    for event in creates:
        sessions[event.get("TerminalSessionId", "?")].append(event)
    print("process starts per session:", {key: len(value) for key, value in sessions.items()})
    print("users seen:", dict(collections.Counter(event.get("User", "?") for event in creates)))

    for session, members in sessions.items():
        if session == UNSET:
            continue
        print(f"\nsession {session} ({labels.get(session, 'no label')}): {len(members)} process starts")
        for event in members:
            depth, cursor = 0, event
            while cursor.get("ParentProcessGuid") in by_guid and depth < 20:
                cursor = by_guid[cursor["ParentProcessGuid"]]
                if cursor.get("TerminalSessionId") != session:
                    break
                depth += 1
            extra = dict(others.get(event["ProcessGuid"], {}))
            print(
                "  " * depth
                + f"{event['UtcTime'][11:]} pid={event['ProcessId']} ppid={event['ParentProcessId']}"
                + f" user={event['User']} logon={event['LogonId']} {event['Image']}"
                + f" :: {event['CommandLine'][:300]!r} other_events={extra}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())

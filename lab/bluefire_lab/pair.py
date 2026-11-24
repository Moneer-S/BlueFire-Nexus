"""Decide how a pull request's change to the defense is shown, and what it declares.

The defense here is what a run loads from the lab's folder: the lab's own rules and
the two sensors' settings. What decides is the digest of those files, the same
digest a recording carries for them, not which paths the pull request touched: a
change that leaves the files as they were runs the list once, as every run that is
not of a pull request does.

On the single host the rules are evaluated after the run, over the telemetry it
recorded. So a change of the lab's rules alone needs no second run of the tests:
the list runs once, and its telemetry is evaluated twice, with the base commit's
rules and with the head's (pair=rules). A change of a sensor's settings changes
what is recorded, so the list runs twice, on two runners, with the base's files
and with the head's (pair=runs). A change of both is two changes: it runs twice
and declares nothing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .recording import digest

# What a run loads from the lab's folder, by the name a recording gives it. The lab workflow
# passes these paths to "bluefire-lab run" and copies the rules into the run's folder.
PARTS = {
    "sensors:sysmon": "sensors/sysmon.xml",
    "sensors:auditd": "sensors/audit.rules",
    "detectors:lab": "rules/linux",
}
WORDS = {
    "sensors:sysmon": "the settings of Sysmon",
    "sensors:auditd": "the rules of auditd",
    "detectors:lab": "the lab's own rules",
}


def fingerprint(path: Path) -> str | None:
    """The SHA-256 of a file, or of a folder of rules as a recording computes it. None when it is missing."""

    if path.is_dir():
        return digest(path)
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return None


def changed(base: Path, head: Path) -> list[str]:
    """The parts of the defense whose files differ between the two lab folders, in the order of PARTS."""

    return [name for name, part in PARTS.items() if fingerprint(base / part) != fingerprint(head / part)]


def decide(base: Path | None, head: Path) -> dict[str, str]:
    """How the change is shown (pair: no, rules or runs), which sides run the list, the one change it
    declares, and a sentence for the summary.

    No base folder means the run is not of a pull request: it runs once, with the head's files.
    A change of the lab's rules alone runs the list once and evaluates it twice. More than one
    changed part declares nothing, and the comparison then gives no verdict.
    """

    once = {"pair": "no", "sides": json.dumps(["head"]), "change": ""}
    if base is None or not base.is_dir():
        return {**once, "said": "This run has no base commit to compare with, so the list runs once."}
    names = changed(base, head)
    if not names:
        return {
            **once,
            "said": "The lab's own rules and the sensors' settings are the same as the base commit's, "
            "so the list runs once.",
        }
    if names == ["detectors:lab"]:
        return {
            "pair": "rules",
            "sides": json.dumps(["head"]),
            "change": "detectors:lab",
            "said": f"Of the defense, this pull request changes only {WORDS['detectors:lab']}. The rules are "
            "evaluated after a run, over the telemetry it recorded, so the list runs once, with the head's "
            "files, and that one run's telemetry is evaluated twice: with the base commit's rules and with "
            "the head's.",
        }
    pair = {"pair": "runs", "sides": json.dumps(["base", "head"])}
    if len(names) == 1:
        return {
            **pair,
            "change": names[0],
            "said": f"Of the defense, this pull request changes only {WORDS[names[0]]}: the list runs twice, each "
            "time on a fresh runner of its own, with the base commit's files and with the head's. Both runs use "
            "this commit's code, list and tools.",
        }
    listed = ", ".join(WORDS[name] for name in names[:-1]) + f" and {WORDS[names[-1]]}"
    return {
        **pair,
        "change": "",
        "said": f"This pull request changes more than one part of the defense: {listed}. The list runs twice, "
        "with the base commit's files and with the head's, but no one change is declared, so the comparison "
        "gives no verdict.",
    }


def main(base: Path | None, head: Path) -> int:
    """Print the decision as name=value lines, the form a workflow step's outputs take."""

    for name, value in decide(base, head).items():
        print(f"{name}={value}")
    return 0

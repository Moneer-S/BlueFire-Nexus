"""Where each event and alert of a run came from, what the defense made of each step, and of the ordinary day.

Every archived event and every alert gets one origin, by the first rule that holds:

1. `engine`: snoopy tagged its program start `engine:*` (a program start is
   decided by its tag alone, since a step's command can name a mark file), or
   another line holds the run's ID, which every nonce and mark of the engine
   carries, and so does the name of every mark file the engine makes. What the plant checks and the
   seal's probes leave behind (a login's session lines, a PHP session file)
   carries no ID.
2. `cleanup`: snoopy tagged its program start `cleanup:<id>`, or it is a file
   integrity event on its step's host, inside the window of a step's published
   cleanup, for a file that the cleanup's command names.
3. `ordinary`: it is a job's of the ordinary activity, sorted to the job as
   `activity.attribute` sorts it (the job's tag, its host's address, the path
   of an http job's request, the account it logs in as, the files it writes,
   inside its window); or snoopy tagged it `job:<name>`. A program start with
   another job's tag is never an ssh job's by its account or address, and an
   nginx line for a path no job fetches is no job's. `labels.job` names the
   job. Cron's session line of a cron job's account inside the job's window is
   ordinary with no `labels.job`, since it does not tell one cron entry of the
   account from another.
4. `step`: what is left is tied to a step of the path on evidence the run
   holds, by the first of these that holds (`labels.tied_by`):
   - `session`: snoopy tagged its program start `step:<id>`;
   - `account`: it names an account the path uses on its host (webadmin on
     web, deploy on build: the activity's loader refuses a job that uses one),
     inside a step's window;
   - `address`: its own source address is an address of the host the step ran
     on, inside the step's window, as sshd's lines on web from attacker's
     address in s01's; or, on a host the step reached (`to`), its text names
     an address of the step's host or that host's container name, as sshd's
     and MariaDB's lines often do when no decoder takes the address out;
   - `content`: on a host the step ran on or reached, inside its window, a file
     integrity event for a path the step was given as an argument, or under
     it, or a log line that names such a path.
   A step's window runs from the Docker daemon's start of its test to `GRACE`
   seconds after the daemon's end, and a second longer, from the start of its
   second, for a line whose own time is to the second. Where two windows hold
   a moment, the later step that had started by then has it.
5. `unattributed`: everything else. These are listed and counted, and never
   called ordinary. One that only falls inside a step's window, on a host the
   step ran on or reached, carries that step and `tied_by` `window`: it is
   coincident in time and never counts toward what the defense saw of the step.

An alert takes the origin and tie of its event in the archive (the same agent,
location, line and manager time), so that a correlation rule such as 40112 is
tied by the line it was raised on, not by the lines before it. An alert with no
such event is given one by the same rules, read on the alert itself.

What the defense made of each step (`path_score`), in the words of
docs/RECORDING.md: `alert` when an alert of the stock rules at the alert level
or higher is tied to the step, `telemetry only` when at least one event is,
`no telemetry` otherwise, and `not applicable` when the attack did not start;
ties by `window` never count. A step cannot be stopped in a range that
configures no active response. The race: the time from the start of the first
step to the first such alert, at the moment the manager raised it, against the
time from the same start to the end of the step that reached the goal, when the
goal check passed. Both are on one clock: the Docker daemon's for the steps,
the manager container's for the alerts, and the kernel's both; `clock` checks
it on each run, against the program starts snoopy logged inside each step.

The ordinary day's score: false alerts are the distinct stock rules at the
range's alert level or higher among the alerts whose origin is `ordinary`;
the rules from level 7 up to the alert level on ordinary work are a second
number, for review, never added to the first. Alerts at the alert level on the
engine's own work and on unattributed events are listed apart: the bench's own
noise is not the shop's.

A named defense (`defenses` in the spec) is the kinds of sensor it records
with and the rules it runs. One run is recorded with every sensor on, and each
defense judges that same run (`judge`): it counts only the events its own
sensors recorded and only the matches of its own rules. The rules the manager
ran live are its alerts; a rule set that is evaluated after the run (`sigma`)
gives matches, each at the time of its event and with no time of being raised,
which count as alerts when the rule's own level is high or critical. A match
is tied as an alert is, by the event it is on: to a step, to the ordinary day,
or, on the engine's own work or an unattributed event, listed apart and never
counted. The score above stays the detail of the manager's live rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import posixpath
import re
import shlex
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from ..recording import outcome as score_word
from ..report import count
from . import activity, ecs, packets, rulesets, sigma, suricata, wazuh
from .spec import PACKET_CAPTURE, WAZUH_AGENT, WAZUH_RULES, Defense, RuleSet, SpecError

ENGINE = "engine"
CLEANUP = "cleanup"
ORDINARY = "ordinary"
STEP = "step"
UNATTRIBUTED = "unattributed"
ORIGINS = (ENGINE, CLEANUP, ORDINARY, STEP, UNATTRIBUTED)
# How a line is tied to a step, in the order the rules are tried; a tie by window never counts.
TIES = ("session", "account", "address", "content", "window")
COUNTED = TIES[:-1]
# A step's window runs this many seconds past the end of its test, as the executor's grace does.
GRACE = 5
STEPS_FILE = "steps.ecs.ndjson"
# A path a step is given as an argument, or a cleanup's command names.
PLAIN_PATH = re.compile(r"/[A-Za-z0-9._/-]*[A-Za-z0-9._-]\Z")
WORD = re.compile(r"[^\s;|&<>()'\"`]+")
HOST_TOKEN = re.compile(r"[a-z][a-z0-9-]*\Z")
# Wazuh's levels in bands: informational, low, medium, high and critical.
BANDS = ((0, 3, "0 to 3"), (4, 6, "4 to 6"), (7, 11, "7 to 11"), (12, 14, "12 to 14"), (15, 15, "15"))
REVIEW_FROM = 7
# A step seen only by the address rule names this many of its lines, each cut to this many characters.
SHOWN_LINES = 3
LINE_CHARACTERS = 240
EVENTS_FILE = "events.ecs.ndjson"
NETWORK_EVENTS_FILE = "events.network.ecs.ndjson.gz"
LEGACY_NETWORK_EVENTS_FILE = "events.network.ecs.ndjson"
ALERTS_FILE = "alerts.ecs.ndjson"
# The matches of a rule set that was evaluated after the run, by the set's name.
MATCHES_FILE = "alerts.{}.ecs.ndjson"
PUBLIC_RULE_REPOSITORY = "https://github.com/Moneer-S/BlueFire-Nexus/blob/main"
# The manager's live rules as a recording names their detector, and when each kind of rules ran.
PINNED = "pinned"
LIVE = "live"
AFTER = "after the run"
# The defense of a range whose spec names none: its agents and the rules its manager runs live.
BASELINE = Defense("wazuh-stock", "Wazuh with its stock rules", (WAZUH_AGENT,), (WAZUH_RULES,))


def sensor_id(kind: str, host: str) -> str:
    """A sensor's id in a recording: its kind and the host it runs on."""

    return f"{kind}-{host}"


def detector_id(rules: str) -> str:
    """The id of a defense's rules as a recording's detector: `pinned` for the manager's live rules, as before."""

    return PINNED if rules == WAZUH_RULES else rules


def _eve_time(value: object, field: str) -> datetime:
    """A zoned time written by Suricata's EVE output."""

    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"a Suricata record has no {field} that can be read: {error}") from error
    if moment.tzinfo is None:
        raise ValueError(f"a Suricata record's {field} has no time zone")
    return moment


def _capture_interface(raw: dict) -> str:
    name = Path(str(raw.get("pcap_filename") or "")).name
    if not name.endswith(".pcap") or name in (".pcap", ""):
        raise ValueError("a Suricata record does not name its input PCAP")
    return name.removesuffix(".pcap")


def _suricata_level(raw: dict) -> str:
    return suricata.severity((raw.get("alert") or {}).get("severity"))


def _observation_sensor(event: dict) -> str:
    labelled = str((event.get("labels") or {}).get("sensor") or "")
    if labelled:
        return labelled
    host = (event.get("agent") or {}).get("name")
    return sensor_id(WAZUH_AGENT, str(host)) if host else ""


def _observation_host(event: dict) -> str | None:
    if "@timestamp" in event:
        return (event.get("observer") or {}).get("name") or (event.get("host") or {}).get("name")
    return (event.get("agent") or {}).get("name")


def _observation_time(event: dict) -> datetime:
    if "@timestamp" in event:
        return _eve_time(event.get("@timestamp"), "@timestamp")
    return _when(event)


def _tag(event: dict) -> str:
    if event.get("location") != activity.SNOOPY_LOG:
        return ""
    return str((event.get("data") or {}).get("tag") or "")


def _line(event: dict) -> str:
    """An archived line in a few words: its agent, its log and its text, cut short."""

    if "@timestamp" in event:
        text = str((event.get("event") or {}).get("original") or event.get("message") or "").strip()
        text = text if len(text) <= LINE_CHARACTERS else text[: LINE_CHARACTERS - 3] + "..."
        return f"{_observation_host(event)}, {_observation_sensor(event)}: {text}"
    text = str(event.get("full_log") or "").strip()
    text = text if len(text) <= LINE_CHARACTERS else text[: LINE_CHARACTERS - 3] + "..."
    return f"{(event.get('agent') or {}).get('name')}, {event.get('location')}: {text}"


def _engine(event: dict, run_id: str) -> bool:
    if event.get("location") == activity.SNOOPY_LOG:
        # A step's own command can name a mark file, as s08's tar of /etc does: its tag decides.
        return _tag(event).startswith("engine:")
    path = str((event.get("syscheck") or {}).get("path") or "")
    return run_id in (event.get("full_log") or "") or run_id in path


@dataclass(frozen=True)
class Stretch:
    """A step's test, or its published cleanup, as the ties read it: when it ran, where, and the paths it names.

    `started` and `ended` are the Docker daemon's times of its exec, in seconds.
    """

    step: str
    host: str
    to: tuple[str, ...]
    started: float
    ended: float
    paths: tuple[str, ...] = ()
    # Range host names explicitly present in the step's arguments, beyond its published `to`.
    peers: tuple[str, ...] = ()

    def holds(self, when: float, whole: bool) -> bool:
        """True for a moment inside the window; `whole` for a time to the second."""

        low = math.floor(self.started) if whole else self.started
        return low <= when <= self.ended + GRACE + (1 if whole else 0)

    def on(self, host: str | None) -> bool:
        return host == self.host or host in self.to


def argument_paths(args: object) -> tuple[str, ...]:
    """The input arguments of a step that are absolute paths."""

    values = args.values() if isinstance(args, dict) else []
    return tuple(dict.fromkeys(v for v in values if isinstance(v, str) and PLAIN_PATH.match(v)))


def network_peers(record: dict) -> tuple[str, ...]:
    """Range host names a step explicitly reaches, from `to` and its recorded arguments."""

    found: list[str] = []
    declared = record.get("to")
    if isinstance(declared, str):
        found.append(declared)
    elif isinstance(declared, (list, tuple)):
        found.extend(value for value in declared if isinstance(value, str))
    args = record.get("args")
    for value in args.values() if isinstance(args, dict) else ():
        if not isinstance(value, str):
            continue
        parsed = urlsplit(value)
        if parsed.scheme and parsed.hostname:
            found.append(parsed.hostname)
        found.extend(host for _, host in activity.AT_HOST.findall(value))
        if HOST_TOKEN.fullmatch(value):
            found.append(value)
    return tuple(dict.fromkeys(host for host in found if host != record.get("host")))


def cleanup_paths(text: str, workdir: str) -> tuple[str, ...]:
    """The paths a cleanup's command names, from its `cleanup.txt`, those written relative to its folder too.

    The first line of the file is `command: ` and the docker exec command line,
    whose last word is the published cleanup's command.
    """

    first = text.splitlines()[0] if text else ""
    if not first.startswith("command: "):
        return ()
    try:
        command = shlex.split(first.removeprefix("command: "))[-1]
    except (ValueError, IndexError):
        return ()
    found = []
    for word in WORD.findall(command):
        if word.startswith("-"):
            continue
        path = posixpath.normpath(word if word.startswith("/") else posixpath.join(workdir, word))
        if PLAIN_PATH.match(path):
            found.append(path)
    return tuple(dict.fromkeys(found))


def stretches(path: dict | None, out: Path) -> tuple[list[Stretch], list[Stretch]]:
    """The tests of the path that started, and the cleanups that ran, from the manifest's `path`."""

    steps, cleanups = [], []
    for record in (path or {}).get("steps") or []:
        if record.get("started_ns") is not None and record.get("ended_ns") is not None:
            steps.append(
                Stretch(
                    record["id"],
                    record["host"],
                    (record["to"],) if isinstance(record.get("to"), str) else tuple(record.get("to") or ()),
                    record["started_ns"] / 1e9,
                    record["ended_ns"] / 1e9,
                    argument_paths(record.get("args")),
                    network_peers(record),
                )
            )
        run = record.get("cleanup_run") or {}
        if run.get("started_ns") is not None and run.get("ended_ns") is not None:
            notes = out / "raw" / "steps" / record["id"] / "cleanup.txt"
            text = notes.read_text(encoding="utf-8", errors="replace") if notes.is_file() else ""
            cleanups.append(
                Stretch(
                    record["id"],
                    record["host"],
                    (),
                    run["started_ns"] / 1e9,
                    run["ended_ns"] / 1e9,
                    cleanup_paths(text, record.get("workdir") or "/"),
                )
            )
    return steps, cleanups


def _cleanup(event: dict, cleanups: list[Stretch]) -> bool:
    if _tag(event).startswith("cleanup:"):
        return True
    if event.get("location") != "syscheck" or not cleanups:
        return False
    moment = activity.event_time(event)
    path = (event.get("syscheck") or {}).get("path")
    host = (event.get("agent") or {}).get("name")
    return moment is not None and any(
        c.host == host and path in c.paths and c.holds(*moment) for c in cleanups
    )


def _accounts(event: dict, uses: set[tuple[str, str]]) -> bool:
    """True when the line names an account the path uses on the line's host."""

    host = (event.get("agent") or {}).get("name")
    mine = {account for where, account in uses if where == host}
    if not mine:
        return False
    data = event.get("data") or {}
    syscheck = event.get("syscheck") or {}
    named = {
        data.get("srcuser"),
        data.get("dstuser"),
        syscheck.get("uname_after"),
        syscheck.get("uname_before"),
    }
    if event.get("location") == activity.SNOOPY_LOG:
        named.add(data.get("login"))
    if mine & named:
        return True
    log = event.get("full_log") or ""
    return event.get("location") == activity.AUTH_LOG and any(
        activity.names(account).search(log) for account in mine
    )


def _names_a_path(event: dict, paths: tuple[str, ...]) -> bool:
    if not paths:
        return False
    if event.get("location") == "syscheck":
        path = str((event.get("syscheck") or {}).get("path") or "")
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths)
    log = event.get("full_log") or ""
    return any(re.search(rf"(?<![A-Za-z0-9._/-]){re.escape(p)}(?![A-Za-z0-9._-])", log) for p in paths)


def _names_a_source(event: dict, sources: list[str]) -> bool:
    """True when the line's text names one of a host's addresses or its container's name, as a whole word."""

    log = event.get("full_log") or ""
    return any(
        re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(source)}(?![A-Za-z0-9_-]|\.[0-9])", log)
        for source in sources
        if source
    )


def tie(
    event: dict,
    steps: list[Stretch],
    uses: set[tuple[str, str]],
    addresses: dict[str, list[str]],
    names: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """The step an event of no other origin belongs to, and how it is tied, by the first rule that holds.

    `address` holds for a line whose source address, as Wazuh decoded it, is
    the step's host's, and for a line on a host the step reached whose text
    names that host's address or container name (`names`, by host): many sshd
    and MariaDB lines carry the address only in their text.
    """

    tag = _tag(event)
    if tag.startswith("step:"):
        return tag.removeprefix("step:"), "session"
    moment = activity.event_time(event)
    if moment is None:
        return None, None
    when, whole = moment
    inside = [stretch for stretch in steps if stretch.holds(when, whole)]
    if not inside:
        return None, None
    host = (event.get("agent") or {}).get("name")
    source = str((event.get("data") or {}).get("srcip") or "")
    named = _accounts(event, uses)
    rules = (
        ("account", lambda s: named and s.on(host)),
        (
            "address",
            lambda s: (
                (bool(source) and source in addresses.get(s.host, []))
                or (
                    host in s.to
                    and _names_a_source(event, [*addresses.get(s.host, []), (names or {}).get(s.host, "")])
                )
            ),
        ),
        ("content", lambda s: s.on(host) and _names_a_path(event, s.paths)),
        ("window", lambda s: s.on(host)),
    )
    for name, holds in rules:
        found = [stretch for stretch in inside if holds(stretch)]
        if found:
            started = [stretch for stretch in found if stretch.started <= when]
            return (started[-1] if started else found[0]).step, name
    return None, None


def origins(
    events: list[dict],
    run_id: str,
    jobs: activity.Activity | None = None,
    addresses: dict[str, list[str]] | None = None,
    go: dict[str, float] | None = None,
    stop: dict[str, float] | None = None,
    cleanups: list[Stretch] | None = None,
) -> list[tuple[str, str | None]]:
    """The origin of each event, and the job's name for an ordinary one, in the order given.

    An event of none of these is `unattributed` here: `ties` gives it to a step if it can.
    """

    sorted_ = activity.attribute(jobs, events, addresses or {}, go or {}, stop or {}) if jobs and go else {}
    names = {job.name for job in jobs.jobs} if jobs else set()
    found: list[tuple[str, str | None]] = []
    for index, event in enumerate(events):
        tag = _tag(event)
        if _engine(event, run_id):
            found.append((ENGINE, None))
        elif _cleanup(event, cleanups or []):
            found.append((CLEANUP, None))
        elif index in sorted_:
            name, how = sorted_[index]
            # Cron's session line of a cron job's account does not tell one entry of the account from another.
            found.append((ORDINARY, None if how == activity.CRON_SESSION_SOURCE else name))
        elif tag.startswith("job:") and tag[4:] in names:
            found.append((ORDINARY, tag[4:]))
        else:
            found.append((UNATTRIBUTED, None))
    return found


def attributed(
    lines: list[dict],
    run_id: str,
    jobs: activity.Activity | None,
    addresses: dict[str, list[str]] | None,
    go: dict[str, float],
    stop: dict[str, float],
    steps: list[Stretch],
    cleanups: list[Stretch],
    uses: set[tuple[str, str]] | None,
    names: dict[str, str] | None = None,
) -> list[tuple[str, str | None, str | None, str | None]]:
    """Each line's origin, job, step and tie: `origins`, then `tie` for what is left."""

    found = []
    for line, (origin, job) in zip(
        lines, origins(lines, run_id, jobs, addresses, go, stop, cleanups), strict=True
    ):
        step = tied_by = None
        if origin == UNATTRIBUTED and steps:
            step, tied_by = tie(line, steps, uses or set(), addresses or {}, names)
            if tied_by in COUNTED:
                origin = STEP
        found.append((origin, job, step, tied_by))
    return found


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def capture_inputs(out: Path, capture: dict | None) -> tuple[dict[str, Path], list[dict]]:
    """The exact manifest-recorded, validated PCAP closure, grouped by capture host.

    The adapter scans the host folder, so the manifest's files must be exactly
    that folder's top-level classic PCAPs before the folder is passed to it.
    """

    hosts = (capture or {}).get("hosts") or {}
    if not isinstance(hosts, dict) or not hosts:
        raise suricata.SuricataError("the run recorded no packet-capture host")
    root = Path(out).resolve()
    found: dict[str, Path] = {}
    records: list[dict] = []
    for host in sorted(hosts):
        entry = hosts[host]
        if not isinstance(entry, dict):
            raise suricata.SuricataError(f"packet capture on {host} has no manifest record")
        folder = out / "raw" / "hosts" / host / packets.CAPTURE_DIR
        actual = suricata.capture_files(folder)
        declared = entry.get("files") or {}
        if not isinstance(declared, dict) or not declared:
            raise suricata.SuricataError(f"packet capture on {host} records no PCAP file")
        expected: dict[Path, dict] = {}
        for name, record in declared.items():
            if not isinstance(record, dict) or not isinstance(record.get("file"), str):
                raise suricata.SuricataError(f"packet capture on {host}: {name} has no recorded file")
            relative = Path(record["file"])
            if relative.is_absolute() or ".." in relative.parts:
                raise suricata.SuricataError(
                    f"packet capture on {host}: {record['file']} is not inside the run folder"
                )
            path = out / relative
            try:
                resolved = path.resolve(strict=True)
            except OSError as error:
                raise suricata.SuricataError(
                    f"packet capture on {host}: {record['file']} is not a retained file"
                ) from error
            if (
                path.is_symlink()
                or not resolved.is_relative_to(root)
                or resolved.parent != folder.resolve()
                or resolved.suffix != ".pcap"
                or not resolved.is_file()
            ):
                raise suricata.SuricataError(
                    f"packet capture on {host}: {record['file']} is not a regular top-level PCAP"
                )
            if resolved in expected:
                raise suricata.SuricataError(
                    f"packet capture on {host} records {record['file']} more than once"
                )
            if isinstance(record.get("bytes"), int) and record["bytes"] != resolved.stat().st_size:
                raise suricata.SuricataError(f"packet capture on {host}: {record['file']} has changed size")
            digest = record.get("sha256")
            if digest is not None and (not isinstance(digest, str) or _sha256(resolved) != digest):
                raise suricata.SuricataError(
                    f"packet capture on {host}: {record['file']} does not have its recorded SHA-256"
                )
            expected[resolved] = record
            records.append(
                {
                    "host": host,
                    "interface": resolved.stem,
                    "file": resolved.relative_to(root).as_posix(),
                    "integrity": "sha256" if digest is not None else "retained closure",
                    **({"sha256": digest} if digest is not None else {}),
                }
            )
        actual_set = {path.resolve() for path in actual}
        if actual_set != set(expected):
            missing = sorted(path.name for path in set(expected) - actual_set)
            extra = sorted(path.name for path in actual_set - set(expected))
            details = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if extra:
                details.append("unrecorded " + ", ".join(extra))
            raise suricata.SuricataError(
                f"packet capture on {host} is not the manifest's exact PCAP set: {'; '.join(details)}"
            )
        found[host] = folder
    return found, records


def protected_addresses(
    addresses: dict[str, list[str]] | None, agents: list[str] | None, capture_hosts: list[str]
) -> list[str]:
    """Exact recorded addresses of agent and capture hosts, for Suricata HOME_NET."""

    values = {
        str(ipaddress.ip_address(address))
        for host in {*list(agents or []), *capture_hosts}
        for address in (addresses or {}).get(host, [])
    }
    if not values:
        raise suricata.SuricataError("the run records no protected address for Suricata HOME_NET")
    return sorted(
        values, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value))
    )


def packet_home_net(
    capture: dict,
    addresses: dict[str, list[str]] | None,
    agents: list[str] | None,
    capture_hosts: list[str],
) -> tuple[list[str], str]:
    """The immutable protected IP list retained with the capture, with old-run compatibility."""

    expected_hosts = sorted({*list(agents or ()), *capture_hosts})
    recorded_hosts = capture.get("home_hosts")
    if recorded_hosts is not None:
        if (
            not isinstance(recorded_hosts, list)
            or not all(isinstance(host, str) and host for host in recorded_hosts)
            or recorded_hosts != sorted(set(recorded_hosts))
        ):
            raise suricata.SuricataError("packet_capture.home_hosts is not a sorted unique host list")
        if agents is not None and recorded_hosts != expected_hosts:
            raise suricata.SuricataError(
                "packet_capture.home_hosts is not the recorded agent and capture host set"
            )
        expected_hosts = recorded_hosts
    expected = (
        protected_addresses(addresses, expected_hosts, [])
        if addresses and any(addresses.get(host) for host in expected_hosts)
        else []
    )
    retained = capture.get("home_net")
    if retained is None:
        if not expected:
            raise suricata.SuricataError(
                "the run records neither packet_capture.home_net nor protected host addresses"
            )
        return expected, "recorded addresses compatibility fallback"
    if not isinstance(retained, list) or not retained:
        raise suricata.SuricataError("packet_capture.home_net is not a non-empty IP list")
    try:
        home_net = [str(ipaddress.ip_address(value)) for value in retained if isinstance(value, str)]
    except ValueError as error:
        raise suricata.SuricataError("packet_capture.home_net contains an invalid IP address") from error
    if len(home_net) != len(retained):
        raise suricata.SuricataError("packet_capture.home_net contains a value that is not an IP string")
    ordered = sorted(
        set(home_net), key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value))
    )
    if home_net != ordered:
        raise suricata.SuricataError("packet_capture.home_net is not the exact sorted unique IP list")
    if expected and home_net != expected:
        raise suricata.SuricataError(
            "packet_capture.home_net is not the exact address set of its protected recorded hosts"
        )
    return home_net, "manifest packet_capture.home_net"


def _network_interval(document: dict) -> tuple[float, float]:
    event = document.get("event") or {}
    start = _eve_time(event.get("start") or document.get("@timestamp"), "event.start").timestamp()
    end = _eve_time(event.get("end") or document.get("@timestamp"), "event.end").timestamp()
    if end < start:
        raise ValueError("a network event ends before it starts")
    return start, end


def _connects(document: dict, first: list[str], second: list[str]) -> bool:
    source = str((document.get("source") or {}).get("ip") or "")
    destination = str((document.get("destination") or {}).get("ip") or "")
    return (source in first and destination in second) or (source in second and destination in first)


def _step_addresses(document: dict, stretch: Stretch, addresses: dict[str, list[str]]) -> bool:
    mine = addresses.get(stretch.host, [])
    peers = tuple(dict.fromkeys((*stretch.to, *stretch.peers)))
    if not mine or not peers:
        return False
    peer_addresses = [address for host in peers for address in addresses.get(host, [])]
    return bool(peer_addresses) and _connects(document, mine, peer_addresses)


def _target_port(document: dict, addresses: list[str]) -> int | None:
    if (document.get("destination") or {}).get("ip") in addresses:
        return (document.get("destination") or {}).get("port")
    if (document.get("source") or {}).get("ip") in addresses:
        return (document.get("source") or {}).get("port")
    return None


def _ordinary_network_candidates(
    document: dict,
    jobs: activity.Activity | None,
    addresses: dict[str, list[str]],
    go: dict[str, float],
    stop: dict[str, float],
    started: float,
    ended: float,
    protected: set[str],
) -> set[str]:
    """Ordinary jobs supported by endpoint, service and activity-window evidence."""

    found: set[str] = set()
    protocol = str((document.get("network") or {}).get("protocol") or "").lower()
    transport = str((document.get("network") or {}).get("transport") or "").lower()
    path = str((document.get("url") or {}).get("path") or "")
    source = document.get("source") or {}
    destination = document.get("destination") or {}
    for job in jobs.jobs if jobs else ():
        if job.target is None:
            continue
        low, high = go.get(job.host), stop.get(job.host, math.inf)
        if low is None or not low <= started <= ended <= high + activity.GRACE:
            continue
        own = addresses.get(job.host, [])
        target = addresses.get(job.target, [])
        if _connects(document, own, target):
            wanted = 80 if job.do == "http" else 22 if job.do == "ssh" else None
            if wanted is None or _target_port(document, target) != wanted:
                continue
            if job.do == "http" and protocol not in ("", "http"):
                continue
            if job.do == "ssh" and protocol not in ("", "ssh"):
                continue
            if job.do == "http" and path and job.paths and path not in job.paths:
                continue
            found.add(job.name)
        # A customer's HTTP request can make the web target query a protected MariaDB host.
        # It is still ordinary work, unless the same endpoint/time evidence also supports a path step.
        if (
            job.do == "http"
            and source.get("ip") in target
            and destination.get("ip") in protected
            and destination.get("ip") not in target
            and destination.get("port") == 3306
            and transport in ("", "tcp")
            and protocol in ("", "mysql", "mariadb")
        ):
            found.add(job.name)
    return found


def name_network_endpoints(document: dict, addresses: dict[str, list[str]]) -> None:
    """Add an unambiguous recorded range-host name beside each exact endpoint IP."""

    owners: dict[str, set[str]] = {}
    for host, values in addresses.items():
        for address in values:
            owners.setdefault(address, set()).add(host)
    for side in ("source", "destination"):
        endpoint = document.get(side)
        if not isinstance(endpoint, dict):
            continue
        names = owners.get(str(endpoint.get("ip") or ""), set())
        if len(names) == 1:
            endpoint.setdefault("domain", next(iter(names)))


def _engine_network(document: dict, marks: list[dict]) -> bool:
    source = str((document.get("source") or {}).get("ip") or "")
    destination = str((document.get("destination") or {}).get("ip") or "")
    destination_port = (document.get("destination") or {}).get("port")
    transport = str((document.get("network") or {}).get("transport") or "").lower()
    observer = document.get("observer") or {}
    interface = ((observer.get("ingress") or {}).get("interface") or {}).get("name")
    return any(
        mark.get("seen") is True
        and transport == "udp"
        and observer.get("name") == mark.get("capture host")
        and interface == mark.get("interface")
        and source == mark.get("source")
        and destination == mark.get("destination")
        and destination_port == mark.get("port")
        for mark in marks
    )


def network_attributed(
    documents: list[dict],
    jobs: activity.Activity | None,
    addresses: dict[str, list[str]],
    go: dict[str, float],
    stop: dict[str, float],
    steps: list[Stretch],
    capture: dict | None = None,
    home_net: list[str] | None = None,
) -> list[tuple[str, str | None, str | None, str | None]]:
    """Attribute canonical network events from exact endpoint and event-time evidence."""

    marks = [
        {**mark, "capture host": host}
        for host, entry in ((capture or {}).get("hosts") or {}).items()
        if isinstance(entry, dict)
        for mark in entry.get("ready") or []
        if isinstance(mark, dict)
    ]
    protected = set(home_net or (capture or {}).get("home_net") or ())
    found = []
    for document in documents:
        started, ended = _network_interval(document)
        origin, job_name, step_id, tied_by = UNATTRIBUTED, None, None, None
        if _engine_network(document, marks):
            origin = ENGINE
        else:
            ordinary = _ordinary_network_candidates(
                document, jobs, addresses, go, stop, started, ended, protected
            )
            counted = [
                stretch
                for stretch in steps
                if _step_addresses(document, stretch, addresses)
                and stretch.holds(started, False)
                and stretch.holds(ended, False)
            ]
            overlap = [
                stretch
                for stretch in steps
                if _step_addresses(document, stretch, addresses)
                and started <= stretch.ended + GRACE
                and ended >= stretch.started
            ]
            if ordinary and not counted and not overlap:
                origin = ORDINARY
                job_name = next(iter(ordinary)) if len(ordinary) == 1 else None
            elif len(counted) == 1 and not ordinary:
                origin, step_id, tied_by = STEP, counted[0].step, "address"
            else:
                # Ordinary/step overlap, multiple counted steps, and interval-only overlap are all
                # coincidences, never a precedence choice. Name a window only when it is unambiguous.
                if len(overlap) == 1:
                    step_id, tied_by = overlap[0].step, "window"
        labels = document.setdefault("labels", {})
        for name in ("job", "step_id", "tied_by"):
            labels.pop(name, None)
        labels["origin"] = origin
        if job_name:
            labels["job"] = job_name
        if step_id:
            labels["step_id"] = step_id
        if tied_by:
            labels["tied_by"] = tied_by
        found.append((origin, job_name, step_id, tied_by))
    return found


def _key(line: dict) -> tuple:
    return (
        (line.get("agent") or {}).get("name"),
        line.get("location"),
        line.get("full_log"),
        line.get("timestamp"),
    )


def matched_events(alerts: list[dict], events: list[dict]) -> list[int | None]:
    """For each alert, the place in `events` of its archived event, or None when the archive has none."""

    index: dict[tuple, int] = {}
    for number, event in enumerate(events):
        index.setdefault(_key(event), number)
    return [index.get(_key(alert)) for alert in alerts]


def alert_origins(alerts: list[dict], events: list[dict], found: list, fallback: list) -> tuple[list, int]:
    """Each alert's origin: its archived event's, else its own (`fallback`); and how many had an event."""

    places = matched_events(alerts, events)
    result = [own if place is None else found[place] for place, own in zip(places, fallback, strict=True)]
    return result, sum(place is not None for place in places)


def band(level: int) -> str:
    for low, high, name in BANDS:
        if low <= level <= high:
            return name
    return "other"


def _rules(alerts: list[dict], picked: list[tuple[str, str | None]], low: int, high: float) -> list[dict]:
    """The distinct rules among the alerts with a level in [low, high], each with its count and jobs or origins."""

    rules: dict[str, dict] = {}
    for alert, (origin, job) in zip(alerts, picked, strict=True):
        rule = alert.get("rule") or {}
        level = rule.get("level")
        if not isinstance(level, int) or not low <= level <= high:
            continue
        entry = rules.setdefault(
            str(rule.get("id")),
            {
                "rule": str(rule.get("id")),
                "description": rule.get("description"),
                "level": level,
                "alerts": 0,
            },
        )
        entry["alerts"] += 1
        where = entry.setdefault("on", {})
        name = (job or "no job named") if origin == ORDINARY else origin
        host = (alert.get("agent") or {}).get("name")
        label = f"{name} ({host})"
        where[label] = where.get(label, 0) + 1
    return sorted(rules.values(), key=lambda entry: (-entry["level"], entry["rule"]))


def not_exercised(jobs: activity.Activity | None) -> list[str]:
    """What the jobs do, which is all the score prices, and examples of what they leave out."""

    if not jobs:
        return ["the range has no ordinary activity, so no false alert can be counted"]
    done = []
    for job in jobs.jobs:
        if job.do == "http":
            done.append(
                f"{job.name}: GET requests for {', '.join(job.paths)} on {job.target}, from {job.host}"
            )
        elif job.do == "ssh":
            done.append(
                f"{job.name}: a key login of {job.target_account}@{job.target} from {job.host}, "
                f"which runs: {job.run}"
            )
        else:
            done.append(f"{job.name}: cron on {job.host}, as {job.account}, runs: {job.run}")
    return done + [
        "nothing else is exercised, for example a password login or a failed login over SSH, a request "
        "other than a GET, or any work none of the commands above does: an alert a rule raises only on "
        "such work is not priced by this score",
        "Wazuh's stateful rules (a first time, a frequency, a rule that follows another) have already "
        "seen the plant checks' logins and sudo before the go, so a rule that fires only on a first "
        "occurrence may not fire on the jobs",
    ]


def ordinary_day(
    alerts: list[dict],
    picked: list[tuple[str, str | None]],
    event_counts: dict[str, int],
    alert_level: int,
    jobs: activity.Activity | None,
    record: dict | None,
) -> dict:
    """The score of the ordinary day, with its denominators."""

    record = record or {}
    by_band = {origin: Counter() for origin in ORIGINS}
    for alert, (origin, _) in zip(alerts, picked, strict=True):
        level = (alert.get("rule") or {}).get("level")
        by_band[origin][band(level) if isinstance(level, int) else "no level"] += 1
    ordinary = [(a, p) for a, p in zip(alerts, picked, strict=True) if p[0] == ORDINARY]
    others = [(a, p) for a, p in zip(alerts, picked, strict=True) if p[0] not in (ORDINARY, STEP)]
    false_alerts = _rules([a for a, _ in ordinary], [p for _, p in ordinary], alert_level, float("inf"))
    review = _rules([a for a, _ in ordinary], [p for _, p in ordinary], REVIEW_FROM, alert_level - 1)
    elsewhere = _rules([a for a, _ in others], [p for _, p in others], alert_level, float("inf"))
    counted = record.get("jobs") or {}
    runs = {
        job.name: {
            "runs": (counted.get(job.name) or {}).get("runs"),
            "archived runs": (counted.get(job.name) or {}).get("archived runs"),
        }
        for job in (jobs.jobs if jobs else [])
    }
    missing = [
        f"{name} (runs {n['runs']}, archived runs {n['archived runs']})"
        for name, n in runs.items()
        if not (n["runs"] or 0) >= 1 or not (n["archived runs"] or 0) >= 1
    ]
    if not jobs:
        reason = not_exercised(jobs)[0]
    elif record.get("minutes") is None:
        reason = "the minutes of activity were not counted, so no number of false alerts is a result"
    elif missing:
        reason = (
            "a job had no run that reached the defense, so no number of false alerts is a result: "
            + ", ".join(missing)
        )
    else:
        reason = None
    return {
        "alert_level": alert_level,
        "for_review_from": REVIEW_FROM,
        "scored": reason is None,
        "not scored": reason,
        "denominators": {
            "minutes of activity": record.get("minutes"),
            "activity started": record.get("started"),
            "runs of each job": runs,
            "events of each origin": event_counts,
        },
        "alerts by origin and level": {origin: dict(sorted(c.items())) for origin, c in by_band.items()},
        "false alerts": len(false_alerts),
        "false alert rules": false_alerts,
        "for review": len(review),
        "for review rules": review,
        "alerts at the alert level on the engine's work and unattributed events": elsewhere,
        "what the jobs exercise": not_exercised(jobs),
    }


def _when(line: dict) -> datetime:
    return ecs.chosen_time(line)[0]


def raised_at(alert: dict) -> datetime:
    """When an alert existed: the manager's time of it, or the time on its line when that is later.

    The manager's time of a line can be seconds earlier than the time rsyslog
    wrote on the line in its container (`clock` measures by how much), and an
    alert is never raised before the line it was raised on was written.
    """

    return max(ecs.manager_time(alert), ecs.chosen_time(alert)[0])


def seconds_between(start: str, end: str) -> float:
    """From one ISO time of the run to another, in seconds, to the millisecond."""

    first, second = (datetime.fromisoformat(text.replace("Z", "+00:00")) for text in (start, end))
    return round((second - first).total_seconds(), 3)


def visibility(started: bool, events: int, alerted: bool) -> str:
    """What the defense made of a step, by the counted ties alone."""

    if not started:
        return "not applicable"
    if alerted:
        return "alert"
    return "telemetry only" if events else "no telemetry"


def race(steps: list[dict], goal: dict | None, agree: bool = True) -> dict:
    """The time to the first alert on a step, against the time to the goal, both from the first step's start.

    A step's times count only on the Docker daemon's clock (`time_source`
    `daemon`). `result` is false, and `says` begins "not a result", when the
    clock check (`agree`) did not pass.
    """

    start = steps[0].get("started") if steps else None
    if steps and steps[0].get("time_source") not in (None, "daemon"):
        return {
            "start": None,
            "result": False,
            "says": f"no race: {steps[0]['id']} has no times on the Docker daemon's clock",
        }
    if start is None:
        return {"start": None, "result": False, "says": "no race: the first step did not start"}
    alerted = [(s["first_alert"]["raised"], s) for s in steps if s.get("first_alert")]
    first = min(alerted, key=lambda pair: pair[0]) if alerted else None
    found: dict = {"start": start, "started by": steps[0]["id"], "result": agree}
    if first:
        found["first_alert_seconds"] = max(0.0, seconds_between(start, first[0]))
        found["first_alert"] = {"step": first[1]["id"], **first[1]["first_alert"]}
    after = next((s for s in steps if goal and s["id"] == goal.get("after")), None)
    end = after.get("ended") if after else None
    daemon = bool(after) and after.get("time_source") == "daemon"
    if goal and goal.get("passed") and end and daemon:
        found["goal_seconds"] = seconds_between(start, end)
        found["goal"] = goal.get("plain")
    alert, reached = found.get("first_alert_seconds"), found.get("goal_seconds")
    unreached = (
        f"the goal's step {after['id']} has no times on the Docker daemon's clock"
        if goal and goal.get("passed") and after and after.get("time_source") not in (None, "daemon")
        else "the goal was not reached"
    )
    if reached is None:
        found["not reached"] = unreached
    if alert is None:
        found["says"] = "no alert" + ("" if reached is not None else f"; {unreached}")
    elif reached is None:
        found["says"] = f"first alert after {alert} s; {unreached}"
    elif alert < reached:
        found["says"] = f"alert before goal by {round(reached - alert, 3)} s"
    elif alert > reached:
        found["says"] = f"alert after goal by {round(alert - reached, 3)} s"
    else:
        found["says"] = "alert at the goal"
    if not agree:
        found["says"] = f"not a result, the clocks are not shown to agree: {found['says']}"
    return found


def path_outcome(race_: dict) -> str:
    """Whether the path reached its goal, and after how long, in one sentence: it is the same for every defense."""

    if race_.get("start") is None:
        return race_["says"]
    if "goal_seconds" in race_:
        said = f"the path reached its goal {race_['goal_seconds']} s after its first step started"
    else:
        said = f"the path did not reach its goal ({race_.get('not reached') or 'the goal was not reached'})"
    return said if race_.get("result") else f"not a result, the clocks are not shown to agree: {said}"


def clock(steps: list[Stretch], events: list[dict], found: list[tuple], records: list[dict]) -> dict:
    """Whether the steps' clock and the containers' agree: each program start snoopy logged in a step's session,
    at rsyslog's time in its container, against the Docker daemon's start and end of the step's test.

    A step that started with the engine's clock for its times (the daemon's
    exec events were not matched, or its end came before its start) makes the
    check fail.
    """

    engine_timed = [
        record["id"]
        for record in records
        if record.get("started") is not None and ecs.step_clock(record) != "daemon"
    ]
    windows = {stretch.step: stretch for stretch in steps}
    before, after, outside, counted = 0.0, 0.0, 0, 0
    lags = []
    for event, (_, _, step, tied_by) in zip(events, found, strict=True):
        moment, source = ecs.chosen_time(event)
        if source != "rsyslog":
            continue
        lags.append((ecs.manager_time(event) - moment).total_seconds())
        if tied_by != "session" or step not in windows:
            continue
        counted += 1
        when, stretch = moment.timestamp(), windows[step]
        early, late = stretch.started - when, when - stretch.ended
        before, after = max(before, early), max(after, late)
        outside += early > 0 or late > 0
    return {
        "steps": "the Docker daemon's times of each test's exec_start and exec_die",
        "alerts": "the manager's time of each alert, or the time on the line it was raised on when that is "
        "later",
        "events": "rsyslog's time in the agent host's container, else the time the program wrote, else the "
        "manager's",
        "engine": "the engine's own clock is not used for any of these",
        "program starts checked": counted,
        "outside their step": outside,
        "most seconds before a step's start": round(before, 6),
        "most seconds after a step's end": round(after, 6),
        "steps on the engine's clock": engine_timed,
        "agree": counted > 0 and outside == 0 and not engine_timed,
        "manager's time against the line's": {
            "lines": len(lags),
            "earlier than the line": sum(1 for lag in lags if lag < 0),
            "least seconds": round(min(lags), 3) if lags else None,
            "most seconds": round(max(lags), 3) if lags else None,
            "note": "the manager's time of an archived line minus rsyslog's time on it in its container; a "
            "line cannot reach the manager before it is written, so a negative value is the manager's time "
            "running behind, and an alert's time is never put before its line's",
        },
    }


def path_score(
    path: dict,
    steps: list[Stretch],
    events: list[dict],
    found: list[tuple],
    alerts: list[dict],
    picked: list[tuple],
    alert_level: int,
) -> dict:
    """What the defense made of each step of the path, the race, and how the run's clocks agree."""

    scored = []
    started = {stretch.step for stretch in steps}
    for record in path["steps"]:
        step_id = record["id"]
        mine = [
            (event, tied_by)
            for event, (_, _, step, tied_by) in zip(events, found, strict=True)
            if step == step_id
        ]
        counted = [event for event, tied_by in mine if tied_by in COUNTED]
        ties = Counter(tied_by for _, tied_by in mine if tied_by in COUNTED)
        on_step = [
            alert
            for alert, (_, _, step, tied_by) in zip(alerts, picked, strict=True)
            if step == step_id and tied_by in COUNTED
        ]
        rules: dict[str, dict] = {}
        for alert in on_step:
            rule = alert.get("rule") or {}
            raised = ecs.iso(raised_at(alert))
            entry = rules.setdefault(
                str(rule.get("id")),
                {
                    "rule": str(rule.get("id")),
                    "description": rule.get("description"),
                    "level": rule.get("level"),
                    "alerts": 0,
                    "first raised": raised,
                },
            )
            entry["alerts"] += 1
            entry["first raised"] = min(entry["first raised"], raised)
        counting = [r for r in rules.values() if isinstance(r["level"], int) and r["level"] >= alert_level]
        first = min(counting, key=lambda r: r["first raised"]) if counting else None
        seen = visibility(step_id in started, len(counted), bool(counting))
        happened = record.get("happened")
        expected = [str(rule) for rule in record.get("expect") or []]
        source = ecs.step_clock(record)
        told = source != ecs.END_BEFORE_START
        entry = {
            "id": step_id,
            "host": record.get("host"),
            "to": record.get("to") or [],
            "started": record.get("started") if told else None,
            "ended": record.get("ended") if told else None,
            "time_source": source,
            "happened": happened,
            "why": record.get("why"),
            "visibility": seen,
            "outcome": score_word(happened, seen),
            "events": len(counted),
            "events by tie": dict(ties),
            # What "seen" rests on, when it rests on the address rule alone: the lines themselves.
            "lines tied by address alone": [_line(event) for event in counted[:SHOWN_LINES]]
            if set(ties) == {"address"}
            else [],
            "coincident events": sum(1 for _, tied_by in mine if tied_by == "window"),
            "agents": dict(Counter((e.get("agent") or {}).get("name") for e in counted)),
            "first_event": ecs.iso(min(_when(e) for e in counted)) if counted else None,
            "alerts": len(on_step),
            "rules": sorted(rules.values(), key=lambda r: (-(r["level"] or 0), r["rule"])),
            "first_alert": {
                "raised": first["first raised"],
                "rule": first["rule"],
                "description": first["description"],
                "level": first["level"],
            }
            if first
            else None,
            "expected rules": expected,
            "expected rules that did not appear": [rule for rule in expected if rule not in rules],
        }
        scored.append(entry)
    words = Counter(step["outcome"] for step in scored)
    checked = clock(steps, events, found, path["steps"])
    return {
        "alert_level": alert_level,
        "steps": scored,
        "outcomes": {
            word: words[word] for word in ("alerted", "seen", "unseen", "no effect", "inconclusive")
        },
        "race": race(scored, path.get("goal"), checked["agree"]),
        "clock": checked,
        "events": {
            "of each origin": {o: sum(1 for f in found if f[0] == o) for o in ORIGINS},
            "unattributed, coincident with a step": sum(1 for f in found if f[0] == UNATTRIBUTED and f[2]),
        },
        "alerts": {
            "of each origin": {o: sum(1 for p in picked if p[0] == o) for o in ORIGINS},
            "unattributed at the alert level": sum(
                1
                for alert, p in zip(alerts, picked, strict=True)
                if p[0] == UNATTRIBUTED and ((alert.get("rule") or {}).get("level") or 0) >= alert_level
            ),
        },
        "notes": [
            "Events are tied to a step by snoopy's tag of its session, the accounts only the path uses, the "
            "address or container name of the host it ran on and the paths it was given, inside its time span, "
            f"from its start to {GRACE} s after its end; an event that only falls inside that time span is "
            "coincident and never counts.",
            "This top-level Wazuh detail uses no network sensor, so scans and exfiltrations are seen here "
            "only through what they leave in the logs and files the agents watch.",
            "Snoopy misses the first program of each docker exec, the published sh -c itself, which is the "
            "step's command.",
            "The defense is the stock Wazuh rules with the lab's agent configuration (its diff is in the "
            "manifest). One run is one sample: variation between runs is not yet shown.",
        ],
    }


def live_matches(alerts: list[dict], picked: list[tuple], places: list, alert_level: int) -> list[dict]:
    """The manager's alerts as the judging of a defense reads them: each a match of a rule that ran live,
    which counts from the moment it was raised, at the alert level or higher."""

    found = []
    for alert, (origin, job, step, tied_by), place in zip(alerts, picked, places, strict=True):
        rule = alert.get("rule") or {}
        level = rule.get("level")
        found.append(
            {
                "detector": PINNED,
                "rule": str(rule.get("id")),
                "title": rule.get("description"),
                "level": level,
                "counts": isinstance(level, int) and not isinstance(level, bool) and level >= alert_level,
                "moment": ecs.iso(raised_at(alert)),
                "host": (alert.get("agent") or {}).get("name"),
                "sensor": sensor_id(WAZUH_AGENT, str((alert.get("agent") or {}).get("name"))),
                "event": place,
                "event_id": f"archive-{place + 1}" if isinstance(place, int) else None,
                "origin": origin,
                "job": job,
                "step": step,
                "tied_by": tied_by,
            }
        )
    return found


def after_the_run(
    out: Path,
    rule_set: RuleSet,
    engine: Path | None,
    lock: dict[str, str] | None,
    events: list[dict],
    ties: list[tuple],
    ids: list[str],
) -> tuple[dict, list[dict] | None]:
    """Give the run's archived events to a rule set from the run's own folder, and write its matches as ECS lines.

    Returns what the score records of the set and its matches, each tied as
    its event is and at its event's time. Without a rule engine, or when a
    rule file of the run's folder is missing or is not the file the lock
    names, or when the engine fails, there are no matches (None) and the
    record says why: the set was not evaluated, which is not the same as a set
    that matched nothing.
    """

    name = MATCHES_FILE.format(rule_set.name)
    found: dict = {
        "kind": rule_set.kind,
        "source": rulesets.source(rule_set),
        "source type": "tracked" if rulesets.local(rule_set) else "repository",
        "when": AFTER,
        "evaluated": False,
    }
    if rule_set.repository_authored is not None:
        found["repository authored"] = rule_set.repository_authored
    try:
        if engine is None:
            raise SpecError("no rule engine was given (--engine <path to Zircolite>)")
        if lock is None:
            raise SpecError(
                f"the run did not fetch the rule set: its folder has no {rulesets.FOLDER}/{rule_set.name} "
                "checked against a lock"
            )
        folder = rulesets.held(out, rule_set.name, lock)
        folders = list(rule_set.folders) if rule_set.folders else ["."]
        made = sigma.evaluate_set(
            engine,
            folder,
            folders,
            events,
            out / "engine" / rule_set.name,
            rule_set.pipelines,
        )
    except (SpecError, sigma.EngineError, OSError) as error:
        (out / name).unlink(missing_ok=True)
        found["not evaluated"] = str(error)
        return found, None
    matches, documents = [], []
    for match in made.pop("matches"):
        index, rule = match["event"], match["rule"]
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(events):
            raise sigma.EngineError(
                f"the rule engine returned a terminal event outside the {len(events)} archived events"
            )
        raw_evidence = match.get("evidence")
        if raw_evidence is None:
            raw_evidence = [index]
        if (
            not isinstance(raw_evidence, list)
            or not raw_evidence
            or any(
                not isinstance(place, int) or isinstance(place, bool) or not 0 <= place < len(events)
                for place in raw_evidence
            )
        ):
            raise sigma.EngineError(
                f"the rule engine returned evidence outside the {len(events)} archived events"
            )
        evidence = list(dict.fromkeys(raw_evidence))
        evidence = [place for place in evidence if place != index] + [index]
        origin, job, step, tied_by = ties[index]
        evidence_event_ids = [ids[place] for place in evidence]
        if rulesets.local(rule_set):
            relative = posixpath.join(posixpath.dirname(rule_set.source_file), rule["file"])
            reference = f"{PUBLIC_RULE_REPOSITORY}/{relative}"
        else:
            reference = f"https://github.com/{rule_set.repo}/blob/{rule_set.commit}/{rule['file']}"
        documents.append(
            ecs.match(
                events[index],
                {**rule, "reference": reference},
                rule_set.name,
                origin,
                job,
                step,
                tied_by,
                ids[index],
                evidence_event_ids,
            )
        )
        matches.append(
            {
                "detector": detector_id(rule_set.name),
                "rule": rule["id"],
                "title": rule["title"],
                "level": rule["level"],
                "counts": rule["level"] in sigma.ALERT_LEVELS,
                "author": rule["author"],
                # The rules ran after the run: a match counts from the time of its event.
                "moment": ecs.iso(_when(events[index])),
                "host": (events[index].get("agent") or {}).get("name"),
                "sensor": sensor_id(WAZUH_AGENT, str((events[index].get("agent") or {}).get("name"))),
                "event": index,
                "event_id": ids[index],
                "origin": origin,
                "job": job,
                "step": step,
                "tied_by": tied_by,
                "evidence": evidence,
                "evidence event ids": evidence_event_ids,
            }
        )
    found.update(made)
    found.update(
        evaluated=True,
        digest=rulesets.digest(rule_set, lock),
        file=name,
        lines=ecs.write(out / name, documents),
    )
    found["rules that matched"] = matched_rules(matches)
    return found, matches


def _frozen(value: object) -> object:
    if isinstance(value, list | tuple):
        return tuple(_frozen(item) for item in value)
    if isinstance(value, dict):
        return tuple((key, _frozen(value[key])) for key in sorted(value))
    return value


def _network_event_document(
    raw: dict,
    host: str,
    event_id: str,
    engine: dict,
    addresses: dict[str, list[str]],
) -> dict:
    interface = _capture_interface(raw)
    document = ecs.network_event(
        raw,
        host,
        interface,
        event_id,
        UNATTRIBUTED,
        engine=engine,
    )
    name_network_endpoints(document, addresses)
    return document


def _network_alert_document(raw: dict, parent: dict, rule_set: RuleSet, engine: dict) -> dict:
    return ecs.network_alert(raw, parent, rule_set.name, engine=engine)


def network_telemetry(
    out: Path,
    image: str,
    capture: dict,
    addresses: dict[str, list[str]],
    agents: list[str] | None,
    jobs: activity.Activity | None,
    go: dict[str, float],
    stop: dict[str, float],
    steps: list[Stretch],
) -> tuple[dict, list[dict], list[tuple], dict[tuple, int], dict[str, Path], list[str]]:
    """Run the rule-independent packet decoder and write one canonical network event stream."""

    folders, retained = capture_inputs(out, capture)
    home_net, home_net_source = packet_home_net(capture, addresses, agents, list(folders))
    raw: list[tuple[str, dict, dict, suricata.EventKey]] = []
    runs = []
    expected_engine = None
    for host, folder in folders.items():
        made = suricata.telemetry(
            image,
            folder,
            home_net,
            out / "engine" / "suricata" / "network" / host,
        )
        records = made.get("records")
        alerts = made.get("alerts")
        if not isinstance(records, list) or not isinstance(alerts, list):
            raise suricata.SuricataError(f"Suricata telemetry on {host} returned no record lists")
        if alerts:
            raise suricata.SuricataError(
                f"the detection-disabled Suricata telemetry pass on {host} returned an alert"
            )
        engine = made.get("engine")
        if not isinstance(engine, dict):
            raise suricata.SuricataError(f"Suricata telemetry on {host} returned no engine identity")
        if expected_engine is not None and engine != expected_engine:
            raise suricata.SuricataError("the canonical packet captures were decoded by different engines")
        expected_engine = engine
        keys = tuple(suricata.record_index(records))
        raw += [(host, record, engine, key) for record, key in zip(records, keys, strict=True)]
        runs.append(
            {
                "host": host,
                **{
                    key: value
                    for key, value in made.items()
                    if key not in ("records", "alerts", "alert event keys")
                },
            }
        )
    raw.sort(
        key=lambda item: (
            item[0],
            _capture_interface(item[1]),
            json.dumps(_frozen(item[3]), default=str),
        )
    )
    documents = []
    places: dict[tuple, int] = {}
    ordinals: Counter = Counter()
    for host, record, engine, event_key in raw:
        interface = _capture_interface(record)
        ordinals[(host, interface)] += 1
        event_id = f"network-{host}-{interface}-{ordinals[(host, interface)]:06d}"
        key = (host, _frozen(event_key))
        if key in places:
            raise suricata.SuricataError(
                f"canonical Suricata telemetry on {host} has the same stable event key twice"
            )
        places[key] = len(documents)
        documents.append(_network_event_document(record, host, event_id, engine, addresses))
    if not documents:
        raise suricata.SuricataError("Suricata produced no canonical network event")
    ties = network_attributed(documents, jobs, addresses, go, stop, steps, capture, home_net)
    network_file = out / NETWORK_EVENTS_FILE
    count = ecs.write(network_file, documents)
    if count != len(documents):
        raise suricata.SuricataError(
            f"{NETWORK_EVENTS_FILE} has {count} lines for {len(documents)} canonical network events"
        )
    section = {
        "evaluated": True,
        "engine": expected_engine,
        "home_net": home_net,
        "home_net source": home_net_source,
        "file": NETWORK_EVENTS_FILE,
        "lines": count,
        "bytes": network_file.stat().st_size,
        "sha256": _sha256(network_file),
        "captures": retained,
        "runs": runs,
    }
    return section, documents, ties, places, folders, home_net


def after_suricata(
    out: Path,
    rule_set: RuleSet,
    image: str | None,
    lock: dict[str, str] | None,
    folders: dict[str, Path],
    home_net: list[str],
    documents: list[dict],
    ties: list[tuple],
    places: dict[tuple, int],
    unavailable: str | None = None,
) -> tuple[dict, list[dict] | None]:
    """Evaluate one Suricata rule set and link each alert to its canonical flow."""

    name = MATCHES_FILE.format(rule_set.name)
    found: dict = {
        "kind": rule_set.kind,
        "source": rulesets.source(rule_set),
        "source type": "tracked" if rulesets.local(rule_set) else "repository",
        "when": AFTER,
        "evaluated": False,
    }
    if rule_set.repository_authored is not None:
        found["repository authored"] = rule_set.repository_authored
    try:
        if unavailable:
            raise suricata.SuricataError(unavailable)
        if image is None:
            raise suricata.SuricataError("no Suricata image was given (--suricata-image IMAGE)")
        if lock is None:
            raise SpecError(
                f"the run did not fetch the rule set: its folder has no {rulesets.FOLDER}/{rule_set.name} "
                "checked against a lock"
            )
        folder = rulesets.held(out, rule_set.name, lock)
        alerts_and_parents: list[tuple[dict, dict, int, dict]] = []
        runs = []
        expected = None
        for host, captures in folders.items():
            made = suricata.evaluate(
                image,
                folder,
                captures,
                home_net,
                out / "engine" / "suricata" / rule_set.name / host,
            )
            engine = made.get("engine")
            if not isinstance(engine, dict):
                raise suricata.SuricataError(f"Suricata evaluation on {host} returned no engine identity")
            facts = tuple(
                made.get(key)
                for key in (
                    "rules",
                    "rule file count",
                    "rule files",
                    "loaded",
                    "failed",
                    "load errors",
                )
            )
            if expected is not None and (engine, facts) != expected:
                raise suricata.SuricataError(
                    f"the rule set {rule_set.name} was not loaded alike for every capture host"
                )
            expected = (engine, facts)
            alerts = made.get("alerts")
            keys = made.get("alert event keys")
            if not isinstance(alerts, list) or not isinstance(keys, list) or len(alerts) != len(keys):
                raise suricata.SuricataError(
                    f"Suricata evaluation of {rule_set.name} on {host} returned alerts without event keys"
                )
            for alert, event_key in zip(alerts, keys, strict=True):
                place = places.get((host, _frozen(event_key)))
                if place is None:
                    raise suricata.SuricataError(
                        f"an alert of {rule_set.name} on {host} has no canonical network event"
                    )
                alerts_and_parents.append((alert, documents[place], place, engine))
            runs.append(
                {
                    "host": host,
                    **{
                        key: value
                        for key, value in made.items()
                        if key not in ("records", "alerts", "alert event keys")
                    },
                }
            )
        made_documents, matches = [], []
        for alert, parent, place, engine in alerts_and_parents:
            document = _network_alert_document(alert, parent, rule_set, engine)
            made_documents.append(document)
            labels = document.get("labels") or {}
            rule = document.get("rule") or {}
            level = str(labels.get("level") or _suricata_level(alert))
            origin, job, step, tied_by = ties[place]
            matches.append(
                {
                    "detector": detector_id(rule_set.name),
                    "rule": str(rule.get("id")),
                    "title": rule.get("name") or rule.get("description") or str(rule.get("id")),
                    "level": level,
                    "counts": level in sigma.ALERT_LEVELS,
                    "moment": document["@timestamp"],
                    "host": _observation_host(parent),
                    "sensor": _observation_sensor(parent),
                    "event": place,
                    "event_id": labels.get("event_id"),
                    "origin": origin,
                    "job": job,
                    "step": step,
                    "tied_by": tied_by,
                }
            )
        count = ecs.write(out / name, made_documents)
        if count != len(made_documents):
            raise suricata.SuricataError(
                f"{name} has {count} lines for {len(made_documents)} Suricata alerts"
            )
        first = runs[0] if runs else {}
        found.update(
            evaluated=True,
            engine=first.get("engine"),
            rules=first.get("rules"),
            loaded=first.get("loaded"),
            failed=first.get("failed"),
            digest=rulesets.digest(rule_set, lock),
            file=name,
            lines=count,
            runs=runs,
        )
        found["rule file count"] = first.get("rule file count")
        found["rule files"] = first.get("rule files")
        found["load errors"] = first.get("load errors")
        found["rules that matched"] = matched_rules(matches)
        return found, matches
    except (SpecError, suricata.SuricataError, OSError, ValueError, TypeError, KeyError) as error:
        (out / name).unlink(missing_ok=True)
        found["not evaluated"] = str(error)
        return found, None


def matched_rules(matches: list[dict]) -> list[dict]:
    """The distinct rules among matches: each with its level, whether it counts as an alert, how many
    matches, the first, and the steps, jobs or other origins they fell on. Those that count come first."""

    rules: dict[tuple, dict] = {}
    for match in matches:
        entry = rules.setdefault(
            (match["detector"], match["rule"]),
            {
                "detector": match["detector"],
                "rule": match["rule"],
                "title": match["title"],
                "level": match["level"],
                "counts": match["counts"],
                **({"author": match["author"]} if match.get("author") else {}),
                "matches": 0,
                "first": match["moment"],
                "on": {},
            },
        )
        entry["matches"] += 1
        entry["first"] = min(entry["first"], match["moment"])
        if match["origin"] == STEP:
            where = match["step"]
        elif match["origin"] == ORDINARY:
            where = match["job"] or "no job named"
        else:
            where = match["origin"]
        label = f"{where} ({match['host']})"
        entry["on"][label] = entry["on"].get(label, 0) + 1
    return sorted(rules.values(), key=lambda entry: (not entry["counts"], entry["detector"], entry["rule"]))


def judge(
    defense: Defense,
    hosts: dict[str, list[str]],
    matches: dict[str, list[dict]],
    events: list[dict],
    ties: list[tuple],
    path: dict | None,
    started: set[str],
    agree: bool,
    day: dict,
) -> dict:
    """What one defense made of the run: of each step of the path, the race, and the ordinary day.

    `hosts` gives the hosts with a sensor of each kind and `matches` the rule
    matches of each detector. The defense counts the events from the exact
    sensor instances of its own kinds and the matches of its own rules on them, by the ties
    every defense shares. `day` is the ordinary day's score, whose
    denominators are the run's own.
    """

    watched = {sensor_id(kind, host) for kind in defense.sensors for host in hosts.get(kind, [])}
    detectors = [detector_id(rules) for rules in defense.rules]
    mine = [
        match
        for detector in detectors
        for match in matches.get(detector, [])
        if match.get("sensor") in watched
    ]
    here = [_observation_sensor(event) in watched for event in events]
    found: dict = {
        "id": defense.id,
        "name": defense.name,
        "sensors": [sensor_id(kind, host) for kind in defense.sensors for host in hosts.get(kind, [])],
        "rules": list(defense.rules),
        "detectors": detectors,
        "judged": True,
    }
    if path and path.get("steps"):
        steps, timed = [], []
        for record_ in path["steps"]:
            step_id = record_["id"]
            of_step = [
                (event, tied_by)
                for event, (_, _, step, tied_by), mine_too in zip(events, ties, here, strict=True)
                if mine_too and step == step_id
            ]
            tied = [event for event, tied_by in of_step if tied_by in COUNTED]
            by_tie = Counter(tied_by for _, tied_by in of_step if tied_by in COUNTED)
            on_step = [m for m in mine if m["step"] == step_id and m["tied_by"] in COUNTED]
            counting = [m for m in on_step if m["counts"]]
            # The first alert is that of the rule whose first match is the earliest, as `path_score` has it.
            earliest: dict[tuple, dict] = {}
            for m in counting:
                key = (m["detector"], m["rule"])
                if key not in earliest or m["moment"] < earliest[key]["moment"]:
                    earliest[key] = m
            first = min(earliest.values(), key=lambda m: m["moment"]) if earliest else None
            seen = visibility(step_id in started, len(tied), bool(counting))
            steps.append(
                {
                    "id": step_id,
                    "visibility": seen,
                    "outcome": score_word(record_.get("happened"), seen),
                    "events": len(tied),
                    "events by tie": dict(by_tie),
                    "lines tied by address alone": [_line(event) for event in tied[:SHOWN_LINES]]
                    if set(by_tie) == {"address"}
                    else [],
                    "coincident events": sum(1 for _, tied_by in of_step if tied_by == "window"),
                    "first_event": ecs.iso(min(_observation_time(event) for event in tied)) if tied else None,
                    "matches": len(on_step),
                    "rules": matched_rules(on_step),
                    "first_alert": {
                        key: first[key] for key in ("moment", "detector", "rule", "title", "level")
                    }
                    if first
                    else None,
                }
            )
            source = ecs.step_clock(record_)
            told = source != ecs.END_BEFORE_START
            timed.append(
                {
                    "id": step_id,
                    "started": record_.get("started") if told else None,
                    "ended": record_.get("ended") if told else None,
                    "time_source": source,
                    "first_alert": {"raised": first["moment"], **steps[-1]["first_alert"]} if first else None,
                }
            )
        words = Counter(step["outcome"] for step in steps)
        raced = race(timed, path.get("goal"), agree)
        if "first_alert" in raced:
            # Its moment says when it counts from: the time the manager raised a live rule's alert, the
            # time of the event for a rule that ran after the run, which was never raised.
            del raced["first_alert"]["raised"]
        found["steps"] = steps
        found["outcomes"] = {
            word: words[word] for word in ("alerted", "seen", "unseen", "no effect", "inconclusive")
        }
        found["race"] = raced
    ordinary = matched_rules([m for m in mine if m["origin"] == ORDINARY])
    packet_only = PACKET_CAPTURE in defense.sensors and WAZUH_AGENT not in defense.sensors
    packet_reason = None
    if packet_only:
        runs = day["denominators"]["runs of each job"]
        missing = [name for name, counted in runs.items() if not (counted.get("runs") or 0) >= 1]
        if not runs:
            packet_reason = "the range has no ordinary jobs, so no number of false alerts is a result"
        elif day["denominators"]["minutes of activity"] is None:
            packet_reason = (
                "the minutes of activity were not counted, so no number of false alerts is a result"
            )
        elif missing:
            packet_reason = "an ordinary job did not run: " + ", ".join(missing)
    found["ordinary"] = {
        "scored": packet_reason is None if packet_only else day["scored"],
        "not scored": packet_reason if packet_only else day["not scored"],
        "minutes": day["denominators"]["minutes of activity"],
        "events": sum(
            1 for (origin, *_), mine_too in zip(ties, here, strict=True) if mine_too and origin == ORDINARY
        ),
        "matches": ordinary,
        "false alerts": sum(1 for rule in ordinary if rule["counts"]),
    }
    found["alerts on the engine's work and unattributed events"] = matched_rules(
        [m for m in mine if m["counts"] and m["origin"] not in (ORDINARY, STEP)]
    )
    return found


def not_judged(
    defense: Defense,
    hosts: dict[str, list[str]],
    sets: dict[str, dict],
    sensor_errors: dict[str, str] | None = None,
) -> dict:
    """A defense that did not judge the run, with unavailable sensors and rule sets named."""

    why = [
        f"its rule set {rules} was not evaluated: {sets[rules].get('not evaluated')}"
        for rules in defense.rules
        if rules in sets and not sets[rules]["evaluated"]
    ]
    why += [
        f"its sensor {kind} was unavailable: {(sensor_errors or {})[kind]}"
        for kind in defense.sensors
        if kind in (sensor_errors or {})
    ]
    return {
        "id": defense.id,
        "name": defense.name,
        "sensors": [sensor_id(kind, host) for kind in defense.sensors for host in hosts.get(kind, [])],
        "rules": list(defense.rules),
        "detectors": [detector_id(rules) for rules in defense.rules],
        "judged": False,
        "not judged": "; ".join(why) or "one of its rule sets is not a rule set of the spec",
    }


def record(
    out: Path,
    logs: Path,
    run_id: str,
    alert_level: int,
    jobs: activity.Activity | None = None,
    activity_record: dict | None = None,
    addresses: dict[str, list[str]] | None = None,
    path: dict | None = None,
    uses: set[tuple[str, str]] | None = None,
    names: dict[str, str] | None = None,
    *,
    defenses: tuple[Defense, ...] = (),
    rule_sets: tuple[RuleSet, ...] = (),
    agents: list[str] | None = None,
    engine: Path | None = None,
    locks: dict[str, dict[str, str]] | None = None,
    packet_capture: dict | None = None,
    suricata_image: str | None = None,
) -> tuple[dict, dict | None]:
    """Write events.ecs.ndjson and alerts.ecs.ndjson from the manager's copied logs, and score the run.

    `logs` is the manager's copied logs folder, `path` the manifest's record of
    the path, `uses` the (host, account) pairs the path uses and `names` each
    host's container name. With a path,
    the steps are written to steps.ecs.ndjson too, and the score has `path`,
    what the defense made of each step and the race (see `path_score`).
    Returns the manifest's `ecs` section, whose `error` says why the conversion
    failed (then the score is None), and the score.

    `defenses` are the spec's named defenses, each of which judges the run
    (`judge`); a spec that names none has the one its agents and its manager's
    live rules make. `rule_sets` are the rule sets they run after the run,
    `agents` the hosts with an agent, `engine` the rule engine's program and
    `locks` the SHA-256 of each rule set's files, by the set's name: a rule
    set is evaluated only from files of the run's folder that have them.
    `packet_capture` is the retained manifest section and `suricata_image` the
    already-present pinned image used for its rule-independent and per-set passes.
    """

    section: dict = {
        "version": ecs.VERSION,
        "files": {},
        "error": None,
        "note": (
            "one ECS line for each line of the manager's archive and alerts as collected, in "
            f"{EVENTS_FILE} and {ALERTS_FILE}; the raw lines stay in raw/ so that the mapping can be checked"
        ),
    }
    try:
        # A rescore is one current judgment of the run. Remove matches and private engine work from
        # an earlier judgment before naming the files written by this one.
        for stale in (
            *out.glob("alerts.*.ecs.ndjson"),
            out / NETWORK_EVENTS_FILE,
            out / LEGACY_NETWORK_EVENTS_FILE,
        ):
            if stale.is_symlink() or stale.is_file():
                stale.unlink()
            elif stale.exists():
                shutil.rmtree(stale)
        work = out / "engine"
        if work.is_symlink() or work.is_file():
            work.unlink()
        elif work.exists():
            shutil.rmtree(work)
        raw = {}
        for kind in ("archives", "alerts"):
            folder = logs / kind
            paths = wazuh.daily_files(folder) if folder.is_dir() else []
            if not paths:
                raise ecs.ConversionError(f"no file of the manager's {kind} was copied out")
            raw[kind] = (paths, *ecs.read(paths))
        events, alerts = raw["archives"][1], raw["alerts"][1]
        record_ = activity_record or {}
        go, stop = record_.get("go") or {}, record_.get("stop") or {}
        steps, cleanups = stretches(path, out)
        found = attributed(events, run_id, jobs, addresses, go, stop, steps, cleanups, uses, names)
        own = attributed(alerts, run_id, jobs, addresses, go, stop, steps, cleanups, uses, names)
        picked, matched = alert_origins(alerts, events, found, own)
        places = matched_events(alerts, events)
        ids = [f"archive-{number}" for number in range(1, len(events) + 1)]
        for kind, name, lines, labels, convert, links in (
            ("archives", EVENTS_FILE, events, found, ecs.event, ids),
            (
                "alerts",
                ALERTS_FILE,
                alerts,
                picked,
                ecs.alert,
                [None if p is None else ids[p] for p in places],
            ),
        ):
            documents = []
            for line, labelled, where, link in zip(lines, labels, raw[kind][2], links, strict=True):
                try:
                    documents.append(convert(line, *labelled, event_id=link))
                except (ValueError, AttributeError, TypeError) as error:
                    raise ecs.ConversionError(f"{where}: {error}") from error
            count = ecs.write(out / name, documents)
            section["files"][name] = {
                "from": [str(p.relative_to(out)) if p.is_relative_to(out) else p.name for p in raw[kind][0]],
                "raw lines": len(lines),
                "ECS lines": count,
                "time sources": dict(Counter(d["labels"]["time_source"] for d in documents)),
                "origins": dict(Counter(d["labels"]["origin"] for d in documents)),
            }
            if count != len(lines):
                raise ecs.ConversionError(f"{name} has {count} lines for {len(lines)} raw lines")
        section["alerts with their event in the archive"] = matched
        counts = {origin: sum(1 for o, *_ in found if o == origin) for origin in ORIGINS}
        unattributed = Counter(
            f"{(e.get('agent') or {}).get('name')}: {e.get('location')}"
            for e, (o, *_) in zip(events, found, strict=True)
            if o == UNATTRIBUTED
        )
        result = ordinary_day(alerts, [p[:2] for p in picked], counts, alert_level, jobs, activity_record)
        result["unattributed events by host and source"] = dict(sorted(unattributed.items()))
        if path and path.get("steps"):
            result["path"] = path_score(path, steps, events, found, alerts, picked, alert_level)
            written = []
            for step_record in path["steps"]:
                scored = next(s for s in result["path"]["steps"] if s["id"] == step_record["id"])
                written.append(
                    ecs.step(
                        {**step_record, "visibility": scored["visibility"], "outcome": scored["outcome"]}
                    )
                )
            section["files"][STEPS_FILE] = {
                "from": ["manifest.json: path.steps"],
                # A "raw line" here is a step as the manifest records it.
                "raw lines": len(path["steps"]),
                "ECS lines": ecs.write(out / STEPS_FILE, written),
            }
        # Decode retained PCAPs once, independently of every packet rule set. Failure leaves the
        # Wazuh score intact and makes only defenses that need the packet sensor unavailable.
        active_defenses = defenses or (BASELINE,)
        capture_hosts = (packet_capture or {}).get("hosts") if isinstance(packet_capture, dict) else {}
        packet_hosts = sorted(capture_hosts) if isinstance(capture_hosts, dict) else []
        need_network = (
            bool(packet_hosts)
            or any(PACKET_CAPTURE in defense.sensors for defense in active_defenses)
            or any(rule_set.kind == "suricata" for rule_set in rule_sets)
        )
        network_documents: list[dict] = []
        network_ties: list[tuple] = []
        network_places: dict[tuple, int] = {}
        capture_folders: dict[str, Path] = {}
        home_net: list[str] = []
        network_error = None
        if need_network:
            try:
                if suricata_image is None:
                    raise suricata.SuricataError("no Suricata image was given (--suricata-image IMAGE)")
                if not isinstance(packet_capture, dict):
                    raise suricata.SuricataError("the run recorded no packet capture")
                (
                    network_section,
                    network_documents,
                    network_ties,
                    network_places,
                    capture_folders,
                    home_net,
                ) = network_telemetry(
                    out,
                    suricata_image,
                    packet_capture,
                    addresses or {},
                    agents,
                    jobs,
                    go,
                    stop,
                    steps,
                )
                section["network"] = network_section
                section["files"][NETWORK_EVENTS_FILE] = {
                    "from": [capture["file"] for capture in network_section["captures"]],
                    "raw lines": len(network_documents),
                    "ECS lines": network_section["lines"],
                    "time sources": dict(
                        Counter(
                            (document.get("labels") or {}).get("time_source")
                            for document in network_documents
                        )
                    ),
                    "origins": dict(Counter(origin for origin, *_ in network_ties)),
                }
            except (
                ecs.ConversionError,
                SpecError,
                suricata.SuricataError,
                OSError,
                ValueError,
                TypeError,
                KeyError,
            ) as error:
                network_error = str(error)
                stale_network = out / NETWORK_EVENTS_FILE
                if stale_network.is_symlink() or stale_network.is_file():
                    stale_network.unlink()
                elif stale_network.exists():
                    shutil.rmtree(stale_network)
                section["network"] = {"evaluated": False, "not evaluated": network_error}

        # Every defense judges the same run: live manager alerts plus matches from the evaluator
        # appropriate to each retained rule-set kind.
        matches = {PINNED: live_matches(alerts, picked, places, alert_level)}
        sets: dict[str, dict] = {}
        for rule_set in rule_sets:
            if rule_set.kind == "sigma":
                sets[rule_set.name], evaluated = after_the_run(
                    out, rule_set, engine, (locks or {}).get(rule_set.name), events, found, ids
                )
            elif rule_set.kind == "suricata":
                sets[rule_set.name], evaluated = after_suricata(
                    out,
                    rule_set,
                    suricata_image,
                    (locks or {}).get(rule_set.name),
                    capture_folders,
                    home_net,
                    network_documents,
                    network_ties,
                    network_places,
                    network_error,
                )
            else:
                raise SpecError(f"the rule set {rule_set.name} has unknown kind {rule_set.kind}")
            if evaluated is not None:
                matches[detector_id(rule_set.name)] = evaluated
        if sets:
            result["rule sets"] = sets
        seen = {(event.get("agent") or {}).get("name") for event in events}
        hosts = {
            WAZUH_AGENT: list(agents) if agents is not None else sorted(host for host in seen if host),
            PACKET_CAPTURE: packet_hosts,
        }
        sensor_errors = {PACKET_CAPTURE: network_error} if network_error else {}
        agree = result["path"]["clock"]["agree"] if "path" in result else True
        all_events = [*events, *network_documents]
        all_ties = [*found, *network_ties]
        judged = []
        for defense in active_defenses:
            unavailable = dict(sensor_errors)
            unavailable.update(
                {
                    kind: "the run records no host for this sensor"
                    for kind in defense.sensors
                    if not hosts.get(kind)
                }
            )
            ready = all(detector_id(rules) in matches for rules in defense.rules) and not any(
                kind in unavailable for kind in defense.sensors
            )
            judged.append(
                judge(
                    defense,
                    hosts,
                    matches,
                    all_events,
                    all_ties,
                    path,
                    {s.step for s in steps},
                    agree,
                    result,
                )
                if ready
                else not_judged(defense, hosts, sets, unavailable)
            )
        result["defenses"] = judged
        # A spec that names no defense has the one above, and its recording is written as before.
        result["defenses named"] = bool(defenses)
        return section, result
    except ecs.ConversionError as error:
        section["error"] = str(error)
    except Exception as error:  # noqa: BLE001 - a conversion that fails for any reason fails the run
        section["error"] = f"{type(error).__name__}: {error}"[:500]
    return section, None


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def summary(manifest: dict) -> str:
    """The ordinary day's score as Markdown, for a CI job's summary.

    A run that did not end sealed is headed "not a result", with its result, exit code and reason,
    on every branch: what could or could not be scored follows under that heading.
    """

    section = manifest.get("ecs") or {}
    score = manifest.get("score")
    invalid = []
    if manifest.get("result") != "sealed":
        invalid = [
            f"### Ordinary day of {manifest.get('range')}: not a result, the run ended "
            f"{manifest.get('result')} (exit code {manifest.get('exit_code')})",
            "",
            f"Reason: {manifest.get('reason')}",
            "",
        ]
    if section.get("error") or not score:
        if invalid:
            return "\n".join(
                [
                    *invalid,
                    f"The ordinary day was not scored: the conversion to ECS failed: {section.get('error')}",
                    "",
                ]
            )
        return (
            f"### Ordinary day of {manifest.get('range')}: not scored\n\n"
            f"The conversion to ECS failed: {section.get('error')}\n"
        )
    files = section.get("files") or {}
    counts = (
        [
            "ECS files: "
            + "; ".join(
                f"{name}, {entry['ECS lines']} lines for {entry['raw lines']} raw lines"
                for name, entry in files.items()
            )
            + ".",
            "",
        ]
        if files
        else []
    )
    if not score["scored"]:
        if invalid:
            return "\n".join(
                [*invalid, f"The ordinary day was not scored: {score['not scored']}.", "", *counts]
            )
        return "\n".join(
            [f"### Ordinary day of {manifest.get('range')}: not scored: {score['not scored']}", "", *counts]
        )
    level = score["alert_level"]
    denominators = score["denominators"]
    runs = denominators["runs of each job"]
    minutes = denominators["minutes of activity"]
    title = f"{score['false alerts']} false alerts at level {level} or higher on {minutes} minutes of ordinary work"
    lines = []
    if invalid:
        # A run that did not end sealed has no score to headline: what it recorded is shown, labelled.
        lines += [*invalid, f"What the run recorded, which is not a score of the range: {title}.", ""]
    else:
        lines += [f"### Ordinary day of {manifest.get('range')}: {title}", ""]
    lines += [
        f"On an ordinary day of {minutes} minutes from {denominators['activity started']}, with "
        + ", ".join(
            f"{name} {n['runs']} {'run' if n['runs'] == 1 else 'runs'} ({n['archived runs']} in the archive)"
            for name, n in runs.items()
        )
        + ", the stock rules raised these alerts on the shop's own work. False alerts are the distinct "
        f"rules at level {level} or higher among alerts on ordinary events; rules from level "
        f"{score['for_review_from']} to {level - 1} are for review, and never added to them.",
        "",
        "| Origin | Events | " + " | ".join(f"Alerts {name}" for _, _, name in BANDS) + " |",
        "|---|---|" + "---|" * len(BANDS),
    ]
    for origin in ORIGINS:
        bands = score["alerts by origin and level"].get(origin, {})
        lines.append(
            f"| {origin} | {denominators['events of each origin'].get(origin, 0)} | "
            + " | ".join(str(bands.get(name, 0)) for _, _, name in BANDS)
            + " |"
        )
    lines.append("")
    for heading, rules in (
        (f"False alerts (level {level} or higher, ordinary)", score["false alert rules"]),
        (
            f"For review (levels {score['for_review_from']} to {level - 1}, ordinary)",
            score["for review rules"],
        ),
        (
            f"Level {level} or higher on the engine's work and on unattributed events (not the shop's)",
            score["alerts at the alert level on the engine's work and unattributed events"],
        ),
    ):
        lines += [f"{heading}: {len(rules)} rules.", ""]
        if rules:
            lines += ["| Rule | Description | Level | Alerts | On |", "|---|---|---|---|---|"]
            lines += [
                f"| {r['rule']} | {_cell(r['description'])} | {r['level']} | {r['alerts']} | "
                + _cell(", ".join(f"{k} {v}" for k, v in r["on"].items()))
                + " |"
                for r in rules
            ]
            lines.append("")
    unattributed = score.get("unattributed events by host and source") or {}
    if unattributed:
        lines += [
            "Unattributed events, neither the engine's, a cleanup's, a job's nor a step's: "
            + ", ".join(f"{k} {v}" for k, v in unattributed.items())
            + ".",
            "",
        ]
    lines += ["What the jobs exercise:", ""]
    lines += [f"- {_cell(item)}" for item in score["what the jobs exercise"]]
    lines.append("")
    return "\n".join(lines + counts)


def markdown(manifest: dict) -> str:
    """score.md: the path's outcome and what each defense made of it, then the ordinary day of the manager's
    live rules, then what each rule set that ran after the run was given and what it matched."""

    path = path_summary(manifest)
    text = (path + "\n" if path else "") + summary(manifest)
    later = ([] if path else defenses_table(manifest)) + rule_sets_summary(manifest)
    return text + ("\n" + "\n".join(later) if later else "")


# A kind of sensor in words, for a table.
SENSOR_WORDS = {WAZUH_AGENT: "Wazuh agent", PACKET_CAPTURE: "packet capture"}


def _sensors(ids: list[str]) -> str:
    """A defense's sensors in words: each kind with the hosts it is on."""

    said = []
    for kind, words in SENSOR_WORDS.items():
        hosts = [found.removeprefix(kind + "-") for found in ids if found.startswith(kind + "-")]
        if hosts:
            said.append(f"{words} on {', '.join(hosts)}")
    return "; ".join(said) or "none"


def _rule_words(manifest: dict, defense: dict) -> str:
    """A defense's rules in words: what they are, and whether they ran live or after the run."""

    sets = (manifest.get("score") or {}).get("rule sets") or {}
    said = []
    for rules in defense["rules"]:
        if rules == WAZUH_RULES:
            version = (manifest.get("defense") or {}).get("wazuh_version")
            said.append(f"Wazuh{' ' + version if version else ''} stock rules, {LIVE}")
            continue
        entry = sets.get(rules) or {}
        repo, _, commit = str(entry.get("source") or rules).partition("@")
        words = f"{repo} at {commit[:8]}, {AFTER}" if commit else f"{repo}, {AFTER}"
        if entry.get("evaluated"):
            engine = entry.get("engine") or {}
            words += (
                f" ({entry['rules']} rules, {entry['loaded']} loaded by "
                f"{' '.join(str(part) for part in (engine.get('name'), engine.get('version')) if part)})"
            )
        said.append(words)
    return "; ".join(said) or "none: it only records"


def _rule(match: dict) -> str:
    """A rule that matched, in a few words: the manager's by their number, a rule set's by its title."""

    if match["detector"] == PINNED:
        return f"rule {match['rule']} ({_cell(match['title'])}, level {match['level']})"
    return f"{_cell(match['title'])} (level {match['level']})"


def defenses_table(manifest: dict) -> list[str]:
    """One row for each defense: its sensors, its rules, how many steps it alerted on, saw and did not see,
    its first alert against the goal, and its false alerts on the ordinary day."""

    judged = (manifest.get("score") or {}).get("defenses") or []
    if not judged:
        return []
    lines = [
        "| Defense | Sensors | Rules | Steps alerted on | Steps seen, no alert | Steps not seen | First alert "
        "| False alerts on the ordinary day |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for defense in judged:
        start = f"| {_cell(defense['name'])} (`{defense['id']}`) | {_sensors(defense['sensors'])} | "
        start += f"{_cell(_rule_words(manifest, defense))} | "
        if not defense["judged"]:
            lines.append(start + "not judged | not judged | not judged | not judged | not judged |")
            continue
        words, raced = defense.get("outcomes"), defense.get("race") or {}
        steps = (
            f"{words['alerted']} | {words['seen']} | {words['unseen']}"
            if words
            else "no path | no path | no path"
        )
        alert, reached = raced.get("first_alert_seconds"), raced.get("goal_seconds")
        if alert is None:
            first = "none"
        else:
            first = f"{alert} s after the first step started"
            if reached is None:
                first += "; the goal was not reached"
            elif alert <= reached:
                first += f", {round(reached - alert, 3)} s before the goal"
            else:
                first += f", {round(alert - reached, 3)} s after the goal"
            first += f": {_rule(raced['first_alert'])} on {raced['first_alert']['step']}"
            if not raced.get("result"):
                first += " (not a result: the clocks are not shown to agree)"
        day = defense["ordinary"]
        false_alerts = f"{day['false alerts']} in {day['minutes']} minutes" if day["scored"] else "not scored"
        lines.append(start + f"{steps} | {first} | {false_alerts} |")
    lines.append("")
    for defense in judged:
        if not defense["judged"]:
            lines += [f"The defense `{defense['id']}` was not judged: {_cell(defense['not judged'])}.", ""]
    lines += [
        "Every defense judges the same run and counts only what its own sensors recorded and its own rules "
        "matched. A match counts as an alert at level high or critical, which for Wazuh's rules is level 12 "
        "or higher; a rule that ran after the run counts from the time of the event it matched. A false "
        "alert is a rule that counts and matched ordinary work, whatever the number of its matches.",
        "",
    ]
    return lines


def rule_sets_summary(manifest: dict) -> list[str]:
    """What each rule set that runs after the run was given, how much of it the engine loaded and read, and
    the rules that matched with where their matches fell."""

    sets = (manifest.get("score") or {}).get("rule sets") or {}
    lines: list[str] = []
    for name, entry in sets.items():
        repo, _, commit = str(entry.get("source") or "").partition("@")
        title = f"{repo} at {commit}, {AFTER}"
        if manifest.get("result") != "sealed":
            # As the path and the ordinary day are: what the run recorded is shown, labelled.
            title = (
                f"not a result, the run ended {manifest.get('result')} (exit code {manifest.get('exit_code')}): "
                + title
            )
        lines += [f"### Rule set {name} of {manifest.get('range')}: {title}", ""]
        if not entry.get("evaluated"):
            lines += [f"Not evaluated: {_cell(entry.get('not evaluated'))}.", ""]
            continue
        engine = entry.get("engine") or {}
        if entry.get("kind") == "suricata":
            rule_files = entry.get("rule files") or []
            failed = entry.get("failed") or 0
            lines += [
                f"{engine.get('name')} {engine.get('version')} read the run's retained packet captures "
                f"after the run with no network: {entry.get('rules', 0)} rules from "
                f"{count(len(rule_files), 'file')}, {entry.get('loaded', 0)} loaded and {failed} failed. "
                "A rule the engine did not load was not evaluated. "
                f"The matches are in {entry['file']} ({count(entry['lines'], 'line')}), each at the time "
                "of its linked packet event.",
                "",
                "| Capture host | Capture files | Packets read | Network records | Alerts |",
                "|---|---|---|---|---|",
            ]
            for run in entry.get("runs") or []:
                read = run.get("read counts") or {}
                lines.append(
                    f"| {_cell(run.get('host'))} | {read.get('capture files', 0)} | "
                    f"{read.get('packets', 0)} | {read.get('network records', 0)} | "
                    f"{read.get('alerts', 0)} |"
                )
            lines.append("")
            if failed:
                reasons = entry.get("load errors") or []
                lines += [
                    "Rule load failures: "
                    + ("; ".join(_cell(reason) for reason in reasons) or "the engine gave no reason")
                    + ".",
                    "",
                ]
            matched = entry.get("rules that matched") or []
            lines += [f"Rules that matched: {len(matched)}.", ""]
            if matched:
                lines += [
                    "| Rule | Level | Counts as an alert | Author | Matches | On |",
                    "|---|---|---|---|---|---|",
                ]
                lines += [
                    f"| {_cell(rule['title'])} (`{rule['rule']}`) | {rule['level']} | "
                    f"{'yes' if rule['counts'] else 'no'} | {_cell(rule.get('author') or '')} | "
                    f"{rule['matches']} | "
                    + _cell(", ".join(f"{where} {number}" for where, number in rule["on"].items()))
                    + " |"
                    for rule in matched
                ]
                lines.append("")
            continue
        lines += [
            f"{engine.get('name')} {engine.get('version')} was given the run's archived events after the run, "
            f"each rule folder over the events of its log source and no others: {entry['rules']} rules, "
            f"{entry['loaded']} loaded by the engine. A rule the engine does not load was not evaluated. "
            f"The matches are in {entry['file']} ({count(entry['lines'], 'line')}), each at the time of its "
            "event.",
            "",
            "| Rule folder | Log source | Events given | Rules | Loaded | Given | Read | Rules that matched | "
            "Matches | Fields given | Fields rules name that are not given |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for group in entry["groups"]:
            missing = group.get("fields the rules name that are not given") or {}
            given = "" if "events" not in group else ", ".join(group.get("fields given") or []) or "the line"
            lines.append(
                f"| {group['folder']} | {_cell(group['log source'])} | "
                f"{_cell(group.get('events') or 'none: ' + group['not evaluated'])} | {group['rules']} | "
                f"{group['loaded']} | {group['given']} | {group['read']} | {group['rules that matched']} | "
                f"{group['matches']} | {given} | "
                + (", ".join(f"{field} ({rules})" for field, rules in missing.items()) or "none")
                + " |"
            )
        lines += [
            "",
            "Loaded is what the engine says it loaded of the rules it was given, and read what it says it "
            "read of the events. In the last column, the number after a field is how many of the rules name "
            "it: a rule cannot match on a field it was not given.",
            "",
        ]
        skipped = [group for group in entry["groups"] if group.get("not evaluated")]
        if skipped:
            lines += [
                "Not evaluated: "
                + "; ".join(
                    f"{count(group['rules'], 'rule')} of {group['folder']} ({_cell(group['not evaluated'])})"
                    for group in skipped
                )
                + ".",
                "",
            ]
        left_out = entry.get("files that are not a rule") or []
        if left_out:
            lines += [
                "Files that are not a rule: "
                + "; ".join(f"{_cell(item['file'])} ({item['why']})" for item in left_out)
                + ".",
                "",
            ]
        matched = entry.get("rules that matched") or []
        lines += [f"Rules that matched: {len(matched)}.", ""]
        if matched:
            lines += [
                "| Rule | Level | Counts as an alert | Author | Matches | On |",
                "|---|---|---|---|---|---|",
            ]
            lines += [
                f"| {_cell(rule['title'])} (`{rule['rule']}`) | {rule['level']} | "
                f"{'yes' if rule['counts'] else 'no'} | {_cell(rule.get('author') or '')} | {rule['matches']} | "
                + _cell(", ".join(f"{where} {number}" for where, number in rule["on"].items()))
                + " |"
                for rule in matched
            ]
            lines.append("")
    return lines


def path_summary(manifest: dict) -> str:
    """The path's outcome, what each defense made of it and of each step, and the detail of the manager's
    live rules, as Markdown for a CI job's summary."""

    found = (manifest.get("score") or {}).get("path")
    if not found:
        return ""
    level = found["alert_level"]
    race_ = found["race"]
    day = manifest.get("score") or {}
    outcome = path_outcome(race_)
    lines = []
    if manifest.get("result") != "sealed":
        lines += [
            f"### Path of {manifest.get('range')}: not a result, the run ended {manifest.get('result')} "
            f"(exit code {manifest.get('exit_code')})",
            "",
            f"Reason: {manifest.get('reason')}",
            "",
            f"What the run recorded, which is not a score of the range: {outcome}.",
            "",
        ]
    else:
        lines += [f"### Path of {manifest.get('range')}: {outcome}", ""]
    lines += defenses_table(manifest)
    judged = day.get("defenses") or []
    columns = [
        (
            f"`{defense['id']}`",
            {step["id"]: step["outcome"] for step in defense.get("steps") or []} if defense["judged"] else {},
        )
        for defense in judged
    ]
    lines += [
        "| Step | Host | What happened | Recorded | Agents | Ties | Coincident | First alert of the live rules | "
        + "".join(f"{name} | " for name, _ in columns or [("Outcome", {})])
        + "Expected live rules missing |",
        "|---|---|---|---|---|---|---|---|" + "---|" * (len(columns) or 1) + "---|",
    ]
    for step in found["steps"]:
        first = step.get("first_alert")
        words = [said.get(step["id"], "not judged") for _, said in columns] or [step["outcome"]]
        lines.append(
            f"| {step['id']} | {step['host']}{''.join(' to ' + t for t in step['to'])} | {step['happened']} | "
            f"{step['visibility']} ({count(step['events'], 'event')}) | "
            + _cell(", ".join(f"{k} {v}" for k, v in step["agents"].items()) or "none")
            + " | "
            + _cell(", ".join(f"{k} {v}" for k, v in step["events by tie"].items()) or "none")
            + f" | {step['coincident events']} | "
            + (f"{first['rule']} (level {first['level']}) at {first['raised']}" if first else "none")
            + " | "
            + "".join(f"{word} | " for word in words)
            + (", ".join(step["expected rules that did not appear"]) or "none")
            + " |"
        )
    lines += [
        "",
        "Recorded, the agents, the ties and the coincident events are the same for every defense that has "
        "these sensors. The rest of this section is the detail of the Wazuh manager's live rules.",
        "",
    ]
    alert = race_.get("first_alert")
    parts = [
        f"First alert at level {level} or higher: "
        + (
            f"{race_['first_alert_seconds']} s after the first step started, rule {alert['rule']} "
            f"({_cell(alert['description'])}, level {alert['level']}) on {alert['step']}"
            if alert
            else "none"
        )
        + ".",
        "Goal: "
        + (
            f"{race_['goal_seconds']} s after the first step started ({_cell(race_['goal'])})"
            if "goal_seconds" in race_
            else "not reached"
        )
        + ".",
    ]
    if day.get("scored"):
        parts.append(
            f"Beside it, on the ordinary day: {day['false alerts']} false alerts at level {level} or higher "
            f"in {day['denominators']['minutes of activity']} minutes."
        )
    else:
        parts.append(f"Beside it, the ordinary day was not scored: {day.get('not scored')}.")
    lines += [" ".join(parts), ""]
    for step in found["steps"]:
        shown = step.get("lines tied by address alone") or []
        if shown:
            lines.append(
                f"{step['id']} is seen only through {count(step['events'], 'line')} tied by the address rule "
                f"alone: {'the line names' if step['events'] == 1 else 'each line names'} {step['host']}'s "
                "address or container name, or comes from its address"
                + (f"; the first {len(shown)}" if len(shown) < step["events"] else "")
                + ": "
                + "; ".join(f"`{_cell(line)}`" for line in shown)
                + "."
            )
            lines.append("")
    check = found["clock"]
    lag = check["manager's time against the line's"]
    lines += [
        f"One clock. Steps: {check['steps']}. Alerts: {check['alerts']}. Checked: "
        f"{check['program starts checked']} program starts in the steps' sessions, at their containers' time, "
        f"{check['outside their step']} outside their step's daemon times"
        + (
            "; the daemon's times of "
            + ", ".join(check["steps on the engine's clock"])
            + " were not matched or not in order, so they are not used"
            if check["steps on the engine's clock"]
            else ""
        )
        + ("." if check["agree"] else ": the clocks are not shown to agree, so the race is not a result."),
        "",
        "The manager's own time of an archived line, against the time rsyslog wrote on it in its container: "
        f"from {lag['least seconds']} s to {lag['most seconds']} s, earlier than the line for "
        f"{lag['earlier than the line']} of {lag['lines']} lines. An alert counts from the manager's time of "
        "it, or from its line's time when the manager's is earlier.",
        "",
        "No step can be stopped: the range configures no active response. "
        f"An event that only falls inside a step's time span, from its start to {GRACE} s after its end, is "
        "coincident and is not counted as the step's. "
        "Unattributed: "
        f"{found['events']['of each origin'].get(UNATTRIBUTED, 0)} events "
        f"({found['events']['unattributed, coincident with a step']} coincident with a step) and "
        f"{found['alerts']['of each origin'].get(UNATTRIBUTED, 0)} alerts "
        f"({found['alerts']['unattributed at the alert level']} at level {level} or higher).",
        "",
    ]
    lines += [f"- {_cell(note)}" for note in found["notes"]]
    lines.append("")
    return "\n".join(lines)

"""The path of a range: its published tests, run one after another inside the sealed range, and what each did.

`load` is the path part of the spec loader. It reads each step's test from the
pinned technique YAML and checks it as the upstream executor would run it. It
then refuses a host outside the spec, or one that shares no network with the
step's host, where it recognises a host: the step's `to`, a Url-typed
argument, a `user@host` argument, and in the merged command, prerequisite
check and cleanup a URL with a scheme, an `@host` and `/dev/tcp/<host>` or
`/dev/udp/<host>`. It refuses any word that Python's `ipaddress` reads as an
address. It does not recognise a bare host name, nor an address in a short,
integer or hex form. It refuses a step on a host that runs a pinned image, and
a step with a `to` that reaches a host, recognised so, that its `to` does not
name, since the score ties a step's events by `to`. These rules are an early,
plain refusal of mistakes; the seal is what keeps a step inside the range. They
run before any container is created.

`Executor` runs the path in a sealed range and only there: in the range's own
containers, once the seal's phases before the path have passed. For each
step: the published prerequisite check, the test through `docker exec` with
exactly the argument vector of `atomic`, a grace of a few seconds, the step's
effect check from the spec, run as root, and the published cleanup when the
spec asks for it. A step's start and end are the Docker daemon's times of its
exec's `exec_start` and `exec_die` events, and the engine's clock, labelled,
only where those were not matched or the end came before the start. What happened is one of `took effect`,
`attempted without effect`, `not attempted` and `inconclusive`. Then the goal
check, on files copied out of the range. An event on the range that the engine
did not cause stops the path, and so does an event watch that no longer runs or
that has not reported the start and end of a step's own command within
`EVENT_SECONDS` and `WATCH_SECONDS`, the watch's time to settle, after the
command returned; the engine then makes the run invalid.

Tags, in BLUEFIRE_TAG: `engine:prereq:<id>`, `step:<id>`, `engine:check:<id>`,
`cleanup:<id>` and `engine:kill`.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
import shlex
import subprocess
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .. import atomic
from ..report import count
from . import build
from .spec import Spec, SpecError, home, read

STEP_KEYS = {
    "id",
    "technique",
    "guid",
    "name",
    "host",
    "to",
    "account",
    "workdir",
    "args",
    "timeout",
    "cleanup",
    "check",
    "expect",
    "plain",
}
STEP_REQUIRED = {"id", "technique", "guid", "name", "host", "account", "workdir", "args", "cleanup", "check"}
PATH_KEYS = {"start", "hand_off", "goal", "steps"}
DEFAULT_TIMEOUT = 120
LONGEST_TIMEOUT = 3600
GRACE_SECONDS = 5
PREREQ_SECONDS = 120
CHECK_SECONDS = 120
CLEANUP_SECONDS = 120
KILL_SECONDS = 60
# How long the engine waits for the daemon's events of an exec after the command returned.
EVENT_SECONDS = 15
# How much longer it waits when they are late: the time the event watch is given to settle. A command
# whose start and end the watch has not reported by then stops the path.
WATCH_SECONDS = 15
POLL_SECONDS = 0.2
# The largest member of an uploaded archive that the goal check reads.
LARGEST_MEMBER = 64 * 1024 * 1024

TOOK_EFFECT = "took effect"
NO_EFFECT = "attempted without effect"
NOT_ATTEMPTED = "not attempted"
INCONCLUSIVE = "inconclusive"
HAPPENED = (TOOK_EFFECT, NO_EFFECT, NOT_ATTEMPTED, INCONCLUSIVE)

STEP_ID = re.compile(r"[a-z][a-z0-9]{0,15}\Z")
WORKDIR = re.compile(r"/[A-Za-z0-9._/-]*\Z")
IP_FILL = re.compile(r"\{ip:([^@}]*)@([^}]*)\}")
HOST_PATH = re.compile(r"([a-z][a-z0-9-]*):(/[A-Za-z0-9._/-]+)\Z")
USER_AT_HOST = re.compile(r"[A-Za-z0-9._-]+@([A-Za-z0-9._-]+)\Z")
# Where a merged command names a host: in a URL, after an @, and in bash's /dev/tcp and /dev/udp.
URL_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s\"'`@]*@)?(\[[^\]\s]*\]|[^/\s\"'`:?#\[\]]+)")
AT_HOST = re.compile(r"@([A-Za-z0-9][A-Za-z0-9.-]*)")
DEV_HOST = re.compile(r"/dev/(?:tcp|udp)/([^/\s\"'`]+)")
# Words that could be an IPv4 or IPv6 address, checked one by one with the ipaddress module.
ADDRESS_WORD = re.compile(r"[0-9A-Za-z:.%]+")
# What the Docker CLI or the container runtime prints when it could not start a command at all.
DOCKER_ERRORS = ("Error response from daemon", "OCI runtime", "unable to start container process")


@dataclass(frozen=True)
class Check:
    """A step's effect check, as the spec writes it.

    `run`: a command run as root on `host`, which shows the effect when it exits
    0. `output`: the attack's standard output holds `text`. `all`: every part
    shows the effect. `upload`: the first upload the stand-in internet stored
    came from `source` and has the SHA-256 of the file `of` (host, path).
    """

    kind: str
    host: str | None = None
    run: str | None = None
    text: str | None = None
    parts: tuple[Check, ...] = ()
    source: str | None = None
    of: tuple[str, str] | None = None


@dataclass(frozen=True)
class Step:
    id: str
    technique: str
    guid: str
    name: str
    host: str
    to: tuple[str, ...]
    account: str
    workdir: str
    args: dict
    timeout: int
    cleanup: str
    check: Check
    expect: tuple[int, ...]
    attack: tuple[str, ...]
    prereqs: tuple[tuple[str, ...], ...]
    # The published cleanup's vector, or None when the step runs no cleanup (cleanup: none).
    undo: tuple[str, ...] | None
    # What the step does, in one plain sentence, for the recording.
    plain: str = ""


@dataclass(frozen=True)
class Goal:
    plain: str
    after: str
    source: str
    contains: str
    inner: str
    equals: tuple[str, str]


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]
    goal: Goal | None
    upload_host: str | None


def section(spec: Spec) -> dict | None:
    """The `path` section of the spec as written, or None."""

    return read(spec.text).get("path") if spec.text else None


def upload_host(spec: Spec) -> str | None:
    """The one host that runs the stand-in internet's server, if there is exactly one."""

    found = [host.name for host in spec.hosts.values() if "inet-server" in host.services]
    return found[0] if len(found) == 1 else None


def addresses_in(text: str) -> list[str]:
    """The words of a text that Python's `ipaddress` reads as an IPv4 or IPv6 address.

    A short, integer or hex form of an address (127.1, 2130706433, 0x7f000001) is not one of them.
    """

    found = []
    for word in ADDRESS_WORD.findall(text):
        for candidate in {word, word.strip("."), word.strip(":")}:
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            found.append(candidate)
            break
    return found


def hosts_in(text: str) -> list[str]:
    """The host names a command writes in a URL with a scheme, after an @, or in /dev/tcp and /dev/udp.

    A bare host name, as in `ping build`, is not found.
    """

    found = [match.strip("[]") for match in URL_HOST.findall(text)]
    found += AT_HOST.findall(text) + DEV_HOST.findall(text)
    return list(dict.fromkeys(found))


def _fills(text: str, where: str, spec: Spec) -> None:
    for host, network in IP_FILL.findall(text):
        if host not in spec.hosts or network not in spec.hosts[host].networks:
            raise SpecError(
                f"{where}: {{ip:{host}@{network}}} must name a host of the spec and one of its networks, "
                "as in {ip:web@edge}"
            )
    if "{ip:" in IP_FILL.sub("", text):
        raise SpecError(f"{where}: write an address to fill in as {{ip:<host>@<network>}}")


def _host_path(value: object, where: str, spec: Spec) -> tuple[str, str]:
    found = HOST_PATH.match(value) if isinstance(value, str) else None
    if not found or found.group(1) not in spec.hosts:
        raise SpecError(
            f"{where} must be <host>:<absolute path> on a host of the spec, as in web:/tmp/loot.tar.gz"
        )
    return found.group(1), found.group(2)


def _check(value: object, where: str, spec: Spec) -> Check:
    if not isinstance(value, dict) or not value:
        raise SpecError(f"{where} must be one of {{host, run}}, {{output_contains}}, {{all}} or {{upload}}")
    keys = set(value)
    if "all" in keys:
        if keys != {"all"} or not isinstance(value["all"], list) or not value["all"]:
            raise SpecError(f"{where}: all takes a list of checks and nothing beside it")
        return Check("all", parts=tuple(_check(part, where, spec) for part in value["all"]))
    if "output_contains" in keys:
        if (
            keys != {"output_contains"}
            or not isinstance(value["output_contains"], str)
            or not value["output_contains"]
        ):
            raise SpecError(f"{where}: output_contains takes a text and nothing beside it")
        if "{ip:" in value["output_contains"]:
            raise SpecError(f"{where}: output_contains is compared as written, without addresses filled in")
        return Check("output", text=value["output_contains"])
    if "upload" in keys:
        if keys != {"upload", "from", "sha256_equals"} or value["upload"] != "first":
            raise SpecError(
                f"{where}: an upload check is {{upload: first, from: <address>, sha256_equals: <host:path>}}"
            )
        if upload_host(spec) is None:
            raise SpecError(f"{where}: an upload check needs exactly one host that runs inet-server")
        source = value["from"]
        if not isinstance(source, str) or not IP_FILL.fullmatch(source):
            raise SpecError(f"{where}: from must be one address to fill in, as in {{ip:web@edge}}")
        _fills(source, where, spec)
        return Check(
            "upload", source=source, of=_host_path(value["sha256_equals"], f"{where}: sha256_equals", spec)
        )
    if keys == {"host", "run"}:
        if value["host"] not in spec.hosts or spec.hosts[value["host"]].kind == "defense":
            raise SpecError(
                f"{where}: host {value['host']!r} must be a host of the spec other than the manager"
            )
        if not isinstance(value["run"], str) or not value["run"].strip():
            raise SpecError(f"{where}: run must be a command")
        _fills(value["run"], where, spec)
        return Check("run", host=value["host"], run=value["run"])
    raise SpecError(f"{where} must be one of {{host, run}}, {{output_contains}}, {{all}} or {{upload}}")


def _reached(step_id: str, host: str, text: str, what: str, spec: Spec) -> None:
    """Refuse a merged command that holds an address, or names a host outside the spec or off the step's networks.

    Only the forms of `addresses_in` and `hosts_in` are recognised; a bare host
    name, for one, is not.
    """

    for address in addresses_in(text):
        raise SpecError(
            f"step {step_id}: the {what} holds the IP address {address}: give the input argument a host name "
            "of the range instead (the engine fills in addresses only in checks, as {ip:<host>@<network>})"
        )
    for name in hosts_in(text):
        if name not in spec.hosts:
            raise SpecError(
                f"step {step_id}: the {what} names {name} (in a URL, after an @, or in /dev/tcp or /dev/udp), "
                "which is not a host of the spec: give the input argument a host of the range"
            )
        if name != host and not spec.shared(host, name):
            raise SpecError(
                f"step {step_id}: the {what} names {name} (in a URL, after an @, or in /dev/tcp or /dev/udp), "
                f"which shares no network with {host}: run the step on a host that shares a network with "
                f"{name}, or name another host"
            )


def _step(value: object, number: int, spec: Spec, atomics: Path, seen: set[str]) -> Step:
    if not isinstance(value, dict):
        raise SpecError(f"step {number} of the path must be a mapping")
    step_id = value.get("id")
    if not isinstance(step_id, str) or not STEP_ID.match(step_id):
        raise SpecError(
            f"step {number} of the path: id must be short, lower-case letters and digits, as in s01"
        )
    if step_id in seen:
        raise SpecError(f"step {step_id}: another step has the same id; give each step its own")
    seen.add(step_id)
    where = f"step {step_id}"
    unknown = sorted(str(key) for key in value if key not in STEP_KEYS)
    if unknown:
        raise SpecError(f"{where} has unknown keys: {', '.join(unknown)}")
    missing = sorted(STEP_REQUIRED - set(value))
    if missing:
        raise SpecError(f"{where} lacks: {', '.join(missing)}")
    host = value["host"]
    if host not in spec.hosts or spec.hosts[host].kind == "defense":
        raise SpecError(f"{where} runs on {host!r}: name a host of the spec other than the manager")
    if not spec.hosts[host].built:
        raise SpecError(
            f"{where} runs on {host}, which runs a pinned image: the path's published files are fetched and "
            f"carried only by hosts built from base, so build {host} from base or run the step on another host"
        )
    to = value.get("to", [])
    to = [to] if isinstance(to, str) else to
    if not isinstance(to, list):
        raise SpecError(f"{where}: to must name a host of the spec, or list several")
    for target in to:
        if target not in spec.hosts:
            raise SpecError(
                f"{where} goes to {target!r}, which is not a host of the spec: name one of its hosts"
            )
        if not spec.shared(host, target):
            raise SpecError(f"{where} goes to {target}, which shares no network with {host}")
    account = value["account"]
    if account not in spec.hosts[host].account_names:
        raise SpecError(
            f"{where} runs as {account!r}, which is not an account of {host}; it has "
            f"{', '.join(spec.hosts[host].account_names)}"
        )
    workdir = value["workdir"]
    if not isinstance(workdir, str) or not WORKDIR.match(workdir) or "/../" in workdir + "/":
        raise SpecError(f"{where}: workdir must be an absolute path, as in /tmp")
    timeout = value.get("timeout", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 < timeout <= LONGEST_TIMEOUT:
        raise SpecError(f"{where}: timeout must be a number of seconds from 1 to {LONGEST_TIMEOUT}")
    expect = value.get("expect", [])
    if not isinstance(expect, list) or not all(
        isinstance(r, int) and not isinstance(r, bool) for r in expect
    ):
        raise SpecError(f"{where}: expect must list Wazuh rule ids, as in [5715, 5501]")
    plain = value.get("plain", "")
    if not isinstance(plain, str) or "\n" in plain:
        raise SpecError(f"{where}: plain must be one sentence that says what the step does")
    args = value["args"]
    if not isinstance(args, dict):
        raise SpecError(f"{where}: args must map each input argument of the test to its value")
    for name, argument in args.items():
        if isinstance(argument, str) and "{ip:" in argument:
            raise SpecError(
                f"{where}: the input argument {name} holds {{ip:...}}, which is filled in only in checks: "
                "give the host's name"
            )

    technique, guid = value["technique"], value["guid"]
    try:
        document = atomic.load_technique(atomics / technique / f"{technique}.yaml")
        test = atomic.find_test(document, str(guid))
        atomic.check_step(value, document, test)
        vectors = atomic.argvs(test, args)
    except FileNotFoundError as error:
        raise SpecError(f"{where}: the technique YAML of {technique} was not fetched: {error}") from error
    except (OSError, ValueError, KeyError) as error:
        message = str(error).removeprefix(f"{where}: ")
        raise SpecError(f"{where} ({technique} {guid}): {message}") from error

    published = test.get("input_arguments") or {}
    reaches: list[str] = []
    for name, argument in args.items():
        kind = (
            str((published.get(name) or {}).get("type", "")).lower()
            if isinstance(published.get(name), dict)
            else ""
        )
        named = []
        if kind == "url":
            parsed = urlsplit(argument) if "://" in argument else None
            named.append(
                parsed.hostname if parsed else argument.rpartition("@")[2].split(":")[0].split("/")[0]
            )
        at = USER_AT_HOST.match(argument)
        if at:
            named.append(at.group(1))
        for name_found in named:
            if name_found not in spec.hosts:
                raise SpecError(
                    f"{where}: the input argument {name} names {name_found!r}, which is not a host of the spec: "
                    "name a host of the range"
                )
        reaches += named

    _reached(step_id, host, vectors["attack"][2], "command", spec)
    reaches += hosts_in(vectors["attack"][2])
    for prereq in vectors["prereqs"]:
        _reached(step_id, host, prereq[2], "prerequisite check", spec)
        reaches += hosts_in(prereq[2])
    if vectors["cleanup_published"]:
        _reached(step_id, host, vectors["cleanup"][2], "cleanup", spec)
        reaches += hosts_in(vectors["cleanup"][2])
    # The score ties a step's events on the hosts of its `to`: a `to` must name every other host the step reaches.
    for name_found in dict.fromkeys(reaches) if to else ():
        if name_found != host and name_found not in to:
            raise SpecError(
                f"{where} reaches {name_found}, which its to does not name: add {name_found} to the step's to, "
                "since the score ties a step's events on the hosts in to"
            )

    return Step(
        step_id,
        technique,
        str(guid),
        value["name"],
        host,
        tuple(to),
        account,
        workdir,
        dict(args),
        timeout,
        value["cleanup"],
        _check(value["check"], f"{where}: check", spec),
        tuple(expect),
        tuple(vectors["attack"]),
        tuple(tuple(prereq) for prereq in vectors["prereqs"]),
        None if value["cleanup"] == "none" else tuple(vectors["cleanup"]),
        plain.strip(),
    )


def _goal(value: object, spec: Spec, steps: tuple[Step, ...]) -> Goal | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"plain", "after", "check"}:
        raise SpecError("path.goal must be {plain, after, check}")
    if value["after"] not in {step.id for step in steps}:
        raise SpecError(f"path.goal: after names {value['after']!r}, which is not a step of the path")
    check = value["check"]
    keys = {"upload", "from", "contains", "inner", "equals"}
    if not isinstance(check, dict) or set(check) != keys or check["upload"] != "first":
        raise SpecError(
            "path.goal.check must be {upload: first, from: <address>, contains: <member>, inner: <member>, "
            "equals: <host:path>}"
        )
    if upload_host(spec) is None:
        raise SpecError("path.goal.check reads an upload, and needs exactly one host that runs inet-server")
    if not isinstance(check["from"], str) or not IP_FILL.fullmatch(check["from"]):
        raise SpecError("path.goal.check: from must be one address to fill in, as in {ip:web@edge}")
    _fills(check["from"], "path.goal.check", spec)
    for key in ("contains", "inner"):
        if not isinstance(check[key], str) or not check[key] or check[key].startswith("/"):
            raise SpecError(
                f"path.goal.check: {key} must be the name of a member of an archive, as tar lists it"
            )
    return Goal(
        str(value["plain"]),
        value["after"],
        check["from"],
        check["contains"],
        check["inner"],
        _host_path(check["equals"], "path.goal.check: equals", spec),
    )


def load(spec: Spec, path: object, atomics: Path) -> Plan:
    """The path of a spec, checked against the technique YAMLs in `atomics` (folders <T>/<T>.yaml)."""

    if path is None:
        return Plan((), None, upload_host(spec))
    if not isinstance(path, dict):
        raise SpecError("path must be a mapping with steps")
    unknown = sorted(str(key) for key in path if key not in PATH_KEYS)
    if unknown:
        raise SpecError(f"path has unknown keys: {', '.join(unknown)}")
    if not isinstance(path.get("steps"), list) or not path["steps"]:
        raise SpecError("path must have steps, a list")
    seen: set[str] = set()
    steps = tuple(
        _step(value, number, spec, atomics, seen) for number, value in enumerate(path["steps"], start=1)
    )
    return Plan(steps, _goal(path.get("goal"), spec, steps), upload_host(spec))


def plan(spec: Spec, rendered: Path | None) -> Plan:
    """The spec's path, read against the technique YAMLs of the rendered build folder.

    `rendered` is None when no host is built from the spec. A spec with a path
    is refused then, since the technique YAMLs are fetched for the build.
    """

    found = section(spec)
    if found is None:
        return Plan((), None, upload_host(spec))
    if rendered is None:
        raise SpecError(
            "the spec has a path, and every host runs a pinned image: the path's published files are "
            "fetched and carried only by hosts built from base, so build the path's hosts from base "
            "or leave the path out"
        )
    return load(spec, found, rendered / "atomics")


# The executor


def exec_argv(container: str, step: Step, tag: str, argv: tuple[str, ...]) -> list[str]:
    """The docker exec command line of a step's test: its account, folder and environment, then the vector as is."""

    return [
        "docker",
        "exec",
        "--user",
        step.account,
        "--workdir",
        step.workdir,
        "--env",
        f"HOME={home(step.account)}",
        "--env",
        f"USER={step.account}",
        "--env",
        f"LOGNAME={step.account}",
        "--env",
        f"BLUEFIRE_TAG={tag}",
        container,
        *argv,
    ]


def kill_script(tag: str) -> str:
    """Bash that kills every process whose environment holds BLUEFIRE_TAG=<tag>, until none is left.

    It uses bash builtins, so that it starts no program besides sleep between rounds.
    """

    return (
        f"want={shlex.quote('BLUEFIRE_TAG=' + tag)}; total=0; "
        "for round in 1 2 3 4 5 6 7 8 9 10; do found=0; "
        'for d in /proc/[0-9]*; do pid=${d#/proc/}; [ "$pid" = "$$" ] && continue; '
        'while IFS= read -r -d "" v; do if [ "$v" = "$want" ]; then '
        'kill -9 "$pid" 2>/dev/null && found=$((found+1)); break; fi; done 2>/dev/null < "$d/environ"; done; '
        "total=$((total+found)); [ $found -eq 0 ] && break; sleep 0.2; done; "
        'echo "killed $total"'
    )


def docker_error(code: int | None, stderr: str) -> bool:
    """True when Docker or the container runtime could not start the command (exit 125 to 127 with its error)."""

    return code in (125, 126, 127) and any(marker in stderr for marker in DOCKER_ERRORS)


def happened(
    prereq_passed: bool, exit_code: int | None, stderr: str, check: str | None, stopped: bool
) -> tuple[str, str]:
    """What happened in a step, and why, by the design's words.

    `check` is the effect check's result: "pass", "fail", "error", or None when
    it did not run. `blocked` cannot occur: range one configures no active
    response.
    """

    if stopped:
        return INCONCLUSIVE, "the run was stopped during the step"
    if not prereq_passed:
        return NOT_ATTEMPTED, "the published prerequisite check did not pass"
    if docker_error(exit_code, stderr):
        return NOT_ATTEMPTED, "Docker could not start the test"
    if check == "pass":
        return TOOK_EFFECT, "the effect check passed"
    if check == "fail":
        return NO_EFFECT, "the test ran and the effect check failed"
    return INCONCLUSIVE, "the effect check itself could not be run"


def fill(text: str, addresses: dict[str, dict[str, str]]) -> str:
    """Put each host's address in each {ip:<host>@<network>}."""

    def one(match: re.Match) -> str:
        found = (addresses.get(match.group(1)) or {}).get(match.group(2))
        if not found:
            raise KeyError(f"no address of {match.group(1)} on {match.group(2)}")
        return found

    return IP_FILL.sub(one, text)


def iso(nanoseconds: int | None) -> str | None:
    if nanoseconds is None:
        return None
    seconds, rest = divmod(int(nanoseconds), 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{rest // 1000:06d}Z"


def out_of_order(record: dict | None) -> bool:
    """True when the daemon stamped an exec's exec_die before its exec_start, as a loaded daemon can."""

    if not record or record.get("start") is None or record.get("die") is None:
        return False
    return record["die"] < record["start"]


def daemon_times(record: dict | None) -> dict:
    """A step's start and end from the daemon's exec_start and exec_die of its exec, as recorded by the watch.

    They are used only when they are in order: with an end before the start
    there are none, and the step is timed by the engine's clock.
    """

    if not record or record.get("start") is None or record.get("die") is None or out_of_order(record):
        return {}
    code = record.get("exit_code")
    return {
        "started_ns": record["start"],
        "ended_ns": record["die"],
        "seconds": round((record["die"] - record["start"]) / 1e9, 3),
        "daemon_exit_code": int(code) if code not in (None, "") else None,
        "exec_id": record.get("exec_id"),
        "time_source": "daemon",
    }


def _member(archive: bytes, name: str) -> bytes | None:
    """A regular file of a gzip tar archive, by its name as tar lists it."""

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as opened:
        for member in opened.getmembers():
            if (
                member.name.rstrip("/") == name.rstrip("/")
                and member.isreg()
                and member.size <= LARGEST_MEMBER
            ):
                return opened.extractfile(member).read()
    return None


def goal_check(uploads: Path, source: str, contains: str, inner: str, expected: bytes | None) -> dict:
    """The goal, on copied files: the first upload came from `source`, is a gzip tar archive that holds the member
    `contains`, itself a gzip tar archive whose member `inner` is byte for byte `expected`."""

    observed: dict = {}

    def result(passed: bool, why: str) -> dict:
        return {"passed": passed, "why": why, "observed": observed}

    index = uploads / "index.tsv"
    if not index.is_file():
        return result(False, "the stand-in internet stored no upload")
    lines = index.read_text(encoding="utf-8", errors="replace").splitlines()
    fields = lines[0].split() if lines else []
    if len(fields) != 4:
        return result(False, "the first line of index.tsv is not '<n> <peer> <sha256> <size>'")
    number, peer, digest, size = fields
    observed.update({"upload": number, "from": peer, "sha256": digest, "size": size})
    if peer != source:
        return result(False, f"the first upload came from {peer}, not {source}")
    stored = uploads / f"{number}.bin"
    if not stored.is_file() or hashlib.sha256(stored.read_bytes()).hexdigest() != digest:
        return result(False, f"{number}.bin is missing or does not have the SHA-256 in index.tsv")
    if expected is None:
        return result(False, "the file to compare with was not copied out")
    try:
        outer = _member(stored.read_bytes(), contains)
        observed["contains"] = outer is not None
        if outer is None:
            return result(False, f"the upload holds no {contains}")
        found = _member(outer, inner)
    except (tarfile.TarError, OSError, EOFError) as error:
        return result(False, f"an archive could not be read: {error}"[:300])
    observed["inner"] = found is not None
    if found is None:
        return result(False, f"{contains} holds no {inner}")
    observed["inner_sha256"] = hashlib.sha256(found).hexdigest()
    if found != expected:
        return result(False, f"{inner} in the upload differs from the file on the host")
    return result(True, f"{inner} in the first upload is byte for byte the file on the host")


def summary(manifest: dict) -> str:
    """The path as Markdown, for a CI job's summary."""

    found = manifest.get("path") or {}
    steps = found.get("steps") or []
    lines = [f"### Path of {manifest.get('range')}", ""]
    if found.get("skipped"):
        lines += [f"Not run: {found['skipped']}", ""]
    if found.get("stopped"):
        lines += [f"Stopped: {found['stopped']}", ""]
    if steps:
        lines += [
            "| Step | Host | Technique | Test | Seconds | Exit code | What happened | The check |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for step in steps:
            seconds = step.get("seconds")
            if seconds is not None and step.get("time_source") != "daemon":
                seconds = f"{seconds} (engine clock)"
            check = (step.get("check") or {}).get("result") or "not run"
            timeout = " (stopped by its timeout)" if step.get("stopped_by_timeout") else ""
            lines.append(
                f"| {step['id']} | {step['host']} | {step['technique']} | {step['name']} | "
                f"{'' if seconds is None else seconds} | {'' if step.get('exit_code') is None else step['exit_code']} | "
                f"{step['happened']}{timeout} | {check} |"
            )
        tests = {step.get("guid") for step in steps}
        lines += ["", f"{count(len(steps), 'step')}, which ran {count(len(tests), 'published test')}.", ""]
    goal = found.get("goal")
    if goal:
        state = (
            "passed" if goal.get("passed") else ("not checked" if goal.get("passed") is None else "failed")
        )
        lines += [f"Goal, {goal.get('plain')}: {state}. {goal.get('why') or ''}".rstrip(), ""]
    first = next((step for step in steps if step.get("seconds") is not None), None)
    if first:
        lines += [f"The first step, {first['id']}, took {first['seconds']} s.", ""]
    lines += [
        "Times are the Docker daemon's times of each test's exec_start and exec_die; a time marked "
        "(engine clock) is the engine's own, used only when those events were not matched or the end came "
        "before the start. "
        "No step can be blocked here: the range configures no active response.",
        "",
    ]
    return "\n".join(lines)


class Executor:
    """Runs a plan's steps in a sealed range through the engine `run` (an `engine.Run`), and records them.

    It uses the engine's sealed containers, its event watch, its own commands
    (`execute`) for checks and kills, and `copy_out` for the goal's files.
    """

    def __init__(self, run, plan: Plan, addresses: dict[str, dict[str, str]]):
        self.run = run
        self.plan = plan
        self.addresses = addresses
        self.claimed: set[str] = set()
        # Why the watch is taken to be blind: it did not report a step's own exec in time.
        self.blind: str | None = None
        self.record = run.manifest["path"]
        self.folder = run.out / "raw" / "steps"

    # Helpers

    def container(self, host: str) -> str:
        identifier = self.run.containers.get(host)
        if identifier is None or identifier not in self.run.watch.containers:
            raise RuntimeError(f"{host} is not a container of the sealed range: the path runs only there")
        return identifier

    def stop_reason(self) -> str | None:
        """Why the path must stop now: a finding of the event watch, a watch that no longer runs, or one
        that did not report the start and end of a step's own command in time."""

        watch = self.run.watch
        with watch.lock:
            if watch.findings:
                return "an event on the range that the engine did not cause: see seal.json"
            if not watch.alive:
                return "the event watch on the range stopped, so nothing watched the seal: see seal.json"
        return self.blind

    def stopped(self) -> bool:
        return self.stop_reason() is not None

    def announce(self, identifier: str, argv: list[str] | tuple[str, ...]) -> None:
        action = " ".join(argv)
        self.run.watch.expect("container", f"exec_create: {action}", id=identifier)
        self.run.watch.expect("container", f"exec_start: {action}", id=identifier)
        self.run.watch.expect("container", "exec_die", id=identifier)

    def events_of(self, identifier: str, argv: tuple[str, ...]) -> dict | None:
        """The daemon's exec_start and exec_die of the command, waited for a little after it returned,
        and for the watch's time to settle more when they are late."""

        command = " ".join(argv)
        deadline = time.monotonic() + EVENT_SECONDS + WATCH_SECONDS
        while True:
            found = self.run.watch.exec_of(identifier, command, self.claimed)
            if found and found.get("die") is not None:
                self.claimed.add(found["exec_id"])
                return found
            if time.monotonic() > deadline:
                if found:
                    self.claimed.add(found["exec_id"])
                return found
            time.sleep(POLL_SECONDS)

    def exec(
        self, step: Step, tag: str, argv: tuple[str, ...], timeout: float, folder: Path, name: str
    ) -> dict:
        """Run one of a step's published commands as the step's account; stdout and stderr go to files."""

        identifier = self.container(step.host)
        command = exec_argv(identifier, step, tag, argv)
        out_path, err_path = folder / f"{name}.stdout", folder / f"{name}.stderr"
        self.announce(identifier, argv)
        engine_start = time.time_ns()
        timed_out = stopped = False
        with out_path.open("wb") as out, err_path.open("wb") as err:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if self.stopped():
                        stopped = True
                        break
                    if time.monotonic() > deadline:
                        timed_out = True
                        break
                    time.sleep(POLL_SECONDS)
            except BaseException:
                self.kill(identifier, step.account, tag, process)
                raise
            if timed_out or stopped:
                self.kill(identifier, step.account, tag, process)
        engine_end = time.time_ns()
        stderr = err_path.read_text(encoding="utf-8", errors="replace")
        found = {
            "command": command,
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "stopped": stopped,
            "stdout_file": out_path.name,
            "stderr_file": err_path.name,
            "stderr": stderr,
            "engine_started_ns": engine_start,
            "engine_ended_ns": engine_end,
        }
        events = self.events_of(identifier, argv)
        # The watch must report the command's own start and end: that shows it still reads Docker's events.
        if (events is None or events.get("die") is None) and self.blind is None:
            self.blind = (
                f"the event watch did not report the {'end' if events else 'start'} of the exec of {name} on "
                f"{step.host} within {EVENT_SECONDS + WATCH_SECONDS} s, so nothing watched the seal during "
                "that step"
            )
        found["stopped"] = stopped or self.stopped()
        found.update(daemon_times(events))
        if "started_ns" not in found:
            why = (
                "the daemon's exec_die came before its exec_start"
                if out_of_order(events)
                else "the daemon's exec events were not matched"
            )
            found.update(
                {
                    "started_ns": engine_start,
                    "ended_ns": engine_end,
                    "seconds": round((engine_end - engine_start) / 1e9, 3),
                    "time_source": f"engine clock ({why})",
                }
            )
        return found

    def kill(self, identifier: str, account: str, tag: str, process: subprocess.Popen) -> None:
        """Kill every process of the step in its container (tag engine:kill), then the docker client if need be.

        The kill runs as the step's own account: a container's root has no
        CAP_SYS_PTRACE, so it cannot read the environment of another account's
        processes, and a kill as root finds none of them.
        """

        entry: dict = {"tag": tag, "account": account}
        self.record.setdefault("kills", []).append(entry)
        try:
            done = self.run.execute(identifier, kill_script(tag), KILL_SECONDS, "engine:kill", account)
            entry["output"] = done.stdout.strip()[-200:]
        except RuntimeError as error:
            entry["error"] = str(error)[:300]
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # The exec did not end: what the step started may still run in the container.
            entry["docker client killed"] = True
            process.kill()
            process.wait()

    def evaluate(self, check: Check, step: Step, stdout: str) -> tuple[str, list[dict]]:
        """Run the effect check: ("pass" | "fail" | "error", what each part ran and saw)."""

        tag = f"engine:check:{step.id}"
        if check.kind == "output":
            return ("pass" if check.text in stdout else "fail"), [
                {
                    "kind": "output_contains",
                    "text": check.text,
                    "result": "pass" if check.text in stdout else "fail",
                }
            ]
        if check.kind == "all":
            results, parts = [], []
            for part in check.parts:
                result, seen = self.evaluate(part, step, stdout)
                results.append(result)
                parts += seen
            overall = "fail" if "fail" in results else ("error" if "error" in results else "pass")
            return overall, parts
        if check.kind == "run":
            return self.root(check.host, check.run, tag)
        # upload
        assert check.of is not None
        first, seen = self.root(
            self.plan.upload_host, f"head -n 1 {build.INET_UPLOADS}/index.tsv", tag, raw=True
        )
        host, path = check.of
        digest, more = self.root(host, f"sha256sum {shlex.quote(path)}", tag, raw=True)
        seen += more
        if "error" in (first, digest):
            return "error", seen
        try:
            source = fill(check.source, self.addresses)
        except KeyError as error:
            seen.append({"kind": "upload", "error": str(error)})
            return "error", seen
        fields = seen[0]["stdout"].split()
        wanted = seen[1]["stdout"].split()[:1]
        good = len(fields) == 4 and fields[1] == source and wanted == [fields[2]]
        seen.append(
            {
                "kind": "upload",
                "first upload": fields,
                "from": source,
                "sha256 on the host": wanted,
                "result": "pass" if good else "fail",
            }
        )
        return ("pass" if good else "fail"), seen

    def root(self, host: str, script: str, tag: str, raw: bool = False) -> tuple[str, list[dict]]:
        """A command of the check, as root. Exit 0 passes, another exit fails; a command that could not run errs.

        With `raw`, any exit that is not an error counts as "pass": the caller judges the output.
        """

        entry: dict = {"kind": "run", "host": host}
        try:
            command = fill(script, self.addresses)
        except KeyError as error:
            entry["error"] = str(error)
            return "error", [entry]
        entry["command"] = command
        try:
            done = self.run.execute(self.container(host), command, CHECK_SECONDS, tag)
        except RuntimeError as error:
            entry["error"] = str(error)[:300]
            entry["result"] = "error"
            return "error", [entry]
        entry.update(
            {"exit_code": done.returncode, "stdout": done.stdout[-4000:], "stderr": done.stderr[-2000:]}
        )
        if docker_error(done.returncode, done.stderr):
            entry["result"] = "error"
        elif raw:
            entry["result"] = "pass"
        else:
            entry["result"] = "pass" if done.returncode == 0 else "fail"
        return entry["result"], [entry]

    def undo(self, step: Step, record: dict) -> None:
        """The published cleanup, with tag cleanup:<id>, as the step's account."""

        folder = self.folder / step.id
        assert step.undo is not None
        found = self.exec(step, f"cleanup:{step.id}", step.undo, CLEANUP_SECONDS, folder, "cleanup")
        record["cleanup_run"] = {
            key: found.get(key) for key in ("exit_code", "timed_out", "time_source", "started_ns", "ended_ns")
        }
        record["cleanup_run"]["started"] = iso(found.get("started_ns"))
        record["cleanup_run"]["ended"] = iso(found.get("ended_ns"))
        text = [
            f"command: {shlex.join(found['command'])}",
            f"exit code: {found['exit_code']}",
            f"time source: {found.get('time_source')}",
            "stdout:",
            (folder / "cleanup.stdout").read_text(encoding="utf-8", errors="replace"),
            "stderr:",
            found["stderr"],
        ]
        (folder / "cleanup.txt").write_text("\n".join(text), encoding="utf-8")
        (folder / "cleanup.stdout").unlink(missing_ok=True)
        (folder / "cleanup.stderr").unlink(missing_ok=True)
        self.run.write()

    # The path

    def step(self, step: Step) -> dict:
        folder = self.folder / step.id
        folder.mkdir(parents=True, exist_ok=True)
        identifier = self.container(step.host)
        record: dict = {
            "id": step.id,
            "host": step.host,
            "to": list(step.to),
            "account": step.account,
            "workdir": step.workdir,
            "technique": step.technique,
            "guid": step.guid,
            "name": step.name,
            "plain": step.plain,
            "args": step.args,
            "timeout": step.timeout,
            "cleanup": step.cleanup,
            "expect": list(step.expect),
            "argv": list(step.attack),
            "handled": iso(time.time_ns()),
            "happened": INCONCLUSIVE,
            "why": "the step had not ended",
        }
        self.record["steps"].append(record)
        (folder / "command").write_text(
            shlex.join(exec_argv(identifier, step, f"step:{step.id}", step.attack)) + "\n"
        )
        stopped = False
        try:
            prereq_passed, notes = True, []
            for number, argv in enumerate(step.prereqs, start=1):
                found = self.exec(step, f"engine:prereq:{step.id}", argv, PREREQ_SECONDS, folder, "prereq")
                stdout = (folder / "prereq.stdout").read_text(encoding="utf-8", errors="replace")
                notes += [
                    f"prerequisite {number}: {shlex.join(found['command'])}",
                    f"exit code: {found['exit_code']}",
                    "stdout:",
                    stdout,
                    "stderr:",
                    found["stderr"],
                ]
                stopped |= found["stopped"]
                if found["exit_code"] != 0 or found["timed_out"] or found["stopped"]:
                    prereq_passed = False
                    break
            (folder / "prereq.txt").write_text(
                "\n".join(notes) if notes else "The published test has no prerequisite check.\n",
                encoding="utf-8",
            )
            (folder / "prereq.stdout").unlink(missing_ok=True)
            (folder / "prereq.stderr").unlink(missing_ok=True)
            record["prereq_passed"] = prereq_passed
            check_result = None
            stdout_text, stderr_text, code = "", "", None
            if prereq_passed and not stopped:
                found = self.exec(step, f"step:{step.id}", step.attack, step.timeout, folder, "attack")
                (folder / "attack.stdout").replace(folder / "stdout")
                (folder / "attack.stderr").replace(folder / "stderr")
                stdout_text = (folder / "stdout").read_text(encoding="utf-8", errors="replace")
                stderr_text, code = found["stderr"], found["exit_code"]
                stopped = found["stopped"]
                record.update(
                    {
                        "exit_code": code,
                        "stopped_by_timeout": found["timed_out"],
                        "started_ns": found["started_ns"],
                        "ended_ns": found["ended_ns"],
                        "started": iso(found["started_ns"]),
                        "ended": iso(found["ended_ns"]),
                        "seconds": found["seconds"],
                        "time_source": found["time_source"],
                    }
                )
                if found.get("daemon_exit_code") is not None:
                    record["daemon_exit_code"] = found["daemon_exit_code"]
                if not stopped and not docker_error(code, stderr_text):
                    time.sleep(GRACE_SECONDS)
                    if self.stopped():
                        stopped = True
                    else:
                        check_result, seen = self.evaluate(step.check, step, stdout_text)
                        record["check"] = {"result": check_result, "parts": seen}
                        (folder / "check.txt").write_text(json.dumps(record["check"], indent=2) + "\n")
            else:
                (folder / "stdout").write_text("")
                (folder / "stderr").write_text("")
            record["happened"], record["why"] = happened(
                prereq_passed, code, stderr_text, check_result, stopped
            )
            if "check" not in record:
                (folder / "check.txt").write_text("The check did not run: " + record["why"] + "\n")
            self.run.write()
            attempted = record["happened"] in (TOOK_EFFECT, NO_EFFECT) or (
                record["happened"] == INCONCLUSIVE and code is not None
            )
            if step.cleanup == "after_check" and attempted and not stopped:
                self.undo(step, record)
            elif step.cleanup == "none":
                (folder / "cleanup.txt").write_text(
                    "cleanup: none. The published test has none, or the spec runs none.\n"
                )
        except BaseException:
            record["happened"], record["why"] = INCONCLUSIVE, "the run was stopped during the step"
            self.run.write()
            raise
        if stopped:
            self.record["stopped"] = self.stop_reason() or "the run was stopped during the step"
        self.run.write()
        return record

    def goal(self) -> dict:
        goal = self.plan.goal
        assert goal is not None
        result: dict = {"plain": goal.plain, "after": goal.after, "passed": None}
        self.record["goal"] = result
        try:
            source = fill(goal.source, self.addresses)
        except KeyError as error:
            result.update({"passed": False, "why": str(error)})
            return result
        uploads = self.run.copy_out(self.plan.upload_host, build.INET_UPLOADS)
        host, path = goal.equals
        copied = self.run.copy_out(host, path)
        result["copied"] = {
            f"{self.plan.upload_host}:{build.INET_UPLOADS}": uploads,
            f"{host}:{path}": copied,
        }
        raw = self.run.out / "raw" / "hosts"
        expected_file = raw / host / path.lstrip("/")
        expected = expected_file.read_bytes() if copied.get("copied") and expected_file.is_file() else None
        found = goal_check(
            raw / self.plan.upload_host / build.INET_UPLOADS.lstrip("/"),
            source,
            goal.contains,
            goal.inner,
            expected,
        )
        result.update(found)
        result["check"] = {
            "from": source,
            "contains": goal.contains,
            "inner": goal.inner,
            "equals": f"{host}:{path}",
        }
        self.run.write()
        return result

    def run_path(self) -> None:
        if not sealed(self.run.phases):
            raise RuntimeError("the path runs only once the seal's phases before it have passed")
        self.folder.mkdir(parents=True, exist_ok=True)
        for step in self.plan.steps:
            reason = self.stop_reason()
            if reason:
                self.record["stopped"] = reason
                break
            self.step(step)
            if self.record.get("stopped"):
                break
        if self.plan.goal and not self.record.get("stopped"):
            self.goal()
        for step in self.plan.steps:
            if step.cleanup != "after_path" or self.stopped():
                continue
            record = next((r for r in self.record["steps"] if r["id"] == step.id), None)
            if record and record.get("exit_code") is not None and record["happened"] != NOT_ATTEMPTED:
                self.undo(step, record)
        self.run.write()


NOTES = [
    "Each test runs through docker exec as the step's account: its parent is the container runtime, not a login "
    "shell, and no step runs inside the session of an earlier one.",
    "A step's start and end are the Docker daemon's times of its exec_start and exec_die events, when they are "
    "in order; otherwise the engine's, and the step's time_source says so.",
    "blocked cannot occur: the range configures no active response.",
    "An effect check that exits nonzero counts as no effect, also when it could not find the file it reads; "
    "only a check that could not be run at all makes a step inconclusive.",
]
# The seal's phases that must have passed before the first step starts.
BEFORE_PATH = ("static", "no way out", "segmentation")


def sealed(phases: list[dict]) -> bool:
    """True when each phase of the seal before the path was judged and passed, and none failed."""

    names = {phase["phase"] for phase in phases}
    return all(name in names for name in BEFORE_PATH) and all(phase["passed"] for phase in phases)

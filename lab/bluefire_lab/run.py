"""Run the pinned tests on the lab target, one at a time, and record what was done.

The target is the machine this runs on: a disposable CI runner, never a
developer machine. Each step (a marker, a test, a cleanup) runs in a kernel
audit session of its own, so that the sensor's records can be tied to the step
that caused them even when a process detaches from its parent.
"""

from __future__ import annotations

import csv
import io
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import auditd, evaluate, sysmon, target

# Run as root by sh: write the login uid, which makes the kernel start a new
# audit session, print that session's id on a line of its own, then become the
# command. The id is read with a builtin, so no extra process joins the session.
SESSION_SHIM = (
    'echo "$1" > /proc/self/loginuid || exit 125; '
    'read -r session < /proc/self/sessionid; echo "$session"; shift; exec "$@"'
)
KEPT_OUTPUT = 20000
# auditd's log, and the file the driver writes until auditd has recorded the write.
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_PROBE = "/var/tmp/bluefire-lab-audit-probe"
# A Sysmon configuration that records no event: for a run whose given sensor settings are
# audit rules only, so that Sysmon's records are not counted under settings that have none.
SYSMON_NOTHING = """<Sysmon schemaversion="4.81">
  <EventFiltering>
    <ProcessCreate onmatch="include"/>
    <NetworkConnect onmatch="include"/>
    <ProcessTerminate onmatch="include"/>
    <FileCreate onmatch="include"/>
    <FileDelete onmatch="include"/>
  </EventFiltering>
</Sysmon>
"""
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
GUID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def output_of(*command: str) -> str:
    done = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
    return done.stdout.strip()


def step(
    label: str, user: str, command: list[str], timeout: float = 60, container: str | None = None
) -> dict:
    """Run a command as a user in a new audit session and return what happened. With a
    container, the command runs inside it: the same account there has the same id, and the
    process writes its own login uid, which needs no privilege while none is set."""

    uid = str(pwd.getpwnam(user).pw_uid)
    wrapped = ["sudo", "sh", "-c", SESSION_SHIM, "sh", uid, "sudo", "-u", user, "-H", "--", *command]
    if container:
        home = "/root" if user == "root" else pwd.getpwnam(user).pw_dir
        # PowerShell, which the executor runs in, needs no ICU data in this mode.
        environment = ["--env", f"HOME={home}", "--env", "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1"]
        inside = ["sh", "-c", SESSION_SHIM, "sh", uid, *command]
        wrapped = [
            "sudo",
            "docker",
            "exec",
            "--user",
            user,
            *environment,
            "--workdir",
            "/",
            container,
            *inside,
        ]
    started = time.monotonic()
    try:
        done = subprocess.run(
            wrapped,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        status, out, err, timed_out = done.returncode, done.stdout, done.stderr, False
    except subprocess.TimeoutExpired as late:
        out = late.stdout.decode(errors="replace") if isinstance(late.stdout, bytes) else late.stdout or ""
        err = late.stderr.decode(errors="replace") if isinstance(late.stderr, bytes) else late.stderr or ""
        status, timed_out = None, True
    session, _, out = out.partition("\n")
    return {
        "label": label,
        "user": user,
        "command": command,
        "session": session.strip(),
        "exit_status": status,
        "timed_out": timed_out,
        "seconds": round(time.monotonic() - started, 1),
        "output": out[-KEPT_OUTPUT:],
        "error": err[-KEPT_OUTPUT:],
    }


def kill_sessions(sessions: set[str]) -> None:
    """Kill whatever is still running in the given audit sessions.

    Only sessions the driver opened are given here. The runner itself runs in no
    session, so that value is refused: it would kill the job.
    """

    sessions = {session for session in sessions if session.isdigit() and session != sysmon.NO_SESSION}
    left = []
    for process in Path("/proc").iterdir():
        try:
            if process.name.isdigit() and (process / "sessionid").read_text().strip() in sessions:
                left.append(process.name)
        except OSError:
            continue  # the process ended while we looked
    if left:
        subprocess.run(["sudo", "kill", "-9", *left], check=False)


def quoted(text: str) -> str:
    """A PowerShell single-quoted string."""

    return "'" + str(text).replace("'", "''") + "'"


def invoke(test: dict, executor: Path, atomics: Path, *flags: str, pwsh: str = "pwsh") -> list[str]:
    """The command that has Invoke-AtomicRedTeam act on one test."""

    script = (
        f"Import-Module {quoted(executor / 'Invoke-AtomicRedTeam.psd1')} -Force; "
        f"Invoke-AtomicTest {test['technique']} -TestGuids {test['guid']} "
        f"-PathToAtomicsFolder {quoted(atomics)} " + " ".join(flags)
    )
    return [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]


def upstream_definition(spec: dict, atomics: Path) -> dict:
    """Find the pinned test in the upstream definitions and check it is the one meant."""

    technique, guid = spec["technique"], spec["guid"]
    if not TECHNIQUE.fullmatch(technique) or not GUID.fullmatch(guid):
        raise SystemExit(f"not a technique id and a test GUID: {technique} {guid}")
    path = atomics / technique / f"{technique}.yaml"
    tests = yaml.safe_load(path.read_text(encoding="utf-8"))["atomic_tests"]
    found = [test for test in tests if test.get("auto_generated_guid") == guid]
    if not found:
        raise SystemExit(f"{path} has no test with GUID {guid}")
    test = found[0]
    if test["name"] != spec["name"]:
        raise SystemExit(f"{guid} is {test['name']!r} upstream, the list calls it {spec['name']!r}")
    if "linux" not in test.get("supported_platforms", []):
        raise SystemExit(f"{guid} {test['name']!r} is not a Linux test")
    if test["executor"]["name"] not in ("sh", "bash"):
        raise SystemExit(f"{guid} {test['name']!r} needs the executor {test['executor']['name']!r}")
    # An input argument the test does not declare changes nothing: the run would use the defaults.
    unknown = sorted(set(spec.get("args") or {}) - set(test.get("input_arguments") or {}))
    if unknown:
        raise SystemExit(f"{guid} {test['name']!r} has no input argument {', '.join(unknown)}")
    if not isinstance(spec.get("shows_technique", True), bool):
        raise SystemExit(
            f"{guid} {test['name']!r}: shows_technique is true or false, with the reason in a comment"
        )
    return test


def marker(run_id: str, order: int, edge: str) -> list[str]:
    return ["/usr/bin/true", "bluefire-lab-marker", run_id, str(order), edge]


def read_execution_log(path: str, container: str | None = None) -> dict:
    """What the executor wrote about the test it ran: the process id and exit code. In a
    container the id is the one the process has there, not the one the sensors on the host
    record."""

    if container:
        text = target.docker("exec", "--user", "root", container, "cat", path).stdout
    else:
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
        except OSError:
            return {}
    rows = list(csv.DictReader(io.StringIO(text.lstrip("\ufeff"), newline="")))
    if not rows:
        return {}
    last = rows[-1]
    return {"launcher_pid": int(last["ProcessId"]), "exit_code": int(last["ExitCode"])}


def plan(document: dict) -> list[dict]:
    """The runs in order: the canary, the control, the baseline of ordinary activity, the
    tests, each test again with each of its hardening changes in place, each test again
    with each of its variants' input arguments, and the canary again."""

    defenses = document.get("defenses") or {}
    runs = [{"role": "canary", "spec": document["canary"]}, {"role": "control", "spec": document["control"]}]
    if "baseline" in document:
        for part in document["baseline"].get("parts") or [{}]:
            missing = [key for key in ("name", "as", "author", "what", "run") if key not in part]
            if missing or part["as"] not in ("root", "account"):
                raise SystemExit(
                    f"the baseline's part {part.get('name', '')!r} needs name, as (root or account), author, "
                    f"what and run: {', '.join(missing) or 'as'} is missing or wrong"
                )
        runs.append({"role": "baseline", "spec": document["baseline"]})
    tests = [{"role": "test", "spec": spec} for spec in document["tests"]]
    runs += tests
    for test in tests:
        for name in test["spec"].get("defenses", []):
            if name not in defenses:
                raise SystemExit(
                    f"{test['spec']['name']!r} names the hardening change {name!r}, which is not defined"
                )
            runs.append(
                {
                    "role": "hardened",
                    "spec": test["spec"],
                    "defense": {"name": name, **defenses[name]},
                    "of": test,
                }
            )
    for test in tests:
        for variant in test["spec"].get("variants", []):
            spec = {key: value for key, value in test["spec"].items() if key not in ("variants", "defenses")}
            runs.append({"role": "variant", "spec": {**spec, **variant}, "of": test})
    runs.append({"role": "canary", "spec": document["canary"]})
    for order, run in enumerate(runs, start=1):
        run["order"] = order
    for run in runs:
        if "of" in run:
            run["compared_with"] = run.pop("of")["order"]
    return runs


def fill(command: str, context: dict) -> str:
    return command.replace("{home}", context["home"]).replace("{account}", context["account"])


def login_accounts(passwd: str, shells: str) -> list[str]:
    """The accounts in /etc/passwd whose shell is one of the login shells /etc/shells lists.
    An empty shell field means /bin/sh."""

    login = {line.strip() for line in shells.splitlines() if line.strip() and not line.startswith("#")}
    entries = [line.split(":") for line in passwd.splitlines() if line.count(":") >= 6]
    return sorted(fields[0] for fields in entries if (fields[6] or "/bin/sh") in login)


def listening(ss: str) -> list[str]:
    """The protocol and local address of each socket in what "ss -H -tuln" printed."""

    return sorted(
        {f"{line.split()[0]} {line.split()[4]}" for line in ss.splitlines() if len(line.split()) > 4}
    )


def running_services(units: str) -> list[str]:
    """The service names in what "systemctl list-units --type=service --state=running" printed."""

    return sorted(line.split()[0] for line in units.splitlines() if line.strip())


def requirements() -> None:
    """Stop with the reason when the target lacks a program the lab itself needs: systemctl
    and ss for the inventory and the sensors. A test that needs one of them is therefore
    never left out on a target the lab runs on."""

    missing = [program for program in ("systemctl", "ss") if not shutil.which(program)]
    if missing:
        raise SystemExit(f"the lab needs {', '.join(missing)} on the target")


def inventory(programs: set[str]) -> dict:
    """What the target is, read before the sensors start: the accounts that can log in, the
    running services, the listening addresses, and where each program the tests need is."""

    units = output_of(
        "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"
    )
    return {
        "accounts": login_accounts(
            Path("/etc/passwd").read_text(encoding="utf-8"), Path("/etc/shells").read_text(encoding="utf-8")
        ),
        "services": running_services(units),
        "listening": listening(output_of("ss", "-H", "-tuln")),
        "programs": {name: shutil.which(name) or "" for name in sorted(programs)},
    }


def select(document: dict, found: dict) -> tuple[dict, list[dict]]:
    """The tests the target can run, by the programs each needs and the inventory found,
    and those it cannot, with the reason, for the report's list of dropped tests."""

    kept, dropped = [], []
    for spec in document["tests"]:
        if not isinstance(spec.get("needs", []), list):
            raise SystemExit(f"{spec['name']}: needs is a list of programs, as in needs: [crontab]")
        missing = [program for program in spec.get("needs", []) if not found["programs"].get(program)]
        if missing:
            reason = f"the target has no {', '.join(missing)}, which the test needs"
            dropped.append({"technique": spec["technique"], "name": spec["name"], "reason": reason})
        else:
            kept.append(spec)
    return {**document, "tests": kept}, dropped


def runs_for(document: dict, found: dict) -> tuple[list[dict], list[dict]]:
    """The runs the target can take, and every test left out with the reason: those the list
    leaves out by hand, then those whose program the target lacks, with their hardened runs
    and variants."""

    kept, unfit = select(document, found)
    return plan(kept), (document.get("dropped") or []) + unfit


def run_baseline(item: dict, context: dict) -> dict:
    """Run the ordinary activity the lab's own rules must stay quiet on: each part as root or
    as the test account, in an audit session of its own, between two markers. The record says
    for each part who wrote what it runs, and whether it ran to its end."""

    spec, run_id, account = item["spec"], context["id"], context["account"]
    record = {"order": item["order"], "role": "baseline", "name": spec["name"], "parts": [], "steps": []}
    record["steps"].append(step("marker-start", account, marker(run_id, item["order"], "start")))
    for part in spec["parts"]:
        user = account if part["as"] == "account" else "root"
        command = ["sh", "-c", fill(part["run"], context)]
        done = step(f"baseline-{part['name']}", user, command, float(part.get("timeout", 300)))
        record["steps"].append(done)
        described = {key: part[key] for key in ("name", "what", "author")}
        record["parts"].append({**described, "session": done["session"], "exit_status": done["exit_status"]})
    record["steps"].append(step("marker-end", account, marker(run_id, item["order"], "end")))
    kill_sessions({done["session"] for done in record["steps"]})
    return record


def run_test(item: dict, context: dict) -> dict:
    """Take one test through preparation, an optional hardening change, the attack step,
    the effect check and cleanup, and remove the change again. The effect check also runs
    before the test, where it must find nothing, and what the test leaves is looked for
    again after its cleanup."""

    order, role, spec = item["order"], item["role"], item["spec"]
    executor, atomics, account, run_id = (context[key] for key in ("executor", "atomics", "account", "id"))
    upstream = upstream_definition(spec, atomics)
    elevated = bool(upstream["executor"].get("elevation_required"))
    user = "root" if elevated else account
    limit = int(spec.get("timeout", 120))
    record: dict = {
        "order": order,
        "role": role,
        "technique": spec["technique"],
        "guid": spec["guid"],
        "name": spec["name"],
        "executor": upstream["executor"]["name"],
        "elevated": elevated,
        "user": user,
        "upstream_cleanup": bool(upstream["executor"].get("cleanup_command")),
        "steps": [],
    }
    for key in ("rule", "effect", "output", "prepare", "args", "dwell", "shows_technique"):
        if key in spec:
            record[key] = spec[key]
    if "effect" in spec:
        record["effect"] = fill(spec["effect"], context)  # as it ran, so that the report shows it so
    # What is looked for again after the cleanup: what the list names, or else the effect.
    if "leftover" in spec or "effect" in spec:
        record["leftover"] = fill(spec.get("leftover", spec.get("effect")), context)
    if "defense" in item:
        record["defense"] = dict(item["defense"])
        for key in ("apply", "revert"):
            record["defense"][key] = fill(record["defense"][key], context)
    if "compared_with" in item:
        record["compared_with"] = item["compared_with"]

    container = context.get("container")

    def do(label: str, command: list[str], as_user: str = user, timeout: float = 60) -> dict:
        result = step(label, as_user, command, timeout, container)
        record["steps"].append(result)
        return result

    def atomic(*flags: str) -> list[str]:
        return invoke(spec, executor, atomics, *flags, pwsh=context.get("pwsh", "pwsh"))

    arguments = []
    if spec.get("args"):
        pairs = "; ".join(f"{quoted(name)} = {quoted(value)}" for name, value in spec["args"].items())
        arguments = [f"-InputArgs @{{ {pairs} }}"]

    record["prerequisites"] = "none declared"
    if "prepare" in spec and do("prepare", ["sh", "-c", spec["prepare"]])["exit_status"] != 0:
        record["prerequisites"] = "not met"
    elif upstream.get("dependencies"):
        check = atomic("-CheckPrereqs", *arguments)
        get = atomic("-GetPrereqs", *arguments)
        met = "Prerequisites met" in do("prerequisites", check, timeout=300)["output"]
        # The test's own account fetches first, so that what it creates is its own. Root is next.
        # An image runs as it is, on a network with no way out: what it lacks is not fetched.
        for fetcher in () if container else dict.fromkeys((user, "root")):
            if not met:
                do("get-prerequisites", get, fetcher, 900)
                met = "Prerequisites met" in do("prerequisites", check, timeout=300)["output"]
        record["prerequisites"] = "met" if met else "not met"

    ready = record["prerequisites"] != "not met"
    defense = record.get("defense")
    if defense is not None and ready:
        defense["applied"] = do("defense", ["sh", "-c", defense["apply"]], "root")["exit_status"] == 0
        ready = defense["applied"]

    if ready:
        log = f"/tmp/bluefire-lab-{run_id}-{order}.csv"
        if "effect" in spec:
            # An effect that is there before the test ran is not the test's doing.
            do("effect-before", ["sh", "-c", record["effect"]], "root")
        do("marker-start", marker(run_id, order, "start"), account)
        attack = atomic(f"-TimeoutSeconds {limit}", f"-ExecutionLogPath {quoted(log)}", *arguments)
        do("attack", attack, timeout=limit + 60)
        time.sleep(float(spec.get("dwell", 0)))
        do("marker-end", marker(run_id, order, "end"), account)
        record.update(read_execution_log(log, container))
        if "effect" in spec:
            # As root, so that neither the account's rights nor a hardening change decide the check.
            do("effect", ["sh", "-c", record["effect"]], "root")
        do("cleanup", atomic("-Cleanup", *arguments), timeout=limit + 60)
        if "leftover" in record:
            do("leftover", ["sh", "-c", record["leftover"]], "root")
        record["cleanup"] = evaluate.cleanup(record)["answer"]
    if defense is not None and "applied" in defense:
        defense["reverted"] = do("revert", ["sh", "-c", defense["revert"]], "root")["exit_status"] == 0
    kill_sessions({done["session"] for done in record["steps"]} - {""})
    return record


def journal(since: float, pid: str) -> bytes:
    """What the sensor's own process wrote to the journal since the run began, byte for byte.

    The journal takes a sender's process id from the kernel, not from the
    message, so no other process can write lines that pass for the sensor's.
    """

    subprocess.run(["sudo", "journalctl", "--sync"], check=False)
    command = ["sudo", "journalctl", f"_PID={pid}", "-t", "sysmon", "--no-pager", "-o", "cat", "--all"]
    return subprocess.run([*command, f"--since=@{int(since)}"], capture_output=True, check=True).stdout


def sensor_pid() -> str:
    return output_of("systemctl", "show", "--property=MainPID", "--value", "sysmon")


def audit_log() -> bytes:
    return subprocess.run(["sudo", "cat", AUDIT_LOG], capture_output=True, check=True).stdout


def audit_rotated() -> list[str]:
    """The files auditd rotated its log into. The export reads only the current log, so any
    of them means that records may be missing from it."""

    found = subprocess.run(
        ["sudo", "find", str(Path(AUDIT_LOG).parent), "-name", "audit.log.*"], capture_output=True, text=True
    ).stdout
    return sorted(line for line in found.splitlines() if line.strip())


def audit_status() -> dict[str, str]:
    return auditd.status(subprocess.run(["sudo", "auditctl", "-s"], capture_output=True, text=True).stdout)


def wait_until_ready(context: dict, since: float) -> int | None:
    """Run a probe command until the sensor reports it, and, when auditd records too, write
    a file auditd watches until it records the write. Return the seconds it took."""

    sysmon_seen, audit_seen = False, "audit" not in context
    for second in range(1, 31):
        probe = ["/usr/bin/true", "bluefire-lab-probe", context["id"]]
        context["probes"].append(step("probe", context["account"], probe))
        if not audit_seen:
            write = ["sh", "-c", f"echo {context['id']} >> {AUDIT_PROBE}"]
            context["probes"].append(step("probe-audit", context["account"], write))
        time.sleep(1)
        context["sensor_pid"] = sensor_pid()
        if not sysmon_seen and context["sensor_pid"] not in ("", "0"):
            for line in journal(since, context["sensor_pid"]).decode("utf-8", "replace").split("\n"):
                event = sysmon.parse_line(line)
                if (
                    event
                    and event["EventID"] == sysmon.PROCESS_START
                    and event["CommandLine"] == " ".join(probe)
                ):
                    sysmon_seen = True
        audit_seen = audit_seen or f'name="{AUDIT_PROBE}"'.encode() in audit_log()
        if sysmon_seen and audit_seen:
            return second
    return None


def given_settings(folder: Path | None, out: Path) -> dict | None:
    """The sensor settings given to the run as an input, copied into the run's folder: a Sysmon
    configuration (sysmon.xml), audit rules (audit.rules), or both, each with the place it came
    from beside it (sysmon.SOURCE, audit.SOURCE). None when the folder holds neither.

    A sensor the input gives no settings for records nothing under them: Sysmon gets a
    configuration that records no event, and auditd only the lab's instrument."""

    found: dict = {"name": "given"}
    for sensor, name, copy in (
        ("sysmon", "sysmon.xml", "given-sysmon.xml"),
        ("audit", "audit.rules", "given-audit.rules"),
    ):
        path = folder / name if folder else None
        if path and path.is_file():
            source = path.with_suffix(".SOURCE")
            shutil.copyfile(path, out / copy)
            found[sensor] = copy
            found[f"{sensor}_source"] = (
                source.read_text(encoding="utf-8").strip() if source.is_file() else name
            )
    if "sysmon" not in found and "audit" not in found:
        return None
    if "sysmon" not in found:
        (out / "given-sysmon.xml").write_text(SYSMON_NOTHING, encoding="utf-8")
        found.update(
            sysmon="given-sysmon.xml", sysmon_source="none given: Sysmon records nothing under these settings"
        )
    if "audit" in found:
        # Rules that lock the audit configuration would keep the lab from loading its own again.
        locked = [
            line for line in (out / found["audit"]).read_text(encoding="utf-8", errors="replace").splitlines()
            if line.split("#")[0].split()[:2] == ["-e", "2"]
        ]  # fmt: skip
        if locked:
            raise SystemExit(
                "the given audit rules make the audit configuration immutable (-e 2): the lab cannot load "
                "its own rules again for the closing canary. Take that line out for the lab run"
            )
    return found


def apply_settings(settings: dict, out: Path, installed: bool = False) -> dict:
    """Load one set of sensor settings: Sysmon's configuration (unless Sysmon was just installed
    with it), then auditd's rules, and after those the lab's instrument rules, so that a record
    a rule of the settings would make carries that rule's key and only the others carry the
    instrument's. Returns what the record says about the change."""

    if not installed:
        loaded = subprocess.run(
            ["sudo", "sysmon", "-c", str(out / settings["sysmon"])], capture_output=True, text=True
        )
        if loaded.returncode != 0:
            said = (loaded.stdout + loaded.stderr).strip()[-600:]
            raise SystemExit(f"Sysmon refused the configuration of the {settings['name']} settings: {said}")
    subprocess.run(["sudo", "auditctl", "-D"], check=True, capture_output=True)
    if settings.get("audit"):
        loaded = subprocess.run(
            ["sudo", "auditctl", "-R", str(out / settings["audit"])], capture_output=True, text=True
        )
        if loaded.returncode != 0:
            raise SystemExit(
                f"auditd refused the audit rules of the {settings['name']} settings: {loaded.stderr.strip()[-600:]}"
            )
    subprocess.run(
        ["sudo", "auditctl", "-R", str(out / "instrument-rules.txt")], check=True, capture_output=True
    )
    listing = subprocess.run(["sudo", "auditctl", "-l"], capture_output=True, text=True).stdout
    (out / f"audit-rules-loaded-{settings['name']}.txt").write_text(listing, encoding="utf-8")
    return {"to": settings["name"], "time": now(), "audit_rules_loaded": len(listing.splitlines())}


def container_inventory(box: dict, programs: set[str]) -> dict:
    """What a container target is: the accounts that can log in, the programs running in it,
    its listening addresses, read with the host's tool in its network namespace, and where
    each program the tests need is."""

    def inside(*command: str) -> str:
        return target.docker("exec", "--user", "root", box["container"], *command).stdout

    state = target.inspect(box)[0].get("State") or {}
    running = target.docker("top", box["container"], "-eo", "comm").stdout.splitlines()[1:]
    sockets = output_of(
        "sudo", "nsenter", "--target", str(state.get("Pid", "")), "--net", "ss", "-H", "-tuln"
    )
    return {
        "accounts": login_accounts(inside("cat", "/etc/passwd"), inside("cat", "/etc/shells")),
        "services": sorted({line.strip() for line in running if line.strip()}),
        "listening": listening(sockets),
        "programs": {name: inside("sh", "-c", f"command -v {name}").strip() for name in sorted(programs)},
    }


def start_container(image: str, context: dict) -> dict:
    """Start the image as the target, with the executor and the tests read-only in it, and give
    it the test account under the id the account has on the host, so that the sensors on the
    host name it alike. Stops, with nothing left, when the image cannot take that."""

    powershell = Path(shutil.which("pwsh") or "pwsh").resolve()
    modules = Path("/usr/local/share/powershell/Modules")
    folders = [str(context["executor"]), str(context["atomics"]), str(powershell.parent)]
    box = target.start(image, context["id"], folders + ([str(modules)] if modules.is_dir() else []))
    target.close_host(box)
    uid = str(pwd.getpwnam(context["account"]).pw_uid)
    add = ("useradd", "--create-home", "--uid", uid, "--shell", "/bin/bash", context["account"])
    added = target.docker("exec", "--user", "root", box["container"], *add)
    if added.returncode != 0:
        target.close_host(box, on=False)
        target.remove()
        raise SystemExit(
            f"the image cannot take the test account: {(added.stdout + added.stderr).strip()[-300:]}"
        )
    context.update(container=box["container"], pwsh=str(powershell))
    return box


def facts(context: dict, box: dict | None = None) -> tuple[dict, dict]:
    text = Path("/etc/os-release").read_text(encoding="utf-8")
    if box:
        text = target.docker("exec", box["container"], "cat", "/etc/os-release").stdout
    release = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    image = " ".join(os.environ.get(name, "") for name in ("ImageOS", "ImageVersion")).strip()
    where = {
        "os": release.get("PRETTY_NAME", "").strip('"'),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "runner_image": image or None,
    }
    if box:
        described = target.inspect(box)[0]
        where.update(container=box["container"], image=box["image"], image_id=described.get("Image", ""))
    tools = {
        "atomic-red-team": output_of("git", "-C", str(context["atomics"]), "rev-parse", "HEAD"),
        "invoke-atomicredteam": output_of("git", "-C", str(context["executor"]), "rev-parse", "HEAD"),
        "powershell": output_of("pwsh", "--version").removeprefix("PowerShell "),
        "powershell-yaml": output_of(
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "(Get-Module -ListAvailable powershell-yaml).Version -join ' '",
        ),
        "sysmonforlinux": output_of("dpkg-query", "-W", "-f", "${Version}", "sysmonforlinux"),
        "sysinternalsebpf": output_of("dpkg-query", "-W", "-f", "${Version}", "sysinternalsebpf"),
        "auditd": output_of("dpkg-query", "-W", "-f", "${Version}", "auditd"),
        # Where the lab's own rules come from: this repository at the commit that ran.
        "lab": f"{os.environ.get('GITHUB_REPOSITORY', '')}@{os.environ.get('GITHUB_SHA', '')}",
    }
    return where, tools


def main(
    tests: Path,
    atomics: Path,
    executor: Path,
    sensor_config: Path,
    out: Path,
    account: str,
    audit_rules: Path,
    instrument: Path,
    given: Path | None = None,
    image: str | None = None,
) -> int:
    document = yaml.safe_load(tests.read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    context = {
        "id": secrets.token_hex(4),
        "account": account,
        "home": pwd.getpwnam(account).pw_dir,
        "atomics": atomics.resolve(),
        "executor": executor.resolve(),
        "probes": [],
    }
    requirements()
    # Stop before anything runs if the list names a test that is not the one upstream, a test
    # the target cannot run included.
    for item in plan(document):
        if item["role"] != "baseline":
            upstream_definition(item["spec"], context["atomics"])
    box = None
    if image:
        # An image runs the tests once, as it is: the baseline, the hardening changes and the runs
        # with changed input arguments belong to a run on the runner itself.
        document = {key: value for key, value in document.items() if key != "baseline"}
        document["tests"] = [
            {key: value for key, value in spec.items() if key not in ("defenses", "variants")}
            for spec in document["tests"]
        ]
        box = start_container(image, context)
    where, tools = facts(context, box)
    # What the target has decides which tests can run on it.
    programs = {program for spec in document["tests"] for program in spec.get("needs", [])}
    found = container_inventory(box, programs) if box else inventory(programs)
    sequence, left_out = runs_for(document, found)
    record: dict = {
        "schema": "bluefire-lab/run/1",
        "id": context["id"],
        "started": now(),
        "account": account,
        "target": where,
        "tools": tools,
        "inventory": found,
        "sensor": {"name": "Sysmon for Linux", "configuration": "sensor-config.xml"},
        "tests": [],
        "dropped": left_out,
    }
    shutil.copyfile(sensor_config, out / "sensor-config.xml")
    shutil.copyfile(instrument, out / "instrument-rules.txt")
    # auditd's rules name the account's start files, so its home is filled in first.
    (out / "audit-rules.txt").write_text(fill(audit_rules.read_text(encoding="utf-8"), context))
    own = {"name": "lab", "sysmon": "sensor-config.xml", "audit": "audit-rules.txt"}
    # The settings under test: the lab's own, unless the run was given others. The canary
    # always runs under the lab's own, which the pinned rules are known to catch it under.
    under_test = given_settings(given, out) or own
    record["settings"] = [own] if under_test is own else [own, under_test]
    record["switches"] = []
    since = time.time() - 1
    subprocess.run(
        ["sudo", "sysmon", "-accepteula", "-i", str(sensor_config)], check=True, capture_output=True
    )
    record["switches"].append({**apply_settings(own, out, installed=True), "before": 0})
    current = own
    record["audit"] = context["audit"] = {
        "rules": "audit-rules.txt",
        "instrument": "instrument-rules.txt",
        "probe": AUDIT_PROBE,
    }
    record["audit"].update(version=tools["auditd"], before=audit_status())
    record["inventory"]["sensors"] = {
        name: output_of("systemctl", "is-active", name) for name in ("sysmon", "auditd")
    }
    try:
        ready = wait_until_ready(context, since)
        record["sensor"]["ready_after_seconds"] = ready
        record["sensor"]["process_id"] = context.get("sensor_pid")
        record["probes"] = context["probes"]
        if box:
            # The container's settings and what it can reach, before the first test.
            record["leash"] = {"before": target.leash(box)}
            for made in record["leash"]["before"]["probes"]:
                print(
                    f"    {'ok     ' if made['held'] else 'WRONG  '} {made['probe']}: {made['expected']}",
                    flush=True,
                )
        if ready is None:
            record["aborted"] = "the sensor did not report a probe command within 30 seconds"
            print(record["aborted"], flush=True)
        elif box and not record["leash"]["before"]["held"]:
            wrong = record["leash"]["before"]["refused"] + [
                f"{made['probe']} {'succeeded' if made['succeeded'] else 'failed'}"
                for made in record["leash"]["before"]["probes"]
                if not made["held"]
            ]
            record["aborted"] = "the container is not held, so no test ran in it: " + "; ".join(
                wrong or ["no probe ran"]
            )
            print(record["aborted"], flush=True)
        else:
            print(f"the sensor reported a probe command after {ready} s", flush=True)
            for item in sequence:
                spec, change = item["spec"], item.get("defense", {}).get("name")
                print(
                    f"[{item['order']}/{len(sequence)}] {item['role']}: {spec.get('technique', '')} {spec['name']}"
                    + (f", with {change}" if change else "")
                    + (f", with the input arguments {spec['args']}" if item["role"] == "variant" else ""),
                    flush=True,
                )
                wanted = own if item["role"] == "canary" else under_test
                if wanted is not current:
                    try:
                        record["switches"].append({**apply_settings(wanted, out), "before": item["order"]})
                    except SystemExit as refused:
                        record["aborted"] = str(refused)
                        print(record["aborted"], flush=True)
                        break
                    current = wanted
                    time.sleep(1)
                    print(f"    sensor settings: {wanted['name']}", flush=True)
                if item["role"] == "baseline":
                    done = run_baseline(item, context)
                    record["tests"].append({**done, "settings": current["name"]})
                    print(f"    exit status: {[s['exit_status'] for s in done['steps']]}", flush=True)
                    continue
                done = {**run_test(item, context), "settings": current["name"]}
                record["tests"].append(done)
                effect = next((s["exit_status"] for s in done["steps"] if s["label"] == "effect"), "none")
                applied = f", change applied: {done['defense'].get('applied')}" if change else ""
                print(
                    f"    prerequisites: {done['prerequisites']}{applied}, exit code: {done.get('exit_code')}, "
                    f"effect check: {effect}",
                    flush=True,
                )
    finally:
        if box:
            # The same check again while the container still exists, then everything of the run goes.
            record.setdefault("leash", {})["after"] = target.leash(box)
            target.close_host(box, on=False)
            record["leash"]["left"] = target.remove()
        pid = context.get("sensor_pid") or sensor_pid()
        subprocess.run(["sudo", "systemctl", "stop", "sysmon"], check=False)
        (out / "sysmon.txt").write_bytes(journal(since, pid))
        if "audit" in record:
            record["audit"]["after"] = audit_status()
            (out / "audit.txt").write_bytes(audit_log())
            record["audit"]["rotated"] = audit_rotated()
        record["finished"] = now()
        (out / "run.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return 1 if "aborted" in record else 0

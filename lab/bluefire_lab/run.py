"""Run the pinned tests on the lab target, one at a time, and record what was done.

The target is the machine this runs on: a disposable CI runner, never a
developer machine. Each step (a marker, a test, a cleanup) runs in a kernel
audit session of its own, so that the sensor's records can be tied to the step
that caused them even when a process detaches from its parent.
"""

from __future__ import annotations

import csv
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

from . import sysmon

# Run as root by sh: write the login uid, which makes the kernel start a new
# audit session, print that session's id on a line of its own, then become the
# command. The id is read with a builtin, so no extra process joins the session.
SESSION_SHIM = (
    'echo "$1" > /proc/self/loginuid || exit 125; '
    'read -r session < /proc/self/sessionid; echo "$session"; shift; exec "$@"'
)
KEPT_OUTPUT = 20000
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
GUID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def output_of(*command: str) -> str:
    done = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
    return done.stdout.strip()


def step(label: str, user: str, command: list[str], timeout: float = 60) -> dict:
    """Run a command as a user in a new audit session and return what happened."""

    uid = str(pwd.getpwnam(user).pw_uid)
    wrapped = ["sudo", "sh", "-c", SESSION_SHIM, "sh", uid, "sudo", "-u", user, "-H", "--", *command]
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


def invoke(test: dict, executor: Path, atomics: Path, *flags: str) -> list[str]:
    """The command that has Invoke-AtomicRedTeam act on one test."""

    script = (
        f"Import-Module {quoted(executor / 'Invoke-AtomicRedTeam.psd1')} -Force; "
        f"Invoke-AtomicTest {test['technique']} -TestGuids {test['guid']} "
        f"-PathToAtomicsFolder {quoted(atomics)} " + " ".join(flags)
    )
    return ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]


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
    return test


def marker(run_id: str, order: int, edge: str) -> list[str]:
    return ["/usr/bin/true", "bluefire-lab-marker", run_id, str(order), edge]


def read_execution_log(path: str) -> dict:
    """What the executor wrote about the test it ran: the process id and exit code."""

    try:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError:
        return {}
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


def run_baseline(item: dict, context: dict) -> dict:
    """Run the ordinary activity the lab's own rules must stay quiet on, as root and as the
    test account, each in an audit session of its own, between two markers."""

    spec, run_id, account = item["spec"], context["id"], context["account"]
    record = {"order": item["order"], "role": "baseline", "name": spec["name"], "steps": []}
    record["steps"].append(step("marker-start", account, marker(run_id, item["order"], "start")))
    for label, user in (("root", "root"), ("account", account)):
        record["steps"].append(step(f"baseline-{label}", user, ["sh", "-c", fill(spec[label], context)], 300))
    record["steps"].append(step("marker-end", account, marker(run_id, item["order"], "end")))
    kill_sessions({done["session"] for done in record["steps"]})
    return record


def run_test(item: dict, context: dict) -> dict:
    """Take one test through preparation, an optional hardening change, the attack step,
    the effect check and cleanup, and remove the change again."""

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
        "steps": [],
    }
    for key in ("rule", "effect", "output", "prepare", "args", "dwell"):
        if key in spec:
            record[key] = spec[key]
    if "effect" in spec:
        record["effect"] = fill(spec["effect"], context)  # as it ran, so that the report shows it so
    if "defense" in item:
        record["defense"] = dict(item["defense"])
        for key in ("apply", "revert"):
            record["defense"][key] = fill(record["defense"][key], context)
    if "compared_with" in item:
        record["compared_with"] = item["compared_with"]

    def do(label: str, command: list[str], as_user: str = user, timeout: float = 60) -> dict:
        result = step(label, as_user, command, timeout)
        record["steps"].append(result)
        return result

    arguments = []
    if spec.get("args"):
        pairs = "; ".join(f"{quoted(name)} = {quoted(value)}" for name, value in spec["args"].items())
        arguments = [f"-InputArgs @{{ {pairs} }}"]

    record["prerequisites"] = "none declared"
    if "prepare" in spec and do("prepare", ["sh", "-c", spec["prepare"]])["exit_status"] != 0:
        record["prerequisites"] = "not met"
    elif upstream.get("dependencies"):
        check = invoke(spec, executor, atomics, "-CheckPrereqs", *arguments)
        get = invoke(spec, executor, atomics, "-GetPrereqs", *arguments)
        met = "Prerequisites met" in do("prerequisites", check, timeout=300)["output"]
        # The test's own account fetches first, so that what it creates is its own. Root is next.
        for fetcher in dict.fromkeys((user, "root")):
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
        do("marker-start", marker(run_id, order, "start"), account)
        attack = invoke(
            spec,
            executor,
            atomics,
            f"-TimeoutSeconds {limit}",
            f"-ExecutionLogPath {quoted(log)}",
            *arguments,
        )
        do("attack", attack, timeout=limit + 60)
        time.sleep(float(spec.get("dwell", 0)))
        do("marker-end", marker(run_id, order, "end"), account)
        record.update(read_execution_log(log))
        if "effect" in spec:
            # As root, so that neither the account's rights nor a hardening change decide the check.
            do("effect", ["sh", "-c", record["effect"]], "root")
        do("cleanup", invoke(spec, executor, atomics, "-Cleanup", *arguments), timeout=limit + 60)
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


def wait_until_ready(context: dict, since: float) -> int | None:
    """Run a probe command until the sensor reports it. Return the seconds it took."""

    for second in range(1, 31):
        probe = ["/usr/bin/true", "bluefire-lab-probe", context["id"]]
        context["probes"].append(step("probe", context["account"], probe))
        time.sleep(1)
        context["sensor_pid"] = sensor_pid()
        if context["sensor_pid"] in ("", "0"):
            continue
        for line in journal(since, context["sensor_pid"]).decode("utf-8", "replace").split("\n"):
            event = sysmon.parse_line(line)
            if event and event["EventID"] == sysmon.PROCESS_START and event["CommandLine"] == " ".join(probe):
                return second
    return None


def facts(context: dict) -> tuple[dict, dict]:
    release = dict(
        line.rstrip("\n").split("=", 1) for line in open("/etc/os-release", encoding="utf-8") if "=" in line
    )
    image = " ".join(os.environ.get(name, "") for name in ("ImageOS", "ImageVersion")).strip()
    target = {
        "os": release.get("PRETTY_NAME", "").strip('"'),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "runner_image": image or None,
    }
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
        # Where the lab's own rules come from: this repository at the commit that ran.
        "lab": f"{os.environ.get('GITHUB_REPOSITORY', '')}@{os.environ.get('GITHUB_SHA', '')}",
    }
    return target, tools


def main(tests: Path, atomics: Path, executor: Path, sensor_config: Path, out: Path, account: str) -> int:
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
    target, tools = facts(context)
    record: dict = {
        "schema": "bluefire-lab/run/1",
        "id": context["id"],
        "started": now(),
        "account": account,
        "target": target,
        "tools": tools,
        "sensor": {"name": "Sysmon for Linux", "configuration": "sensor-config.xml"},
        "tests": [],
        "dropped": document.get("dropped") or [],
    }
    shutil.copyfile(sensor_config, out / "sensor-config.xml")
    sequence = plan(document)
    # Stop before anything runs if the list names a test that is not the one upstream.
    for item in sequence:
        if item["role"] != "baseline":
            upstream_definition(item["spec"], context["atomics"])
    since = time.time() - 1
    subprocess.run(
        ["sudo", "sysmon", "-accepteula", "-i", str(sensor_config)], check=True, capture_output=True
    )
    try:
        ready = wait_until_ready(context, since)
        record["sensor"]["ready_after_seconds"] = ready
        record["sensor"]["process_id"] = context.get("sensor_pid")
        record["probes"] = context["probes"]
        if ready is None:
            record["aborted"] = "the sensor did not report a probe command within 30 seconds"
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
                if item["role"] == "baseline":
                    done = run_baseline(item, context)
                    record["tests"].append(done)
                    print(f"    exit status: {[s['exit_status'] for s in done['steps']]}", flush=True)
                    continue
                done = run_test(item, context)
                record["tests"].append(done)
                effect = next((s["exit_status"] for s in done["steps"] if s["label"] == "effect"), "none")
                applied = f", change applied: {done['defense'].get('applied')}" if change else ""
                print(
                    f"    prerequisites: {done['prerequisites']}{applied}, exit code: {done.get('exit_code')}, "
                    f"effect check: {effect}",
                    flush=True,
                )
    finally:
        pid = context.get("sensor_pid") or sensor_pid()
        subprocess.run(["sudo", "systemctl", "stop", "sysmon"], check=False)
        (out / "sysmon.txt").write_bytes(journal(since, pid))
        record["finished"] = now()
        (out / "run.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return 1 if "aborted" in record else 0

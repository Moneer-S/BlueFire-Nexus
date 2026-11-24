"""The seal, judged on output captured from real runs of lab/range/seal-check.yaml on Docker 29.

The fixtures are `docker inspect` and `docker network inspect` output, trimmed
to the fields the seal reads, and the output of the probe script in each
container: of a passing run, and of runs with a planted break.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from bluefire_lab.range import engine, seal
from bluefire_lab.range import spec as range_spec

FIXTURES = Path(__file__).parent / "fixtures" / "range"
SPEC = range_spec.load(Path(__file__).parents[1] / "range" / "seal-check.yaml")


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def static(objects: dict, started: bool) -> list[dict]:
    networks = {name: data["Id"] for name, data in objects["networks"].items()}
    containers = {host: data["Id"] for host, data in objects["containers"].items()}
    checks = []
    for name, data in objects["networks"].items():
        members = {host: containers[host] for host in SPEC.members(name)} if started else None
        checks += seal.network(SPEC, name, networks[name], data, members)
    for host, data in objects["containers"].items():
        checks += seal.container(SPEC, host, containers[host], data, data["Image"], networks, started)
    return checks


def failed(checks: list[dict]) -> set[str]:
    return {item["check"] for item in checks if not item["pass"]}


def test_the_static_seal_passes_on_the_created_range_and_on_the_started_range() -> None:
    assert failed(static(fixture("seal-check-created.json"), started=False)) == set()
    assert failed(static(fixture("seal-check-started.json"), started=True)) == set()


def test_after_start_a_network_must_list_exactly_its_spec_members() -> None:
    objects = fixture("seal-check-started.json")
    objects["networks"]["west"]["Containers"]["f" * 64] = {"Name": "someone-else"}

    checks = static(objects, started=True)

    assert failed(checks) == {"network: members"}


@pytest.mark.parametrize(
    ("plant", "caught_by"),
    [
        ("not-internal", {"network: internal", "network: gateway mode"}),
        ("published-port", {"container: port bindings"}),
        ("bind-mount", {"container: mounts"}),
    ],
)
def test_the_static_seal_catches_a_planted_break_before_any_container_starts(
    plant: str, caught_by: set
) -> None:
    assert failed(static(fixture(f"plant-{plant}-created.json"), started=False)) == caught_by


def test_the_static_seal_refuses_a_privileged_container_with_an_added_capability_and_the_host_network() -> (
    None
):
    objects = fixture("seal-check-created.json")
    config = objects["containers"]["left"]["HostConfig"]
    config.update(Privileged=True, CapAdd=["NET_ADMIN"], PidMode="host", SecurityOpt=["seccomp=unconfined"])
    config["NetworkMode"] = "host"

    assert failed(static(objects, started=False)) == {
        "container: privileged",
        "container: added capabilities",
        "container: namespaces",
        "container: security options",
        "container: network mode",
    }


def test_the_objects_check_fails_on_another_object_named_with_the_prefix() -> None:
    objects = fixture("seal-check-created.json")
    networks = {name: data["Id"] for name, data in objects["networks"].items()}
    containers = {host: data["Id"] for host, data in objects["containers"].items()}
    prefixed = [(i, SPEC.container_name(h)) for h, i in containers.items()]
    prefixed += [(i, SPEC.network_name(n)) for n, i in networks.items()]
    run_id = objects["containers"]["left"]["Config"]["Labels"][seal.LABEL_RUN]
    listed = (sorted(containers.values()), sorted(networks.values()))

    clean = seal.objects(SPEC, *listed, prefixed, containers, networks, run_id)
    stale = seal.objects(
        SPEC, *listed, prefixed + [("e" * 64, "bluefire-lab-sc-old")], containers, networks, run_id
    )

    assert failed(clean) == set()
    assert failed(stale) == {"objects: names"}


@pytest.mark.parametrize(
    ("code", "text", "result"),
    [
        (0, "", seal.CONNECTED),
        (124, "", seal.TIMEOUT),
        (1, "bash: connect: Network is unreachable", seal.ENETUNREACH),
        (1, "bash: connect: No route to host", seal.EHOSTUNREACH),
        (1, "bash: connect: Connection refused", seal.REFUSED),
        (127, "bash: timeout: command not found", seal.TOOL_ERROR),
        (1, "bash: /dev/tcp/x/80: Name or service not known", seal.TOOL_ERROR),
    ],
)
def test_a_probe_is_classified_by_its_exit_code_and_error(code: int, text: str, result: str) -> None:
    assert seal.classify(code, text) == result


def inside(host: str, output: str, name: str = "seal-check-probes.json") -> list[dict]:
    recorded = fixture(name)[host]
    # The recorded outputs come from a probe script that did not yet read the socket tables, so they
    # get the tables of nginx's own listeners on port 80, as /proc/net/tcp and /proc/net/tcp6 print them.
    if "\ntcp\t" not in output:
        output = output.replace("done\n", NGINX_SOCKETS + "done\n")
    plan = {"listens": SPEC.hosts[host].listens, "control_must": "connect", **recorded["plan"]}
    return seal.inside(
        SPEC, host, ["docker", "exec", "<id>", "bash", "-c", "<probe script>"], 0, output, plan
    )


NGINX_SOCKETS = (
    "tcp\t  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "tcp\t   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
    "tcp\t   1: 0B00007F:A3C1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1\n"
    "tcp\t  sl  local_address                         remote_address                        st\n"
    "tcp\t   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 0 0 0\n"
)


def test_every_check_inside_the_containers_passes_on_a_sealed_range() -> None:
    for host, recorded in fixture("seal-check-probes.json").items():
        checks = inside(host, recorded["output"])
        assert failed(checks) == set(), host
        assert {item["check"] for item in checks} >= {
            "probes: positive control",
            "segmentation: must connect",
            "outside: must fail",
            "host canary: must fail",
            "routes: only own subnets",
            "forwarding off",
            "no Docker socket",
            "names: resolver",
            "names: lookup",
        }


@pytest.mark.parametrize(
    ("line", "passes"),
    [
        ("1\tbash: connect: Network is unreachable", True),
        ("1\tbash: connect: No route to host", True),
        ("124\t", True),
        ("1\tbash: connect: Connection refused", False),
        ("0\t", False),
        ("127\tbash: timeout: command not found", False),
    ],
)
def test_a_probe_that_must_fail_passes_only_when_nothing_answered(line: str, passes: bool) -> None:
    output = fixture("seal-check-probes.json")["left"]["output"]
    original = next(row for row in output.splitlines() if row.startswith("probe\tleft -> right@east:80\t"))
    changed = output.replace(original, "probe\tleft -> right@east:80\t" + line)

    verdict = [item for item in inside("left", changed) if item["subject"].endswith("left -> right@east:80")]

    assert [item["pass"] for item in verdict] == [passes]


@pytest.mark.parametrize(
    "line", ["127\tbash: timeout: command not found", "1\tbash: connect: Connection refused"]
)
def test_without_a_working_positive_control_the_seal_fails(line: str) -> None:
    # Once the services listen, the control must connect: a refusal is not enough.
    output = fixture("seal-check-probes.json")["left"]["output"]
    changed = output.replace(
        "probe\tcontrol left -> middle@west:80\t0\t", "probe\tcontrol left -> middle@west:80\t" + line
    )

    assert failed(inside("left", changed)) == {"probes: positive control"}


def test_a_probe_script_that_did_not_finish_fails_the_seal() -> None:
    output = fixture("seal-check-probes.json")["left"]["output"].replace("done\n", "")

    assert "probes: script ran" in failed(inside("left", output))


def test_a_default_route_a_resolver_search_line_and_forwarding_fail_the_seal() -> None:
    output = fixture("seal-check-probes.json")["middle"]["output"]
    output = output.replace("forward\t0", "forward\t1")
    output = output.replace("resolv\toptions ndots:0", "resolv\toptions ndots:0\nresolv\tsearch example.com")
    output = output.replace(
        "done\n", "route\teth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\ndone\n"
    )

    assert failed(inside("middle", output)) == {
        "forwarding off",
        "names: resolver",
        "routes: only own subnets",
    }


def test_a_port_that_listens_beyond_the_spec_fails_the_seal_and_loopback_ones_do_not() -> None:
    output = fixture("seal-check-probes.json")["left"]["output"]
    # The Wazuh API's port 55000 on every IPv6 address, and a resolver on 127.0.0.11.
    api = "tcp\t   1: 00000000000000000000000000000000:D6D8 00000000000000000000000000000000:0000 0A 0 0 0\n"
    loopback = "tcp\t   2: 0B00007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3 1\n"
    closed = "tcp\t   3: 0200130A:0016 0300130A:9C40 01 00000000:00000000 00:00000000 00000000 0 0 4 1\n"

    with_api = inside("left", output.replace("done\n", NGINX_SOCKETS + api + "done\n"))
    quiet = inside("left", output.replace("done\n", NGINX_SOCKETS + loopback + closed + "done\n"))
    silent = inside("left", output.replace("done\n", "tcp\t  sl  local_address\ndone\n"))

    verdict = next(item for item in with_api if item["check"] == "listening: only declared ports")
    assert verdict["observed"] == ["0.0.0.0:80", "[::]:55000", "[::]:80"]
    assert failed(with_api) == {"listening: only declared ports"}
    assert failed(quiet) == set()
    assert failed(silent) == {"listening: only declared ports"}


def test_a_name_that_resolves_outside_the_range_fails_the_seal() -> None:
    output = fixture("seal-check-probes.json")["left"]["output"]
    output = output.replace("name\texample.com\t2\t", "name\texample.com\t0\t93.184.215.14")
    output = output.replace("name\tright\t2\t", "name\tright\t0\t172.19.0.2")

    lookups = [item for item in inside("left", output) if not item["pass"]]

    assert [item["subject"] for item in lookups] == ["container left: right", "container left: example.com"]


def test_without_the_isolated_gateway_mode_the_containers_reach_the_host_canary() -> None:
    recorded = fixture("plant-no-isolated-gateway-probes.json")

    caught = {
        item["subject"]
        for host in recorded
        for item in inside(host, recorded[host]["output"], "plant-no-isolated-gateway-probes.json")
        if not item["pass"]
    }

    port = recorded["left"]["canary"][1]
    assert caught == {
        f"container left: host canary 172.18.0.1:{port}",
        f"container middle: host canary 172.18.0.1:{port}",
        f"container middle: host canary 172.19.0.1:{port}",
        f"container right: host canary 172.19.0.1:{port}",
    }


def test_the_canary_targets_are_the_gateways_and_each_first_subnet_address_no_container_holds() -> None:
    daemon = [
        {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}]}},
        {"IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": ""}]}},
        {"IPAM": {"Config": None}},
    ]

    targets = seal.canary_targets(daemon, ["172.18.0.0/16", "172.19.0.0/16"], {"172.18.0.1"}, rootless=False)
    rootless = seal.canary_targets(daemon, [], set(), rootless=True)

    assert targets == ["172.17.0.1", "172.19.0.1"]
    assert rootless == ["172.17.0.1", "10.0.2.2"]


ADDRESSES = {
    "left": {"west": "172.18.0.2"},
    "middle": {"west": "172.18.0.3", "east": "172.19.0.3"},
    "right": {"east": "172.19.0.2"},
}
SUBNETS = {"west": ["172.18.0.0/16"], "east": ["172.19.0.0/16"]}


def test_before_the_services_listen_the_plan_leaves_out_only_what_needs_them() -> None:
    canary = (["172.17.0.1"], 40000)

    early = seal.plan_for(SPEC, "left", ADDRESSES, SUBNETS, canary, services_up=False)
    later = seal.plan_for(SPEC, "left", ADDRESSES, SUBNETS, canary, services_up=True)

    kinds = {kind for _, _, _, kind, _ in early["probes"]}
    assert kinds == {"outside: must fail", "host canary: must fail"}
    assert {kind for _, _, _, kind, _ in later["probes"]} >= kinds | {"segmentation: must connect"}
    assert early["control"] == later["control"] == ("control left -> middle@west:80", "172.18.0.3", 80)
    assert (early["control_must"], later["control_must"]) == ("answer", "connect")
    assert (early["listens"], later["listens"]) == (None, [80])
    assert early["names"] == later["names"]


def early_plan(host: str) -> dict:
    """The plan before the services listen, with the recorded run's own probes out of the range."""

    recorded = fixture("seal-check-probes.json")[host]["plan"]
    probes = [probe for probe in recorded["probes"] if not probe[3].startswith("segmentation")]
    return {**recorded, "probes": probes, "control_must": "answer", "listens": None}


@pytest.mark.parametrize(
    ("line", "passes"),
    [
        ("0\t", True),
        ("1\tbash: connect: Connection refused", True),
        ("1\tbash: connect: Network is unreachable", False),
        ("124\t", False),
        ("127\tbash: timeout: command not found", False),
    ],
)
def test_before_the_services_listen_the_control_needs_an_answer_from_the_other_host(
    line: str, passes: bool
) -> None:
    output = fixture("seal-check-probes.json")["left"]["output"]
    original = next(
        row for row in output.splitlines() if row.startswith("probe\tcontrol left -> middle@west:80\t")
    )
    changed = output.replace(original, "probe\tcontrol left -> middle@west:80\t" + line)

    checks = seal.inside(SPEC, "left", ["docker", "exec"], 0, changed, early_plan("left"))

    assert "listening: only declared ports" not in {item["check"] for item in checks}
    assert not any(item["check"].startswith("segmentation") for item in checks)
    assert failed(checks) == (set() if passes else {"probes: positive control"})


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_probe_script_runs_the_control_first_and_alone(tmp_path: Path) -> None:
    plan = fixture("seal-check-probes.json")["left"]["plan"]
    log = tmp_path / "probes.log"
    # Stand-ins for timeout and getent, so that nothing connects or looks a name up: each
    # probe logs when it starts and ends, and the control takes a moment.
    stubs = (
        'timeout() { printf "start %s\\n" "$4" >> "$LOG"; '
        'case "$4" in *"/dev/tcp/$CONTROL/"*) sleep 0.3 ;; esac; '
        'printf "end %s\\n" "$4" >> "$LOG"; return 124; }\n'
        "getent() { return 2; }\n"
    )
    environment = {"PATH": os.environ.get("PATH", ""), "LOG": str(log), "CONTROL": plan["control"][1]}

    done = subprocess.run(
        ["bash", "-c", stubs + seal.script_for(plan)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )

    lines = log.read_text().splitlines()
    control = f"exec 3<>/dev/tcp/{plan['control'][1]}/{plan['control'][2]}"
    assert done.returncode == 0
    assert lines[:2] == [f"start {control}", f"end {control}"]
    assert len(lines) == 2 * (1 + len(plan["probes"]))


UNRELATED = {"Id": "y" * 64, "Name": "/someone-else", "HostConfig": {"NetworkMode": "bridge"}}


def watched(lines: list[str], announce, folder: Path, inspected: dict | None = UNRELATED) -> engine.Watch:
    """A watch of a range with one container and one network, fed `lines`; `inspected` is what
    `docker inspect` gives of any other container (None: it is gone)."""

    watch = engine.Watch("bluefire-lab-sc", folder / "docker-events.ndjson", inspect=lambda _: inspected)
    watch.networks.add("n" * 64)
    watch.containers.add("c" * 64)
    announce(watch)
    watch.feed(line + "\n" for line in lines)
    return watch


def an_event(kind: str, action: str, actor: str, **attributes: str) -> str:
    return json.dumps({"Type": kind, "Action": action, "Actor": {"ID": actor, "Attributes": attributes}})


def test_the_watch_reports_a_network_connect_the_engine_did_not_announce(tmp_path: Path) -> None:
    started = an_event("network", "connect", "n" * 64, name="bluefire-lab-sc-west", container="c" * 64)
    intruder = an_event("network", "connect", "n" * 64, name="bluefire-lab-sc-west", container="x" * 64)
    elsewhere = an_event("container", "start", "y" * 64, name="someone-else")

    watch = watched(
        [started, intruder, elsewhere],
        lambda w: w.expect("network", "connect", id="n" * 64, container="c" * 64),
        tmp_path,
    )

    assert [finding["container"] for finding in watch.findings] == ["x" * 64]
    assert watch.events == 2
    assert len((tmp_path / "docker-events.ndjson").read_text().splitlines()) == 2


def test_the_watch_reports_a_second_start_and_an_exec_the_engine_did_not_run(tmp_path: Path) -> None:
    start = an_event("container", "start", "c" * 64, name="bluefire-lab-sc-left")
    ours = an_event("container", "exec_start: bash -c true", "c" * 64, name="bluefire-lab-sc-left")
    theirs = an_event("container", "exec_start: sh", "c" * 64, name="bluefire-lab-sc-left")

    def announce(watch: engine.Watch) -> None:
        watch.expect("container", "start", required=True, id="c" * 64)
        watch.expect("container", "exec_start: bash -c true", id="c" * 64)

    watch = watched([start, ours, theirs, start], announce, tmp_path)

    assert [finding["action"] for finding in watch.findings] == ["exec_start: sh", "start"]
    assert watch.settle(0) == []


def test_the_end_of_a_command_is_matched_to_the_one_the_engine_waits_for_before_one_that_may_never_end(
    tmp_path: Path,
) -> None:
    # A command that runs until the teardown is announced first, without waiting for its end. A
    # short command's end must not be taken for it, or the short command would look unreported.
    ended = an_event("container", "exec_die", "c" * 64, name="bluefire-lab-sc-left")

    def announce(watch: engine.Watch) -> None:
        watch.expect("container", "exec_die", id="c" * 64)
        watch.expect("container", "exec_die", required=True, id="c" * 64)

    watch = watched([ended], announce, tmp_path)

    assert watch.findings == []
    assert watch.settle(0) == []


def test_a_container_started_with_init_is_seen_unless_the_engine_set_it() -> None:
    objects = fixture("seal-check-created.json")
    objects["containers"]["left"]["HostConfig"]["Init"] = True

    checks = static(objects, started=False)

    assert failed(checks) == {"container: init"}


PARENT = {"image": "ubuntu:noble@sha256:" + "1" * 64, "layers": ["sha256:" + "a" * 64]}


def a_built_image(layers: list[str], tags: list[str] | None = None) -> dict:
    return {
        "Id": "sha256:" + "b" * 64,
        "RepoTags": tags or ["bluefire-lab-wz-web:0123"],
        "RootFS": {"Layers": layers},
    }


def test_a_built_image_passes_only_under_its_tag_and_on_the_pinned_image() -> None:
    def judged(image: dict) -> bool:
        checked = seal.built_image("web", "bluefire-lab-wz-web:0123", "sha256:" + "b" * 64, image, PARENT)
        return checked["pass"]

    assert judged(a_built_image(["sha256:" + "a" * 64, "sha256:" + "c" * 64]))
    # Another image given the same tag, built on something else.
    assert not judged(a_built_image(["sha256:" + "d" * 64, "sha256:" + "c" * 64]))
    assert not judged(a_built_image(["sha256:" + "a" * 64], tags=["bluefire-lab-wz-web:4567"]))
    assert not judged({**a_built_image(["sha256:" + "a" * 64]), "Id": "sha256:" + "e" * 64})


def a_joiner(target: str, mode: str = "NetworkMode") -> dict:
    """`docker inspect` of a container outside the range, trimmed; Docker records its target as a full ID."""

    config = {"NetworkMode": "bridge", "PidMode": "", "IpcMode": "private", mode: f"container:{target}"}
    return {"Id": "9" * 63 + "0", "Name": "/someone-else", "HostConfig": config}


def test_the_watch_reports_another_container_that_joins_a_range_containers_namespace(tmp_path: Path) -> None:
    created = an_event("container", "create", "9" * 63 + "0", name="someone-else", image="nginx")

    joined = watched([created], lambda w: None, tmp_path, inspected=a_joiner("c" * 64))
    apart = watched([created], lambda w: None, tmp_path, inspected=a_joiner("e" * 64))

    assert [finding["joins"] for finding in joined.findings] == [{"NetworkMode": "container:" + "c" * 64}]
    assert apart.findings == []


class Stream:
    """Stands in for the `docker events` process: the test feeds the watch itself."""

    def poll(self) -> int:
        return 0


class Teardown(engine.Run):
    """A run with Docker's steps stubbed, whose every seal phase passes; the teardown shows `events` to the watch."""

    def __init__(self, folder: Path, events: list[str], watching: bool = True):
        super().__init__(SPEC, "seal-check.yaml", folder, None, 0)
        self.events = events
        self.watching = watching
        self.watch.settle = lambda seconds=0.2: engine.Watch.settle(self.watch, seconds)

    def preflight(self) -> None:
        def start(since: str) -> None:
            self.watch.process, self.watch.alive = Stream(), True

        self.watch.start = start

    def prepare_images(self) -> None:
        pass

    def create_networks(self) -> None:
        self.created = True

    def create_containers(self) -> None:
        pass

    def start(self) -> None:
        pass

    def ready(self) -> None:
        pass

    def static_checks(self, started: bool) -> list[dict]:
        return []

    def dynamic_checks(self, services_up: bool = True) -> list[dict]:
        return []

    def teardown(self) -> bool:
        self.watch.containers.add("c" * 64)
        self.watch.expect("container", "destroy", required=True, id="c" * 64)
        self.watch.feed(line + "\n" for line in self.events)
        self.watch.alive = self.watching
        return True


DESTROY = an_event("container", "destroy", "c" * 64, name="bluefire-lab-sc-left")
INTRUDER = an_event("network", "connect", "n" * 64, name="bluefire-lab-sc-west", container="c" * 64)


@pytest.mark.parametrize(
    "events, watching, code",
    [
        ([DESTROY], True, engine.EXIT_OK),
        ([], True, engine.EXIT_INVALID),
        ([DESTROY, INTRUDER], True, engine.EXIT_INVALID),
        ([DESTROY], False, engine.EXIT_INVALID),
    ],
    ids=["reported", "destroy-not-reported", "event-not-caused", "watch-stopped"],
)
def test_the_watch_during_the_teardown_is_part_of_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, events: list[str], watching: bool, code: int
) -> None:
    monkeypatch.setattr(engine, "docker", lambda *a, **k: subprocess.CompletedProcess(a, 0, "now\n", ""))

    run = Teardown(tmp_path, events, watching)
    run.run()

    record = json.loads((tmp_path / "seal.json").read_text())
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["exit_code"] == code
    assert record["passed"] == (code == engine.EXIT_OK)
    assert [phase["phase"] for phase in record["phases"]] == [
        "static",
        "no way out",
        "segmentation",
        "after path",
        "teardown",
    ]
    assert record["phases"][-1]["passed"] == (code == engine.EXIT_OK)
    title = "passed" if code == engine.EXIT_OK else "failed"
    assert (tmp_path / "seal.md").read_text().startswith(f"### Seal of seal-check: {title}")


def test_a_run_stopped_after_the_seal_passed_is_not_recorded_as_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ctrl-C where the path will run: every recorded phase passed, and the run is still invalid.
    monkeypatch.setattr(engine, "docker", lambda *a, **k: subprocess.CompletedProcess(a, 0, "now\n", ""))
    run = Teardown(tmp_path, [DESTROY])

    def stopped() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(run, "hold_window", stopped)
    run.run()

    record = json.loads((tmp_path / "seal.json").read_text())
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert (manifest["exit_code"], manifest["result"]) == (engine.EXIT_INVALID, "invalid")
    assert all(phase["passed"] for phase in record["phases"])
    assert record["passed"] is False
    assert (tmp_path / "seal.md").read_text().startswith("### Seal of seal-check: failed")


def test_a_teardown_that_left_objects_behind_stays_an_engine_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A removal Docker refused is never reported as a destroy: the failed removal is the cause.
    monkeypatch.setattr(engine, "docker", lambda *a, **k: subprocess.CompletedProcess(a, 0, "now\n", ""))
    run = Teardown(tmp_path, [])
    monkeypatch.setattr(run, "teardown", lambda: Teardown.teardown(run) and False)
    run.run()

    record = json.loads((tmp_path / "seal.json").read_text())
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["exit_code"] == engine.EXIT_REFUSED
    assert manifest["teardown_complete"] is False
    assert manifest["reason"].startswith("the teardown left objects behind")
    assert record["passed"] is False


@pytest.mark.parametrize("mode", ["NetworkMode", "PidMode", "IpcMode"])
def test_the_objects_check_fails_on_a_container_that_shares_a_namespace_with_the_range(mode: str) -> None:
    objects = fixture("seal-check-started.json")
    containers = {host: data["Id"] for host, data in objects["containers"].items()}
    daemon = list(objects["containers"].values()) + [a_joiner("e" * 64, "IpcMode")]

    clean = seal.joiners(daemon, containers, SPEC)
    joined = seal.joiners(daemon + [a_joiner(containers["middle"], mode)], containers, SPEC)

    assert clean["pass"]
    assert not joined["pass"]
    assert joined["observed"]["9" * 63 + "0"][mode] == "container:" + containers["middle"]


def test_the_watch_reports_a_container_that_is_gone_before_it_could_be_inspected(tmp_path: Path) -> None:
    # Such as `docker run --rm --network container:<range container>` that ends at once.
    created = an_event("container", "create", "9" * 63 + "0", name="someone-else", image="nginx")
    started = an_event("container", "start", "9" * 63 + "0", name="someone-else", image="nginx")

    gone = watched([created, started], lambda w: None, tmp_path, inspected=None)

    assert [finding["action"] for finding in gone.findings] == ["create", "start"]
    assert all(finding["joins"] == {"inspect": "gone before it"} for finding in gone.findings)


BREAK = seal.check("host canary", "Docker host", "listener", ["172.17.0.2"], "no connection", False)


class Ordered(Teardown):
    """A run that records the order of its steps; `broken` lists the seal phases that fail."""

    def __init__(
        self,
        folder: Path,
        broken: tuple[str, ...] = (),
        ready: bool = True,
        events: tuple[str, ...] = (DESTROY,),
        raises: BaseException | None = None,
    ):
        super().__init__(folder, list(events))
        self.steps: list[str] = []
        self.broken = broken
        self.is_ready = ready
        self.raises = raises
        self.calls = 0

    def start(self) -> None:
        self.steps.append("start")

    def ready(self) -> None:
        self.steps.append("ready")
        if not self.is_ready:
            raise engine.NotReady("host left: port 80 did not answer within 30 s of the start")

    def plant_checks(self) -> None:
        self.steps.append("plant checks")

    def dynamic_checks(self, services_up: bool = True) -> list[dict]:
        self.calls += 1
        name = "segmentation" if services_up else "no way out"
        self.steps.append(name)
        if self.raises is not None and self.calls > 1:
            raise self.raises
        return [BREAK] if f"{name} {self.calls}" in self.broken else []


def ordered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **settings) -> tuple[Ordered, dict, dict]:
    monkeypatch.setattr(engine, "docker", lambda *a, **k: subprocess.CompletedProcess(a, 0, "now\n", ""))
    run = Ordered(tmp_path, **settings)
    run.run()
    record = json.loads((tmp_path / "seal.json").read_text())
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    return run, record, manifest


def test_nothing_can_leave_is_proven_right_after_the_start_before_the_ready_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, record, manifest = ordered(tmp_path, monkeypatch)

    assert run.steps[:4] == ["start", "no way out", "ready", "segmentation"]
    assert manifest["exit_code"] == engine.EXIT_OK


def test_a_way_out_found_before_the_ready_gate_stops_the_run_before_anything_waits_in_the_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, record, manifest = ordered(tmp_path, monkeypatch, broken=("no way out 1",))

    assert run.steps == ["start", "no way out"]
    assert (manifest["exit_code"], manifest["result"]) == (engine.EXIT_SEAL, "seal failed")
    assert manifest["reason"] == "seal failed before the ready gate: host canary"
    assert [phase["phase"] for phase in record["phases"]] == ["static", "no way out", "teardown"]


@pytest.mark.parametrize(
    ("broken", "code", "result"),
    [((), engine.EXIT_REFUSED, "not ready"), (("no way out 2",), engine.EXIT_SEAL, "seal failed")],
    ids=["sealed", "a-way-out-while-not-ready"],
)
def test_a_range_that_is_not_ready_still_has_its_seal_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broken: tuple, code: int, result: str
) -> None:
    run, record, manifest = ordered(tmp_path, monkeypatch, broken=broken, ready=False)

    assert run.steps == ["start", "no way out", "ready", "no way out"]
    assert (manifest["exit_code"], manifest["result"]) == (code, result)
    assert "port 80 did not answer" in manifest["reason"]
    assert [phase["phase"] for phase in record["phases"]][:3] == [
        "static",
        "no way out",
        "no way out, not ready",
    ]


def test_a_range_that_is_not_ready_and_whose_watch_fails_in_the_teardown_ends_with_a_failed_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, record, manifest = ordered(tmp_path, monkeypatch, ready=False, events=(DESTROY, INTRUDER))

    assert (manifest["exit_code"], manifest["result"]) == (engine.EXIT_SEAL, "seal failed")
    assert manifest["reason"].startswith("the event watch failed during the teardown")
    assert "port 80 did not answer" in manifest["reason"]
    assert record["phases"][-1] == {**record["phases"][-1], "phase": "teardown", "passed": False}


@pytest.mark.parametrize(
    ("raises", "code", "result"),
    [
        (KeyboardInterrupt(), engine.EXIT_REFUSED, "engine error"),
        (OSError("the probe script could not be sent"), engine.EXIT_SEAL, "seal failed"),
    ],
    ids=["stopped", "could-not-judge"],
)
def test_a_stop_or_an_error_while_a_not_ready_seal_is_judged_again_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raises: BaseException, code: int, result: str
) -> None:
    run, record, manifest = ordered(tmp_path, monkeypatch, ready=False, raises=raises)

    assert (manifest["exit_code"], manifest["result"]) == (code, result)
    assert "port 80 did not answer" in manifest["reason"]
    again = next(phase for phase in record["phases"] if phase["phase"] == "no way out, not ready")
    assert [(item["check"], item["pass"]) for item in again["checks"]] == [("seal judged", False)]
    assert manifest["teardown_complete"] is True


def test_the_wazuh_versions_are_read_only_after_the_ready_gate(tmp_path: Path) -> None:
    run = engine.Run(
        range_spec.load(Path(__file__).parents[1] / "range" / "range-one.yaml"),
        "range-one.yaml",
        tmp_path,
        None,
        0,
    )
    read = []
    run.static_checks = lambda started: []
    run.dynamic_checks = lambda services_up: []
    run.watch.check = lambda command: seal.check("events", "watch", command, [], [], True)
    run.wazuh_pins = lambda: read.append("pins") or []

    run.sealed_checks("docker events", services_up=False)
    assert read == []
    run.sealed_checks("docker events", services_up=True)
    assert read == ["pins"]

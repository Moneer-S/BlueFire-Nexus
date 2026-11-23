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
    return seal.inside(
        SPEC, host, ["docker", "exec", "<id>", "bash", "-c", "<probe script>"], 0, output, recorded["plan"]
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


def test_without_a_working_positive_control_the_seal_fails() -> None:
    output = fixture("seal-check-probes.json")["left"]["output"]
    changed = output.replace(
        "probe\tcontrol left -> middle@west:80\t0\t", "probe\tcontrol left -> middle@west:80\t127\t"
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


def watched(lines: list[str], announce, folder: Path, inspected: dict | None = None) -> engine.Watch:
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

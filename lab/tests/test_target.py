"""A container as the target: what the lab refuses in its settings, on what the runtime would say."""

from __future__ import annotations

from test_evaluate import ACCOUNT, a_test, see, start, step
from test_report import results

from bluefire_lab import evaluate, report, target

TARGET = {
    "container": "bluefire-lab-target-r1",
    "network": "bluefire-lab-r1",
    "image": "nginx@sha256:" + "a" * 64,
    "read_only": ["/opt/bluefire-lab/atomic-red-team/atomics", "/opt/microsoft/powershell/7"],
}


def inspected(**host) -> dict:
    """What "docker inspect" says of a container the lab started as it should."""

    mounts = [{"Source": folder, "Destination": folder, "RW": False} for folder in TARGET["read_only"]]
    return {
        "State": {"Running": True, "Pid": 4242},
        "HostConfig": {"Privileged": False, "CapAdd": None, "Devices": [], "NetworkMode": TARGET["network"],
                       "PidMode": "", "IpcMode": "private", "PortBindings": {}, "PublishAllPorts": False,
                       "RestartPolicy": {"Name": "no"}, "SecurityOpt": None, **host},
        "Mounts": mounts,
        "NetworkSettings": {"Networks": {TARGET["network"]: {}}},
    }  # fmt: skip


INTERNAL = {"Id": "0123456789abcdef", "Internal": True}


def test_a_container_started_as_the_lab_starts_it_is_not_refused() -> None:
    assert target.refusals(inspected(), INTERNAL, TARGET) == []


def test_each_setting_that_would_let_a_container_out_is_refused() -> None:
    def refused(container: dict, network: dict = INTERNAL) -> str:
        found = target.refusals(container, network, TARGET)
        assert len(found) == 1, found
        return found[0]

    assert "privileged" in refused(inspected(Privileged=True))
    assert "added capabilities: NET_ADMIN" in refused(inspected(CapAdd=["NET_ADMIN"]))
    assert "device" in refused(inspected(Devices=[{"PathOnHost": "/dev/kvm"}]))
    assert "host's process namespace" in refused(inspected(PidMode="host"))
    assert "publishes a port" in refused(inspected(PortBindings={"80/tcp": [{"HostPort": "8080"}]}))
    assert "restart policy" in refused(inspected(RestartPolicy={"Name": "always"}))
    assert "seccomp=unconfined" in refused(inspected(SecurityOpt=["seccomp=unconfined"]))
    assert "is not internal" in refused(inspected(), {"Internal": False})

    stopped = inspected()
    stopped["State"]["Running"] = False
    assert "not running" in refused(stopped)
    socket = inspected()
    socket["Mounts"].append({"Source": "/var/run/docker.sock", "RW": True})
    assert "Docker socket" in refused(socket)
    workspace = inspected()
    workspace["Mounts"].append({"Source": "/home/runner/work", "RW": False})
    assert "folder of the host it may not have" in refused(workspace)
    writable = inspected()
    writable["Mounts"][0]["RW"] = True
    assert "may write to" in refused(writable)
    second = inspected()
    second["NetworkSettings"]["Networks"]["bridge"] = {}
    assert "not only on its own" in refused(second)
    # The host's network namespace is its own refusal, and then the container is on no network of its own.
    assert any(
        "host's network namespace" in reason
        for reason in target.refusals(inspected(NetworkMode="host"), INTERNAL, TARGET)
    )


def a_probe(description: str, expected: str, succeeded: bool) -> dict:
    return {"probe": description, "expected": expected, "succeeded": succeeded,
            "held": succeeded == (expected == "succeeds")}  # fmt: skip


def test_the_leash_holds_only_when_every_probe_came_out_as_it_had_to_before_and_after() -> None:
    sound = {"refused": [], "probes": [a_probe("from the host to an outside address", "succeeds", True),
                                         a_probe("from the container to an outside address over IPv4", "fails", False)]}  # fmt: skip
    out = {
        "refused": [],
        "probes": [a_probe("from the container to an outside address over IPv4", "fails", True)],
    }
    blind = {"refused": [], "probes": [a_probe("from the host to an outside address", "succeeds", False)]}

    assert evaluate.leash_held({"before": sound, "after": sound, "left": []})[0] is True
    held, why = evaluate.leash_held({"before": sound, "after": out, "left": []})
    assert not held and why == "after the tests, from the container to an outside address over IPv4 succeeded"
    # A check whose own control failed shows nothing, and a check that did not run has not passed.
    assert evaluate.leash_held({"before": blind, "after": sound, "left": []})[0] is False
    assert evaluate.leash_held({"before": sound, "left": []})[1] == "the check after the tests did not run"
    assert (
        evaluate.leash_held(
            {"before": {**sound, "refused": ["the container is privileged"]}, "after": sound}
        )[0]
        is False
    )
    assert "were left" in evaluate.leash_held({"before": sound, "after": sound, "left": ["0a1b"]})[1]


def test_in_a_container_the_launcher_is_the_one_shell_the_executors_powershell_started() -> None:
    marker = "/usr/bin/true bluefire-lab-marker r1 1"
    events = [
        start(1, 1.0, 90, 89, f"{marker} start", 10),
        {
            **start(2, 2.0, 5100, 5000, "pwsh -Command Invoke-AtomicTest", 11),
            "Image": "/opt/microsoft/powershell/7/pwsh",
        },
        start(3, 2.5, 5110, 5100, "hostname", 11),  # the executor's own
        {**start(4, 5.0, 5120, 5100, "sh -c touch /tmp/x; id", 11), "Image": "/usr/bin/dash"},  # the launcher
        start(5, 5.01, 5121, 5120, "id", 11),
        start(6, 6.0, 91, 89, f"{marker} end", 12),
    ]
    # The executor's log names the launcher by its id inside the container, 77, which no sensor recorded.
    test = a_test(launcher_pid=77)

    lost, _ = see(test, events)
    found, mine = see(test, events, container=True)

    assert lost["answer"] == "inconclusive"
    assert found["answer"] == "telemetry only" and found["launcher"]["process_id"] == "5120"
    assert [event["detail"] for event in mine] == ["id"]
    # Two such shells, or no record that the executor started the test, and the launcher is not known.
    twice = [*events[:4], {**events[3], "EventRecordID": "7", "ProcessId": "5130"}, *events[4:]]
    assert see(test, twice, container=True)[0]["answer"] == "inconclusive"
    unstarted = a_test(steps=[step("marker-start", 10), step("attack", 11), step("marker-end", 12)])
    del unstarted["launcher_pid"]
    assert see(unstarted, events, container=True)[0]["answer"] == "inconclusive"
    assert ACCOUNT  # the account the fixtures run as


def test_the_report_shows_the_image_the_settings_and_every_probe() -> None:
    document = results()
    document["run"]["target"].update(image=TARGET["image"], image_id="sha256:" + "b" * 64, container="c")
    sound = {
        "refused": [],
        "probes": [a_probe("from the container to the cloud metadata address", "fails", False)],
    }
    document["leash"] = {"before": sound, "after": sound, "left": []}

    page, summary = report.html_report(document), report.markdown_summary(document)

    assert f"ran on a container of the image {TARGET['image']}" in summary
    section = page[page.index('id="image"') :]
    assert "None of these was found." in section
    assert section.count("from the container to the cloud metadata address") == 2
    assert "<td>before the tests</td>" in section and "<td>after the tests</td>" in section
    assert 'id="image"' not in report.html_report(results())

"""The packet-capture lifecycle keeps every host's evidence on every engine exit."""

import io
import subprocess
import sys
import tarfile
from pathlib import Path

from bluefire_lab.range import build, engine
from bluefire_lab.range import spec as range_spec

SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"


def a_run(tmp_path: Path, *hosts: str) -> engine.Run:
    run = engine.Run(range_spec.load(SMALL), "small.yaml", tmp_path, None, 0)
    run.containers = {host: host * 64 for host in hosts}
    run.manifest["packet_capture"] = {
        "program": "tcpdump",
        "path": build.CAPTURE_DIR,
        "filter": build.CAPTURE_FILTER,
        "hosts": {
            host: {
                "started": True,
                "ready": [],
                "stopped": None,
                "collected": None,
                "files": {},
            }
            for host in hosts
        },
        "analysed": False,
        "delivery_gap": None,
        "delivery_findings": [],
    }
    run.write = lambda: None
    return run


def test_capture_stop_waits_for_exit_status_and_one_host_does_not_stop_the_next(tmp_path: Path) -> None:
    run = a_run(tmp_path, "web", "db")
    scripts = []

    def execute(identifier: str, script: str, timeout: float, tag: str):
        scripts.append(script)
        if identifier == "web" * 64:
            raise engine.EngineError("web disappeared")
        return subprocess.CompletedProcess([], 0, "", "")

    run.execute = execute

    run.stop_captures()

    assert len(scripts) == 2
    assert all(build.CAPTURE_ARMED_SUFFIX in script for script in scripts)
    assert all(build.CAPTURE_STATUS_SUFFIX in script for script in scripts)
    assert all("while kill -0" not in script for script in scripts)
    assert all(script.index('[ -s "$armed" ]') < script.index('kill -TERM "$pid"') for script in scripts)
    assert all(
        'wrapper was not armed" >&2; pid=$(< "$pidfile"); kill -TERM "$pid"' in script for script in scripts
    )
    assert all("for pidfile in $signaled" in script for script in scripts)
    assert all('code=$(< "$marker")' in script for script in scripts)
    assert run.manifest["packet_capture"]["hosts"]["web"]["stopped"]["cleanly"] is False
    assert run.manifest["packet_capture"]["hosts"]["db"]["stopped"]["cleanly"] is True


def test_packet_home_net_is_the_exact_addresses_of_agent_and_capture_hosts(tmp_path: Path) -> None:
    run = engine.Run(range_spec.load(RANGE_ONE), "range-one.yaml", tmp_path, None, 0)
    capture = run.manifest["packet_capture"]

    assert capture["home_hosts"] == ["build", "db", "web"]
    run.manifest["containers"] = {host: {} for host in ("attacker", "build", "db", "web")}
    run.record_addresses(
        {
            "attacker": {"edge": "172.18.0.2"},
            # Numeric address order differs from string order here: .10 belongs after .4.
            "build": {"inside": "172.19.0.10", "mgmt": "172.20.0.2"},
            "db": {"inside": "172.19.0.3", "mgmt": "172.20.0.3"},
            "web": {"edge": "172.18.0.3", "inside": "172.19.0.4", "mgmt": "172.20.0.4"},
        }
    )

    assert capture["home_net"] == [
        "172.18.0.3",
        "172.19.0.3",
        "172.19.0.4",
        "172.19.0.10",
        "172.20.0.2",
        "172.20.0.3",
        "172.20.0.4",
    ]


def test_one_capture_copy_error_does_not_sacrifice_the_next_host(tmp_path: Path) -> None:
    run = a_run(tmp_path, "web", "db")
    copied = []

    def copy_out(host: str, path: str) -> dict:
        copied.append((host, path))
        if host == "web":
            raise OSError("web copy failed")
        return {"copied": True}

    run.copy_out = copy_out

    run.collect_captures()

    assert copied == [("web", build.CAPTURE_DIR), ("db", build.CAPTURE_DIR)]
    hosts = run.manifest["packet_capture"]["hosts"]
    assert hosts["web"]["collected"] == {"copied": False, "error": "OSError: web copy failed"}
    assert hosts["db"]["collected"] == {"copied": True}


def test_copy_out_kills_a_process_whose_tar_stream_stalls(tmp_path: Path, monkeypatch) -> None:
    run = a_run(tmp_path, "web")
    popen = subprocess.Popen

    def stalled(_command, *, stdout, stderr):
        return popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr(engine.subprocess, "Popen", stalled)
    monkeypatch.setattr(engine, "COPY_SECONDS", 0.05)

    copied = run.copy_out("web", "/capture")

    assert copied["copied"] is False
    assert copied["error"] == "docker cp did not finish within 0.05 seconds"


def test_copy_out_drains_noisy_stderr_while_reading_the_tar_stream(tmp_path: Path, monkeypatch) -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("capture/eth0.pcap")
        payload = b"retained packet"
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    source = tmp_path / "copy.tar"
    source.write_bytes(stream.getvalue())
    script = """
import os
import sys

noise = b"e" * (1024 * 1024)
while noise:
    written = os.write(2, noise)
    noise = noise[written:]
with open(sys.argv[1], "rb") as source:
    while block := source.read(64 * 1024):
        os.write(1, block)
"""
    run = a_run(tmp_path / "run", "web")
    popen = subprocess.Popen

    def noisy(_command, *, stdout, stderr):
        return popen(
            [sys.executable, "-c", script, str(source)],
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr(engine.subprocess, "Popen", noisy)
    monkeypatch.setattr(engine, "COPY_SECONDS", 5)

    copied = run.copy_out("web", "/capture")

    assert copied == {"copied": True}
    assert (tmp_path / "run" / "raw" / "hosts" / "web" / "capture" / "eth0.pcap").read_bytes() == payload


def test_capture_finalizer_continues_after_a_stage_error(tmp_path: Path, monkeypatch) -> None:
    run = a_run(tmp_path, "web")
    stages = []

    def preflight() -> None:
        run.started = True
        raise engine.EngineError("sequence stopped")

    def stop() -> None:
        stages.append("stop")
        raise engine.EngineError("stop failed")

    run.preflight = preflight
    run.stop_captures = stop
    run.collect_captures = lambda: stages.append("collect")
    run.analyse_captures = lambda: stages.append("analyse")
    run.collect = lambda: None
    run.analyse = lambda: None
    run.record_ecs = lambda: None
    monkeypatch.setattr(engine, "write_recording", lambda *_: None)

    run.run()

    assert stages == ["stop", "collect", "analyse"]
    assert run.manifest["packet_capture"]["collect_error"] == "stopping: EngineError: stop failed"


def test_capture_is_analysed_even_when_the_range_never_started(tmp_path: Path, monkeypatch) -> None:
    run = a_run(tmp_path, "web")
    stages = []
    run.manifest["packet_capture"]["analysed"] = "not a boolean"
    run.preflight = lambda: (_ for _ in ()).throw(engine.EngineError("preflight stopped"))
    run.stop_captures = lambda: stages.append("stop")
    run.collect_captures = lambda: stages.append("collect")
    run.analyse_captures = lambda: stages.append("analyse")
    monkeypatch.setattr(engine, "write_recording", lambda *_: None)

    run.run()

    assert stages == ["analyse"]
    capture = run.manifest["packet_capture"]
    assert capture["analysed"] is False
    assert capture["delivery_gap"] is True
    assert capture["delivery_findings"] == ["packet capture analysis did not complete"]


def test_capture_analysis_error_is_one_fail_closed_delivery_finding(tmp_path: Path, monkeypatch) -> None:
    run = a_run(tmp_path, "web")
    capture = run.manifest["packet_capture"]
    capture["delivery_findings"] = ["packet capture analysis did not complete"]
    run.preflight = lambda: (_ for _ in ()).throw(engine.EngineError("preflight stopped"))
    run.analyse_captures = lambda: (_ for _ in ()).throw(ValueError("broken PCAP"))
    monkeypatch.setattr(engine, "write_recording", lambda *_: None)

    run.run()

    assert capture["analysed"] is False
    assert capture["delivery_gap"] is True
    assert capture["delivery_findings"] == [
        "packet capture analysis did not complete: ValueError: broken PCAP"
    ]
    assert capture["collect_error"] == "analysing: ValueError: broken PCAP"


def test_scored_forwards_the_retained_capture_and_suricata_image(tmp_path: Path, monkeypatch) -> None:
    spec = range_spec.load(RANGE_ONE)
    capture = {"hosts": {"web": {}}, "home_net": ["172.18.0.3"]}
    manifest = {
        "run_id": "made-up-run",
        "containers": {},
        "activity": None,
        "path": None,
        "packet_capture": capture,
        "rule_sets": {},
    }
    received = {}

    def record(*args, **kwargs):
        received["args"] = args
        received["kwargs"] = kwargs
        return {"error": None}, {"scored": True}

    monkeypatch.setattr(engine.score, "record", record)

    engine.scored(tmp_path, manifest, spec, suricata_image="example/suricata:8@sha256:" + "a" * 64)

    assert received["kwargs"]["packet_capture"] is capture
    assert received["kwargs"]["suricata_image"] == "example/suricata:8@sha256:" + "a" * 64


def test_run_record_ecs_forwards_its_suricata_image(tmp_path: Path, monkeypatch) -> None:
    image = "example/suricata:8@sha256:" + "d" * 64
    run = engine.Run(
        range_spec.load(SMALL),
        SMALL.name,
        tmp_path,
        None,
        0,
        suricata_image=image,
    )
    received = {}

    def score_run(out, manifest, spec, rule_engine, *, suricata_image):
        received["call"] = (out, manifest, spec, rule_engine, suricata_image)

    monkeypatch.setattr(engine, "scored", score_run)
    run.write = lambda: None

    run.record_ecs()

    assert received["call"] == (tmp_path, run.manifest, run.spec, None, image)


def test_run_keeps_existing_positional_arguments_and_forwards_the_suricata_image(
    tmp_path: Path, monkeypatch
) -> None:
    spec = range_spec.load(SMALL)
    image = "example/suricata:8@sha256:" + "b" * 64
    received = {}

    class FakeRun:
        def __init__(self, *args, **kwargs):
            received["args"] = args
            received["kwargs"] = kwargs
            self.manifest = {"exit_code": 0, "result": "sealed", "reason": None}

        def run(self) -> None:
            pass

    monkeypatch.setattr(engine, "load", lambda _path: spec)
    monkeypatch.setattr(engine, "Run", FakeRun)

    assert engine.run(SMALL, tmp_path, None, 0, None, suricata_image=image) == 0
    assert received["args"] == (spec, SMALL.name, tmp_path, None, 0, None)
    assert received["kwargs"] == {"suricata_image": image}


def test_rescore_keeps_three_positional_arguments_and_forwards_the_suricata_image(
    tmp_path: Path, monkeypatch
) -> None:
    spec = range_spec.load(RANGE_ONE)
    image = "example/suricata:8@sha256:" + "c" * 64
    (tmp_path / "manifest.json").write_text('{"spec":{"text":"made up"}}', encoding="utf-8")
    received = {}

    monkeypatch.setattr(engine, "read", lambda _text: {})
    monkeypatch.setattr(engine, "parse", lambda _data, _text: spec)

    def score_run(folder, manifest, parsed, rule_engine, judged_by, *, suricata_image):
        received["call"] = (folder, parsed, rule_engine, judged_by, suricata_image)
        manifest["ecs"] = {"error": None}
        manifest["score"] = {}

    monkeypatch.setattr(engine, "scored", score_run)
    monkeypatch.setattr(engine, "write_recording", lambda *_args: None)
    monkeypatch.setattr(engine.score, "path_summary", lambda _manifest: "")
    monkeypatch.setattr(engine.score, "summary", lambda _manifest: "")

    assert engine.rescore(tmp_path, None, None, suricata_image=image) == 0
    assert received["call"] == (tmp_path, spec, None, None, image)

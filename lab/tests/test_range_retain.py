import gzip
import hashlib
import ipaddress
import json
import lzma
import shutil
import struct
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from bluefire_lab.__main__ import main
from bluefire_lab.range import build, retain, retained
from bluefire_lab.range import path as range_path
from bluefire_lab.range.spec import load

REPOSITORY = Path(__file__).parents[2]
RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit(workspace: Path) -> str:
    subprocess.run(["git", "init", "-q", workspace], check=True)
    subprocess.run(["git", "-C", workspace, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            workspace,
            "-c",
            "user.name=BlueFire test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture checkout",
        ],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", workspace, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()


def hosted_checkout(tmp_path: Path) -> tuple[dict[str, str], Path]:
    workspace = tmp_path / "workspace"
    spec_path = workspace / "lab/range/range-one.yaml"
    workflow = workspace / ".github/workflows/retained-packet.yml"
    spec_path.parent.mkdir(parents=True)
    workflow.parent.mkdir(parents=True)
    spec_path.write_bytes(RANGE_ONE.read_bytes())
    workflow.write_text("name: retained packet test\n", encoding="utf-8")
    head = commit(workspace)
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    environment = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "example/bluefire",
        "GITHUB_WORKFLOW_REF": ("example/bluefire/.github/workflows/retained-packet.yml@refs/heads/main"),
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_JOB": "make-fixture",
        "GITHUB_SHA": head,
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(runner_temp),
    }
    return environment, spec_path


def pcap(token: str) -> bytes:
    payload = b"packet-start:" + token.encode() + b":packet-end"
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
        + struct.pack("<IIII", 1_795_643_323, 123456, len(payload), len(payload))
        + payload
    )


def numeric(values: set[str]) -> list[str]:
    return sorted(
        values, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value))
    )


def source_run(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path]:
    environment, spec_path = hosted_checkout(tmp_path)
    spec = load(spec_path)
    run = Path(environment["RUNNER_TEMP"]) / "range-run"
    run.mkdir()
    run_url = "https://github.com/example/bluefire/actions/runs/123456"

    containers = {}
    for host_number, (host, settings) in enumerate(spec.hosts.items(), start=1):
        containers[host] = {
            "name": spec.container_name(host),
            "id": str(host_number) * 64,
            "image_id": str(host_number + 1) * 64,
            "addresses": {
                network: f"10.{host_number}.{network_number}.2"
                for network_number, network in enumerate(settings.networks, start=1)
            },
        }

    capture_hosts = [host for host, settings in spec.hosts.items() if settings.capture == "packets"]
    packet_hosts = {}
    for capture_host in capture_hosts:
        packet_folder = run / f"raw/hosts/{capture_host}/var/log/bluefire/packets"
        packet_folder.mkdir(parents=True)
        ready = []
        files = {}
        for number, network in enumerate(spec.hosts[capture_host].networks):
            interface = f"eth{number}"
            token = f"bluefire-packet-ready-{capture_host}-{network}"
            capture = pcap(token)
            pcap_path = packet_folder / f"{interface}.pcap"
            counter_path = packet_folder / f"{interface}.log"
            pcap_path.write_bytes(capture)
            counter_path.write_text(
                "1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n",
                encoding="utf-8",
            )
            peer = next(host for host in spec.members(network) if host != capture_host)
            ready.append(
                {
                    "network": network,
                    "interface": interface,
                    "source": containers[capture_host]["addresses"][network],
                    "destination": containers[peer]["addresses"][network],
                    "destination host": peer,
                    "port": 62000 + number,
                    "token": token,
                    "seen": True,
                    "seconds": 0.1,
                }
            )
            files[f"{interface}.pcap"] = {
                "file": f"raw/hosts/{capture_host}/var/log/bluefire/packets/{interface}.pcap",
                "bytes": len(capture),
                "sha256": sha256(capture),
                "packets": 1,
                "captured packet bytes": len(capture) - 40,
                "wire packet bytes": len(capture) - 40,
                "whole packets": True,
                "snap length": 262144,
                "link type": 1,
                "timestamp resolution": "microseconds",
                "xz -9 bytes": len(lzma.compress(capture, format=lzma.FORMAT_XZ, preset=9)),
                "tcpdump": {
                    "captured": 1,
                    "received by filter": 1,
                    "dropped by kernel": 0,
                },
            }
        packet_hosts[capture_host] = {
            "started": True,
            "ready": ready,
            "stopped": {"at": "2026-11-26T01:03:00Z", "cleanly": True},
            "collected": {"copied": True},
            "files": files,
        }
    home_hosts = sorted(set(spec.agents) | set(capture_hosts))
    home_net = numeric({address for host in home_hosts for address in containers[host]["addresses"].values()})
    packet_capture = {
        "program": "tcpdump",
        "path": "/var/log/bluefire/packets",
        "filter": build.CAPTURE_FILTER,
        "home_hosts": home_hosts,
        "home_net": home_net,
        "hosts": packet_hosts,
        "analysed": True,
        "delivery_gap": False,
        "delivery_findings": [],
    }

    manager = spec.manager
    live = run / "live"
    live.mkdir()
    archive_bytes = b'{"archive":"identity"}\n'
    alert_bytes = b'{"alert":"identity"}\n'
    (live / "archives.json").write_bytes(archive_bytes)
    (live / "alerts.json").write_bytes(alert_bytes)
    write_collected(run, manager, "archives", archive_bytes)
    write_collected(run, manager, "alerts", alert_bytes)
    startup = run / f"raw/hosts/{manager}/var/ossec/logs/ossec.log"
    startup.parent.mkdir(parents=True, exist_ok=True)
    startup.write_text("startup\nTotal rules enabled: '321'\n", encoding="utf-8")

    step_ids = [entry["id"] for entry in range_path.section(spec)["steps"]]
    for step_id in step_ids:
        folder = run / "raw/steps" / step_id
        folder.mkdir(parents=True)
        for name, data in {
            "command": b"docker exec command\n",
            "prereq.txt": b"The published test has no prerequisite check.\n",
            "stdout": f"output of {step_id}\n".encode(),
            "stderr": b"",
            "check.txt": b'{"result":"pass"}\n',
            "cleanup.txt": b"cleanup: none\n",
        }.items():
            (folder / name).write_bytes(data)
    nested = run / "raw/steps" / step_ids[0] / "extra/context.txt"
    nested.parent.mkdir()
    nested.write_text("all step files are retained\n", encoding="utf-8")

    first_time = 1_795_643_323_123_456_789
    last_time = 1_795_643_384_987_654_321
    (run / "docker-events.ndjson").write_text(
        json.dumps({"timeNano": first_time}) + "\n" + json.dumps({"timeNano": last_time}) + "\n",
        encoding="utf-8",
    )

    defense = {
        "wazuh_version": spec.wazuh.version,
        "alert_level": spec.wazuh.alert_level,
        "manager": manager,
        "agents": spec.agents,
        "delivery": {
            host: [{"source": "/var/log/auth.log", "sent": 1, "archived": 1, "missing": 0}]
            for host in spec.agents
        },
        "delivery_gap": False,
        "delivery_findings": [],
        "drops": {"manager: wazuh-analysisd.state": {"events_dropped": "0"}},
        "wazuh_counted_drops": False,
        "live": {"files": ["live/archives.json", "live/alerts.json"]},
    }
    manifest = {
        "range": spec.range,
        "version": spec.version,
        "run_id": "20261126T010203Z-abc123",
        "spec": {"file": spec_path.name, "sha256": spec.sha256, "text": spec.text},
        "environment": "GitHub-hosted runner",
        "run_url": run_url,
        "containers": containers,
        "defense": defense,
        "atomic_red_team": {"commit": spec.atomics.commit},
        "activity": {} if spec.activity is not None else None,
        "weaknesses": [],
        "path": {
            "planned": step_ids,
            "steps": [
                {
                    "id": step_id,
                    "host": host,
                    "technique": technique,
                    "happened": "took effect",
                }
                for step_id, (technique, host) in zip(step_ids, spec.steps, strict=True)
            ],
            "goal": None,
            "stopped": None,
            "notes": [],
        },
        "packet_capture": packet_capture,
        "result": "sealed",
        "reason": None,
        "exit_code": 0,
        "teardown_complete": True,
        "ecs": {"derived": True},
        "score": {"derived": True},
        "recording": {"derived": True},
    }
    write_json(run / "manifest.json", manifest)
    out = Path(environment["RUNNER_TEMP"]) / "retained-artifact/lab/retained/packet-download"
    return environment, spec_path, run, out


def write_collected(run: Path, manager: str, kind: str, data: bytes) -> None:
    singular = "archive" if kind == "archives" else "alerts"
    path = run / f"raw/hosts/{manager}/var/ossec/logs/{kind}/2026/Nov/ossec-{singular}-26.json.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as stream:
        stream.write(data)


def manifest(run: Path) -> dict:
    return json.loads((run / "manifest.json").read_text(encoding="utf-8"))


def source_hashes(run: Path) -> dict[str, str]:
    return {
        path.relative_to(run).as_posix(): sha256(path.read_bytes())
        for path in run.rglob("*")
        if path.is_file()
    }


def test_exports_identity_bytes_with_derived_hosted_provenance_and_actual_verification(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    before = source_hashes(run)

    published, document = retain.export(run, spec_path, out, environment)
    proof = retained.verify_retained(published)
    projected = json.loads((out / "files/manifest.json").read_text(encoding="utf-8"))

    assert document["source"] == {
        "repository": "example/bluefire",
        "workflow": ".github/workflows/retained-packet.yml",
        "run_id": 123456,
        "run_attempt": 2,
        "job": "make-fixture",
        "head": environment["GITHUB_SHA"][:12],
        "run_url": "https://github.com/example/bluefire/actions/runs/123456",
        "artifact": "range-one-run-2",
    }
    assert proof.run["id"] == "20261126T010203Z-abc123"
    assert all(
        entry.artifact_path.as_posix().startswith("lab/retained/packet-download/files/")
        for entry in proof.files
    )
    assert set(projected).isdisjoint({"ecs", "score", "recording", "rule_sets", "docker"})
    assert projected["recording_clock"] == {
        "started": retain.iso(1_795_643_323_123_456_789),
        "ended": retain.iso(1_795_643_384_987_654_321),
        "basis": "the first and last Docker event timeNano selected by the hosted workflow",
    }
    assert (out / "files/raw/steps/s01/extra/context.txt").read_text() == "all step files are retained\n"
    spec = load(spec_path)
    expected_packets = sum(
        len(settings.networks) for settings in spec.hosts.values() if settings.capture == "packets"
    )
    assert sum(entry["role"] == "raw packet capture" for entry in document["files"]) == expected_packets
    assert (
        sum(entry["role"] == "raw tcpdump delivery counters" for entry in document["files"])
        == expected_packets
    )
    for capture_host, settings in spec.hosts.items():
        if settings.capture != "packets":
            continue
        for number, _network in enumerate(settings.networks):
            interface = f"eth{number}"
            target = out / f"files/raw/hosts/{capture_host}/var/log/bluefire/packets"
            source = run / f"raw/hosts/{capture_host}/var/log/bluefire/packets"
            assert (target / f"{interface}.pcap").read_bytes() == (source / f"{interface}.pcap").read_bytes()
            assert (target / f"{interface}.txt").read_bytes() == (source / f"{interface}.log").read_bytes()
    assert source_hashes(run) == before


def test_range_retain_command_passes_the_exact_public_interface(monkeypatch):
    called = []
    monkeypatch.setattr(retain, "main", lambda *arguments: called.append(arguments) or 7)

    assert (
        main(
            [
                "range",
                "retain",
                "hosted-run",
                "--spec",
                "lab/range/retained-packet.yaml",
                "--out",
                "/tmp/retained-artifact/lab/retained/packet-download",
            ]
        )
        == 7
    )
    assert called == [
        (
            Path("hosted-run"),
            Path("lab/range/retained-packet.yaml"),
            Path("/tmp/retained-artifact/lab/retained/packet-download"),
        )
    ]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CI", "false"),
        ("GITHUB_ACTIONS", "false"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        ("GITHUB_EVENT_NAME", "push"),
    ],
)
def test_refuses_any_context_other_than_hosted_workflow_dispatch(tmp_path, name, value):
    environment, spec_path, run, out = source_run(tmp_path)
    environment[name] = value

    with pytest.raises(retain.RetainError, match=name):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_refuses_a_spec_that_differs_from_the_tracked_commit(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    spec_path.write_bytes(spec_path.read_bytes() + b"\n")

    with pytest.raises(retain.RetainError, match="byte-for-byte"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_git_replacement_refs_cannot_substitute_the_declared_head_spec(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    workspace = Path(environment["GITHUB_WORKSPACE"])
    declared = environment["GITHUB_SHA"]
    spec_path.write_bytes(spec_path.read_bytes() + b"\n")
    replacement = commit(workspace)
    subprocess.run(["git", "-C", workspace, "replace", declared, replacement], check=True)
    subprocess.run(
        ["git", "--no-replace-objects", "-C", workspace, "checkout", "--detach", "-q", declared],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-C",
            workspace,
            "checkout",
            replacement,
            "--",
            spec_path.relative_to(workspace),
        ],
        check=True,
    )
    replacement_spec = load(spec_path)
    record = manifest(run)
    record["spec"] = {
        "file": spec_path.name,
        "sha256": replacement_spec.sha256,
        "text": replacement_spec.text,
    }
    write_json(run / "manifest.json", record)

    with pytest.raises(retain.RetainError, match="byte-for-byte"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        ("packet digest", "another sha256"),
        ("packet counters", "other counters"),
        ("packet home net", "home_net differs"),
        ("packet extra", "missing or undeclared"),
        ("packet delivery", "incomplete, has a delivery gap"),
        ("wazuh delivery", "Wazuh delivery has a gap"),
    ],
)
def test_refuses_an_incomplete_or_inconsistent_sensor_closure(tmp_path, problem, message):
    environment, spec_path, run, out = source_run(tmp_path)
    record = manifest(run)
    capture = record["packet_capture"]
    host = next(iter(capture["hosts"]))
    packet = capture["hosts"][host]["files"]["eth0.pcap"]
    if problem == "packet digest":
        packet["sha256"] = "0" * 64
    elif problem == "packet counters":
        packet["tcpdump"]["received by filter"] = 2
    elif problem == "packet home net":
        capture["home_net"] = []
    elif problem == "packet extra":
        (run / f"raw/hosts/{host}/var/log/bluefire/packets/extra.txt").write_text("extra\n")
    elif problem == "packet delivery":
        capture["delivery_gap"] = True
    else:
        record["defense"]["delivery_gap"] = True
    write_json(run / "manifest.json", record)

    with pytest.raises(retain.RetainError, match=message):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        ("filter", "exact filter"),
        ("capture host", "hosts differ from the tracked spec"),
        ("duplicate network", "repeats a tracked network"),
        ("duplicate mark", "exactly one ready mark"),
        ("network subset", "exactly one ready mark"),
        ("reused interface", "reuses one interface"),
    ],
)
def test_refuses_packet_capture_that_differs_from_the_engine_and_spec_closure(tmp_path, problem, message):
    environment, spec_path, run, out = source_run(tmp_path)
    record = manifest(run)
    capture = record["packet_capture"]
    host = next(iter(capture["hosts"]))
    entry = capture["hosts"][host]
    ready = entry["ready"]
    assert len(ready) >= 2

    if problem == "filter":
        capture["filter"] = "not port 1514 and not port 1515"
    elif problem == "capture host":
        other = next(name for name, settings in load(spec_path).hosts.items() if settings.capture is None)
        capture["hosts"][other] = capture["hosts"].pop(host)
    elif problem == "duplicate network":
        ready[1]["network"] = ready[0]["network"]
    elif problem == "duplicate mark":
        ready.append(dict(ready[0]))
    elif problem == "network subset":
        removed = ready.pop()
        interface = removed["interface"]
        entry["files"].pop(f"{interface}.pcap")
        folder = run / f"raw/hosts/{host}/var/log/bluefire/packets"
        (folder / f"{interface}.pcap").unlink()
        (folder / f"{interface}.log").unlink()
    else:
        ready[1]["interface"] = ready[0]["interface"]
    write_json(run / "manifest.json", record)

    with pytest.raises(retain.RetainError, match=message):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


@pytest.mark.parametrize("problem", ["renamed id", "order", "host", "technique"])
def test_refuses_a_source_path_identity_that_differs_from_the_tracked_spec(tmp_path, problem):
    environment, spec_path, run, out = source_run(tmp_path)
    record = manifest(run)
    first = record["path"]["steps"][0]
    if problem == "renamed id":
        old = first["id"]
        first["id"] = "renamed"
        record["path"]["planned"][0] = "renamed"
        (run / "raw/steps" / old).rename(run / "raw/steps/renamed")
    elif problem == "order":
        record["path"]["planned"][:2] = reversed(record["path"]["planned"][:2])
        record["path"]["steps"][:2] = reversed(record["path"]["steps"][:2])
    elif problem == "host":
        first["host"] = next(host for host in load(spec_path).hosts if host != first["host"])
    else:
        first["technique"] = "T9999"
    write_json(run / "manifest.json", record)

    with pytest.raises(retain.RetainError, match="does not match every tracked step"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


@pytest.mark.parametrize("kind", ["symbolic", "hard"])
def test_refuses_linked_raw_sources(tmp_path, kind):
    environment, spec_path, run, out = source_run(tmp_path)
    archive = run / "live/archives.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(archive.read_bytes())
    archive.unlink()
    if kind == "symbolic":
        archive.symlink_to(outside)
    else:
        archive.hardlink_to(outside)

    with pytest.raises(retain.RetainError, match="safely|hard link"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_refuses_an_existing_or_outside_output(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    out.mkdir(parents=True)

    with pytest.raises(retain.RetainError, match="exists"):
        retain.export(run, spec_path, out, environment)
    with pytest.raises(retain.RetainError, match="below.*retained-artifact"):
        retain.export(run, spec_path, tmp_path / "elsewhere", environment)


def test_atomic_publish_never_replaces_a_directory_created_in_the_gap(tmp_path, monkeypatch):
    environment, spec_path, run, out = source_run(tmp_path)
    publish = retain._publish

    def race(work, destination):
        destination.mkdir()
        publish(work, destination)

    monkeypatch.setattr(retain, "_publish", race)

    with pytest.raises(retain.RetainError, match="appeared while"):
        retain.export(run, spec_path, out, environment)
    assert out.is_dir()
    assert list(out.iterdir()) == []
    assert list(out.parent.glob(".packet-download.partial-*")) == []


def test_run_root_swap_cannot_redirect_sources_outside_runner_temp(tmp_path, monkeypatch):
    environment, spec_path, run, out = source_run(tmp_path)
    validate = retain._source_run
    moved = Path(environment["RUNNER_TEMP"]) / "moved-original"
    outside = tmp_path / "outside-copy"

    def swap_after_validation(context, requested):
        approved = validate(context, requested)
        shutil.copytree(approved.original, outside)
        approved.original.rename(moved)
        approved.original.symlink_to(outside, target_is_directory=True)
        return approved

    monkeypatch.setattr(retain, "_source_run", swap_after_validation)

    with pytest.raises(retain.RetainError, match="RUN cannot be anchored safely|RUN changed"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_same_size_source_edit_before_publish_removes_the_private_candidate(tmp_path, monkeypatch):
    environment, spec_path, run, out = source_run(tmp_path)
    original = retain._copy_snapshot
    edited = False

    def copy_then_edit(snapshot, destination):
        nonlocal edited
        original(snapshot, destination)
        if not edited and snapshot.what == "complete raw Wazuh archive":
            archive = run / "live/archives.json"
            archive.write_bytes(archive.read_bytes().replace(b"identity", b"changed!"))
            edited = True

    monkeypatch.setattr(retain, "_copy_snapshot", copy_then_edit)

    with pytest.raises(retain.RetainError, match="changed while the export"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()
    assert list(out.parent.glob(".packet-download.partial-*")) == []


def test_calls_the_real_retained_verifier_before_atomic_publish(tmp_path, monkeypatch):
    environment, spec_path, run, out = source_run(tmp_path)
    original = retained.verify_retained
    calls = []

    def verify(path):
        calls.append(path)
        assert path.name.startswith(".packet-download.partial-")
        assert not out.exists()
        return original(path)

    monkeypatch.setattr(retain.retained, "verify_retained", verify)

    retain.export(run, spec_path, out, environment)
    assert len(calls) == 1
    assert out.is_dir()


def test_an_empty_but_complete_alert_stream_is_retained(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    manager = load(spec_path).manager
    (run / "live/alerts.json").write_bytes(b"")
    write_collected(run, manager, "alerts", b"")

    retain.export(run, spec_path, out, environment)
    assert (out / f"files/raw/hosts/{manager}/var/ossec/logs/alerts/alerts.json").read_bytes() == b""


def test_refuses_a_live_wazuh_stream_that_differs_from_the_collected_logs(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    (run / "live/alerts.json").write_bytes(b"")

    with pytest.raises(retain.RetainError, match="live Wazuh alerts stream differs"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_refuses_packet_identity_bytes_above_the_fixed_limit(tmp_path, monkeypatch):
    environment, spec_path, run, out = source_run(tmp_path)
    monkeypatch.setattr(retain, "MAX_PCAP_BYTES", 1)

    with pytest.raises(retain.RetainError, match="above the 1-byte limit"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_refuses_an_oversized_non_packet_source_before_buffering_or_publication(tmp_path):
    environment, spec_path, run, out = source_run(tmp_path)
    oversized = run / "raw/steps/s01/oversized.bin"
    with oversized.open("wb") as stream:
        stream.truncate(retain.MAX_RETAINED_BYTES + 1)

    with pytest.raises(retain.RetainError, match="larger than the .* retained limit"):
        retain.export(run, spec_path, out, environment)
    assert not out.exists()


def test_file_plan_rejects_stored_run_and_artifact_collisions():
    payload = b"x"
    first = retain.PlannedFile(PurePosixPath("files/a"), PurePosixPath("raw/a"), "one", payload=payload)
    second = retain.PlannedFile(PurePosixPath("files/a"), PurePosixPath("raw/b"), "two", payload=payload)

    with pytest.raises(retain.RetainError, match="stored_path"):
        retain._validate_plan([first, second], PurePosixPath("lab/retained/fixture"))


def test_cli_reports_failure_without_leaving_a_partial_output(tmp_path, capsys):
    environment, spec_path, run, out = source_run(tmp_path)
    environment["GITHUB_EVENT_NAME"] = "push"

    assert retain.main(run, spec_path, out, environment) == 2
    assert "hosted workflow_dispatch" in capsys.readouterr().err
    assert not out.exists()

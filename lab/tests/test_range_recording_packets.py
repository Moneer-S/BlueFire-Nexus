"""Packet recording fixtures are normalized ECS made up for these tests; no range or rule engine runs."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bluefire_lab.range import ecs, recording, score
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
T0 = 1_795_000_000.0


def iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).isoformat()


def packet_event(number: int, *, protocol: str | None = None, message: str | None = None) -> dict:
    document = {
        "@timestamp": iso(T0 + 1 + number / 1_000),
        "event": {
            "id": f"network-web-eth0-{number:06d}",
            "kind": "event",
            "module": "suricata",
            "dataset": "suricata.eve",
            "category": ["network"],
            "type": ["connection"],
        },
        "observer": {"name": "web", "ingress": {"interface": {"name": "eth0"}}},
        "labels": {
            "sensor": "packet-capture-web",
            "origin": score.STEP,
            "step_id": "s01",
            "tied_by": "address",
        },
        "source": {"ip": "10.9.0.2", "domain": "attacker", "port": 40_000 + number},
        "destination": {"ip": "10.9.0.5", "domain": "web", "port": 22},
        "network": {"transport": "tcp", "bytes": 80 + number, "packets": 2},
        "suricata": {"flow_id": 18_446_744_073_709_551_000 + number},
    }
    if protocol:
        document["network"]["protocol"] = protocol
    if message:
        document["message"] = message
    return document


@pytest.mark.parametrize(
    ("parts", "kind", "text"),
    [
        (
            {"message": "10.9.0.2:40001 -> 10.9.0.5:22"},
            "network flow",
            "attacker:40001 → web:22 tcp: 2 packets, 81 bytes",
        ),
        (
            {
                "network": {"protocol": "http"},
                "http": {"request": {"method": "GET"}, "response": {"status_code": 404}},
                "url": {"path": "/admin"},
                "message": "GET http://10.9.0.5/admin returned 404",
            },
            "HTTP request",
            "GET http://web/admin returned 404",
        ),
        (
            {
                "network": {"protocol": "tls"},
                "tls": {"version": "TLS 1.3", "client": {"server_name": "web"}},
                "message": "TLS 1.3 to 10.9.0.5",
            },
            "TLS handshake",
            "TLS 1.3 to web",
        ),
        (
            {
                "network": {"protocol": "ssh"},
                "suricata": {"ssh": {"client": {"software_version": "OpenSSH_9.6"}}},
                "message": "OpenSSH_9.6 client connected to 10.9.0.5",
            },
            "SSH session",
            "SSH session attacker:40001 → web:22 tcp/ssh: 2 packets, 81 bytes; client OpenSSH_9.6",
        ),
        (
            {
                "network": {"protocol": "dns"},
                "dns": {"type": "query", "question": {"name": "web", "type": "A"}},
                "message": "A query for 10.9.0.5",
            },
            "DNS query",
            "A query for web",
        ),
        (
            {
                "network": {"protocol": "dns"},
                "dns": {
                    "type": "response",
                    "question": {"name": "web", "type": "A"},
                    "answers": [{"data": "10.9.0.5"}],
                },
                "message": "A response for 10.9.0.5",
            },
            "DNS query",
            "A response for web: 10.9.0.5",
        ),
    ],
)
def test_packet_events_use_the_capture_sensor_and_plain_words(parts: dict, kind: str, text: str) -> None:
    document = packet_event(1)
    for key, value in parts.items():
        if key in {"network", "suricata"}:
            document[key].update(value)
        else:
            document[key] = value

    found = recording.event_of(document, "s01", 1)

    assert (found["sensor"], found["host"], found["kind"], found["text"]) == (
        "packet-capture-web",
        "web",
        kind,
        text,
    )
    assert found["fields"]["ecs_event_id"] == "network-web-eth0-000001"
    assert found["fields"]["interface"] == "eth0"
    assert found["fields"]["flow_id"] == "18446744073709551001"
    assert all(not isinstance(value, (list, dict)) for value in found["fields"].values())
    assert recording.sensor_of({"host": {"name": "web"}}) == "wazuh-agent-web"


def write_lines(path: Path, documents: list[dict]) -> None:
    ecs.write(path, documents)


def test_lines_reads_lossless_gzip_and_refuses_corruption(tmp_path: Path) -> None:
    path = tmp_path / recording.NETWORK_EVENTS_FILE
    documents = [packet_event(1), packet_event(2)]
    assert ecs.write(path, documents) == 2
    assert recording.lines(path) == documents

    path.write_bytes(b"not a gzip stream")
    with pytest.raises(OSError):
        recording.lines(path)


def wazuh_event() -> dict:
    return {
        "@timestamp": iso(T0 + 1),
        "event": {
            "id": "wazuh-web-000001",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "original": "uname -a",
        },
        "host": {"name": "web"},
        "labels": {"origin": score.STEP, "step_id": "s01", "tied_by": "session"},
        "process": {"command_line": "uname -a"},
        "wazuh": {"location": "/var/log/snoopy.log", "decoder": {"name": "bluefire-snoopy"}},
    }


def packet_alert(number: int, level: str, rule: str, title: str) -> dict:
    return {
        "@timestamp": iso(T0 + 1 + number / 1_000),
        "event": {"kind": "alert", "module": "suricata", "dataset": "suricata.alert"},
        "observer": {"name": "web", "ingress": {"interface": {"name": "eth0"}}},
        "labels": {
            "sensor": "packet-capture-web",
            "origin": score.STEP,
            "step_id": "s01",
            "tied_by": "address",
            "event_id": f"network-web-eth0-{number:06d}",
            "level": level,
        },
        "rule": {"id": rule, "name": title, "ruleset": "et-open"},
    }


def judged_step(events: int, *, alerted: bool) -> dict:
    found = {
        "id": "s01",
        "visibility": "alert" if alerted else "telemetry only",
        "outcome": "alerted" if alerted else "seen",
        "events": events,
        "events by tie": {"address" if alerted else "session": events},
        "lines tied by address alone": [],
        "coincident events": 0,
        "matches": 2 if alerted else 0,
        "rules": [],
    }
    if alerted:
        moment = iso(T0 + 1.305)
        found["first_alert"] = {
            "moment": moment,
            "detector": "et-open",
            "rule": "1:2100365",
            "title": "ET scan",
            "level": "high",
        }
        found["rules"] = [
            {
                "detector": "et-open",
                "rule": "1:2100365",
                "title": "ET scan",
                "level": "high",
                "counts": True,
                "matches": 1,
                "first": moment,
                "on": {"s01 (web)": 1},
            },
            {
                "detector": "et-open",
                "rule": "1:2100366",
                "title": "ET scan review",
                "level": "informational",
                "counts": False,
                "matches": 1,
                "first": iso(T0 + 1.320),
                "on": {"s01 (web)": 1},
            },
        ]
    return found


def ordinary() -> dict:
    return {
        "scored": True,
        "not scored": None,
        "minutes": 1,
        "events": 0,
        "matches": [],
        "false alerts": 0,
    }


def manifest() -> dict:
    started, ended = iso(T0), iso(T0 + 10)
    stock = {
        "id": "wazuh-stock",
        "name": "Wazuh with its stock rules",
        "sensors": ["wazuh-agent-web"],
        "rules": ["wazuh"],
        "detectors": ["pinned"],
        "judged": True,
        "steps": [judged_step(1, alerted=False)],
        "ordinary": ordinary(),
    }
    packets = {
        "id": "packets-et-open",
        "name": "Packets on web, judged by Suricata with the ET Open rules",
        "sensors": ["packet-capture-web"],
        "rules": ["et-open"],
        "detectors": ["et-open"],
        "judged": True,
        "steps": [judged_step(320, alerted=True)],
        "ordinary": ordinary(),
    }
    return {
        "range": "range-one",
        "run_id": "20261101T000000Z-packets",
        "spec": {"file": "range-one.yaml", "text": RANGE_ONE.read_text(encoding="utf-8")},
        "environment": "made up for this test",
        "result": "sealed",
        "reason": None,
        "exit_code": 0,
        "containers": {},
        "images": {},
        "atomic_red_team": {"commit": "a" * 40},
        "weaknesses": [],
        "defense": {"wazuh_version": "4.14.10", "agents": ["web"], "manager": "manager"},
        "packet_capture": {
            "hosts": {"web": {"files": {"eth0.pcap": {"packets": 320}}}},
            "delivery_gap": True,
            "delivery_findings": ["web: eth0.pcap: 2 packets dropped by the kernel"],
        },
        "ecs": {
            "network": {
                "HOME_NET": ["10.9.0.0/24"],
                "captures": 1,
                "engine": {"name": "Suricata", "version": "7.0.3"},
            }
        },
        "path": {
            "planned": ["s01"],
            "steps": [
                {
                    "id": "s01",
                    "host": "web",
                    "to": [],
                    "account": "webadmin",
                    "technique": "T1046",
                    "guid": "00000000-0000-4000-8000-000000000001",
                    "name": "Network Service Scanning",
                    "plain": "Scans the web host's ports.",
                    "argv": ["sh", "-c", "scan web"],
                    "happened": "took effect",
                    "why": "the scan completed",
                    "started_ns": int(T0 * 1e9),
                    "ended_ns": int((T0 + 10) * 1e9),
                    "started": started,
                    "ended": ended,
                    "time_source": "daemon",
                }
            ],
            "goal": {"plain": "the web host's services are found", "after": "s01", "passed": True},
            "notes": [],
        },
        "score": {
            "defenses named": True,
            "defenses": [stock, packets],
            "rule sets": {
                "et-open": {
                    "kind": "suricata",
                    "source": "lab/rules/et-open/SHA256SUMS@11342",
                    "source type": "tracked",
                    "repository authored": False,
                    "when": score.AFTER,
                    "evaluated": True,
                    "engine": {"name": "Suricata", "version": "7.0.3"},
                    "digest": "d" * 64,
                    "rules": 2,
                    "loaded": 2,
                    "file": "alerts.et-open.ecs.ndjson",
                    "lines": 2,
                    "rules that matched": [
                        {"rule": "1:2100365", "title": "ET scan"},
                        {"rule": "1:2100366", "title": "ET scan review"},
                    ],
                }
            },
            "path": {
                "steps": [{"id": "s01"}],
                "alert_level": 12,
                "race": {"start": started, "result": True, "says": "alert before goal"},
                "clock": {"program starts checked": 0},
                "notes": [],
                "events": {},
            },
        },
    }


def test_packet_cut_keeps_each_sensor_share_and_every_rule_match(tmp_path: Path) -> None:
    made_up = manifest()
    spec_document = range_spec.read(made_up["spec"]["text"])
    executor = spec_document["executor"]["commit"]
    chunks = [executor[place : place + 8] for place in range(0, 40, 8)]
    scalar = f"  commit: {executor}  # pragma: allowlist secret"
    chunked = "  commit: [" + ", ".join(f"{chr(34)}{part}{chr(34)}" for part in chunks) + "]"
    assert made_up["spec"]["text"].count(scalar) == 1
    made_up["spec"]["text"] = made_up["spec"]["text"].replace(scalar, chunked)
    (tmp_path / "manifest.json").write_text(json.dumps(made_up), encoding="utf-8")
    write_lines(
        tmp_path / "docker-events.ndjson",
        [{"timeNano": int((T0 - 1) * 1e9)}, {"timeNano": int((T0 + 11) * 1e9)}],
    )
    manager = tmp_path / "raw" / "hosts" / "manager" / "var" / "ossec" / "logs"
    manager.mkdir(parents=True)
    (manager / "ossec.log").write_text("Total rules enabled: '100'\n", encoding="utf-8")
    web_log = tmp_path / "raw" / "hosts" / "web" / "var" / "log"
    web_log.mkdir(parents=True)
    (web_log / "dpkg.log").write_text("2026-11-01 00:00:00 install tcpdump:amd64 <none> 4.99.4-3ubuntu4\n")
    write_lines(tmp_path / score.EVENTS_FILE, [wazuh_event()])
    write_lines(
        tmp_path / recording.NETWORK_EVENTS_FILE, list(reversed([packet_event(n) for n in range(1, 321)]))
    )
    write_lines(
        tmp_path / score.MATCHES_FILE.format("et-open"),
        [
            packet_alert(305, "high", "1:2100365", "ET scan"),
            packet_alert(320, "informational", "1:2100366", "ET scan review"),
        ],
    )

    made = recording.build(tmp_path)

    assert [(sensor["id"], sensor["host"]) for sensor in made["network"]["sensors"]] == [
        ("wazuh-agent-web", "web"),
        ("packet-capture-web", "web"),
    ]
    packet_sensor = next(
        sensor for sensor in made["network"]["sensors"] if sensor["id"] == "packet-capture-web"
    )
    assert packet_sensor["records"] == (
        "every packet web sent or received on its captured range interfaces, except Wazuh agent traffic "
        "to the manager on ports 1514 and 1515"
    )
    detector = next(entry for entry in made["network"]["detectors"] if entry["id"] == "et-open")
    assert (detector["rules"], detector["when"]) == (2, "after the run")
    assert detector["name"] == (
        "Published packet rules (lab/rules/et-open/SHA256SUMS at 11342) with Suricata 7.0.3"
    )
    assert (
        "The detector et-open is the published rule set lab/rules/et-open/SHA256SUMS at version 11342"
    ) in " ".join(made["notes"])
    held = {
        event["fields"]["ecs_event_id"] for event in made["events"] if event["sensor"] == "packet-capture-web"
    }
    assert held == {
        *(f"network-web-eth0-{number:06d}" for number in range(1, 300)),
        "network-web-eth0-000305",
        "network-web-eth0-000320",
    }
    assert len(made["events"]) == 302
    stock, packets = made["defenses"]
    stock_visibility = stock["steps"]["s01"]["visibility"]
    assert stock_visibility["answer"] == "telemetry only"
    assert stock_visibility["events"] == 1
    packet_visibility = packets["steps"]["s01"]["visibility"]
    assert packet_visibility["answer"] == "alert"
    assert packet_visibility["events"] == 320
    assert packet_visibility["kept"] == 301
    matches = [alert for alert in made["alerts"] if alert["detector"] == "et-open"]
    assert len(matches) == 2
    assert all(alert["host"] == "web" and alert["events"] and "raised" not in alert for alert in matches)
    assert {alert["rule"]["level"] for alert in matches} == {"high", "informational"}
    assert "Packet capture has a delivery gap" in " ".join(made["notes"])
    assert any(f"Invoke-AtomicRedTeam {executor} does;" in note for note in made["notes"])
    assert all(str(chunks) not in note for note in made["notes"])
    tools = {(tool["name"], tool["version"], tool["role"]) for tool in made["source"]["tools"]}
    assert {
        ("tcpdump", "4.99.4-3ubuntu4", "sensor"),
        ("Suricata", "7.0.3", "rule engine"),
        ("et-open", "11342", "rules"),
    } <= tools

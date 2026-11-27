"""Focused scoring contracts for retained packet telemetry.

These inputs are deliberately small and made up. They test attribution and
orchestration, not a claimed range result or the Suricata adapter itself.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone

import pytest

from bluefire_lab.range import activity, score, suricata
from bluefire_lab.range.spec import PACKET_CAPTURE, WAZUH_AGENT, Defense, RuleSet


def iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).isoformat()


def network_event(
    source: str,
    destination: str,
    started: float,
    ended: float,
    *,
    source_port: int = 41000,
    destination_port: int = 80,
    protocol: str = "http",
) -> dict:
    return {
        "@timestamp": iso(started),
        "event": {"start": iso(started), "end": iso(ended), "id": "network-1"},
        "observer": {"name": "web"},
        "source": {"ip": source, "port": source_port},
        "destination": {"ip": destination, "port": destination_port},
        "network": {"transport": "tcp", "protocol": protocol},
        "labels": {"sensor": "packet-capture-web", "origin": "unattributed"},
    }


def test_step_peers_come_only_from_recorded_targets_and_arguments(tmp_path):
    records = {
        "download": {
            "id": "s02",
            "host": "web",
            "to": [],
            "args": {"remote_url": "http://inet/atomics/payload.sh"},
            "started_ns": 1_000_000_000,
            "ended_ns": 2_000_000_000,
        },
        "ssh": {
            "id": "s08",
            "host": "web",
            "to": "build",
            "args": {"domain": "deploy@build"},
            "started_ns": 3_000_000_000,
            "ended_ns": 4_000_000_000,
        },
        "local": {
            "id": "s03",
            "host": "web",
            "to": [],
            "args": {"output_file": "/tmp/result"},
            "started_ns": 5_000_000_000,
            "ended_ns": 6_000_000_000,
        },
    }

    stretches, _ = score.stretches({"steps": list(records.values())}, tmp_path)

    assert {stretch.step: stretch.peers for stretch in stretches} == {
        "s02": ("inet",),
        "s08": ("build",),
        "s03": (),
    }


def test_ordinary_and_step_candidates_are_ambiguous_not_precedence_choices():
    addresses = {
        "client": ["10.0.0.2"],
        "web": ["10.0.0.3"],
        "db": ["10.0.0.4"],
    }
    jobs = activity.Activity(
        1,
        0,
        0,
        (
            activity.Job(
                "shop",
                "client",
                "customer",
                (1, 1),
                "http",
                "web",
                paths=("/",),
            ),
        ),
    )
    step = score.Stretch("scan-db", "web", ("db",), 100.0, 110.0, peers=("db",))
    downstream = network_event(
        "10.0.0.3",
        "10.0.0.4",
        102.0,
        103.0,
        destination_port=3306,
        protocol="mysql",
    )

    ordinary = score.network_attributed(
        [downstream.copy()],
        jobs,
        addresses,
        {"client": 90.0},
        {"client": 120.0},
        [],
        home_net=["10.0.0.3", "10.0.0.4"],
    )
    ambiguous = score.network_attributed(
        [downstream],
        jobs,
        addresses,
        {"client": 90.0},
        {"client": 120.0},
        [step],
        home_net=["10.0.0.3", "10.0.0.4"],
    )
    partial = score.network_attributed(
        [
            network_event(
                "10.0.0.3",
                "10.0.0.4",
                95.0,
                105.0,
                destination_port=3306,
                protocol="mysql",
            )
        ],
        jobs,
        addresses,
        {"client": 90.0},
        {"client": 120.0},
        [step],
        home_net=["10.0.0.3", "10.0.0.4"],
    )

    assert ordinary == [(score.ORDINARY, "shop", None, None)]
    assert ambiguous == [(score.UNATTRIBUTED, None, "scan-db", "window")]
    assert partial == [(score.UNATTRIBUTED, None, "scan-db", "window")]


def test_no_declared_peer_and_overlapping_steps_do_not_claim_a_network_event():
    addresses = {"web": ["10.0.0.3"], "db": ["10.0.0.4"]}
    event = network_event("10.0.0.3", "10.0.0.4", 102.0, 103.0, destination_port=3306, protocol="mysql")
    local = score.Stretch("local", "web", (), 100.0, 110.0)
    first = score.Stretch("first", "web", ("db",), 100.0, 110.0, peers=("db",))
    second = score.Stretch("second", "web", ("db",), 101.0, 111.0, peers=("db",))

    assert score.network_attributed([event.copy()], None, addresses, {}, {}, [local]) == [
        (score.UNATTRIBUTED, None, None, None)
    ]
    assert score.network_attributed([event], None, addresses, {}, {}, [first, second]) == [
        (score.UNATTRIBUTED, None, None, None)
    ]


def test_only_the_exact_udp_ready_mark_is_engine_traffic():
    marked = network_event(
        "10.0.0.3",
        "10.0.0.4",
        100.0,
        100.1,
        destination_port=62001,
        protocol="",
    )
    marked["network"]["transport"] = "udp"
    marked["observer"]["ingress"] = {"interface": {"name": "eth0"}}
    capture = {
        "hosts": {
            "web": {
                "ready": [
                    {
                        "seen": True,
                        "interface": "eth0",
                        "source": "10.0.0.3",
                        "destination": "10.0.0.4",
                        "port": 62001,
                    }
                ]
            }
        }
    }

    assert score.network_attributed([marked.copy()], None, {}, {}, {}, [], capture) == [
        (score.ENGINE, None, None, None)
    ]
    wrong_transport = {**marked, "network": {**marked["network"], "transport": "tcp"}}
    wrong_interface = {
        **marked,
        "observer": {**marked["observer"], "ingress": {"interface": {"name": "eth1"}}},
    }
    assert score.network_attributed([wrong_transport, wrong_interface], None, {}, {}, {}, [], capture) == [
        (score.UNATTRIBUTED, None, None, None),
        (score.UNATTRIBUTED, None, None, None),
    ]


def _day() -> dict:
    return {
        "scored": True,
        "not scored": None,
        "denominators": {
            "minutes of activity": 5,
            "runs of each job": {"shop": {"runs": 1, "archived runs": 1}},
        },
    }


def _match(detector: str, sensor: str) -> dict:
    return {
        "detector": detector,
        "rule": detector,
        "title": detector,
        "level": "high" if detector != score.PINNED else 12,
        "counts": True,
        "moment": iso(100.0),
        "host": "web",
        "sensor": sensor,
        "origin": score.ORDINARY,
        "job": "shop",
        "step": None,
        "tied_by": None,
    }


def test_defenses_on_one_host_count_only_their_own_sensor_kind():
    wazuh_event = {"agent": {"name": "web"}}
    packet_event = network_event("10.0.0.2", "10.0.0.3", 100.0, 101.0)
    ties = [(score.ORDINARY, "shop", None, None)] * 2
    hosts = {WAZUH_AGENT: ["web"], PACKET_CAPTURE: ["web"]}
    malformed = _match(score.PINNED, "wazuh-agent-web")
    del malformed["sensor"]
    matches = {
        score.PINNED: [_match(score.PINNED, "wazuh-agent-web"), malformed],
        "packets": [_match("packets", "packet-capture-web")],
    }

    wazuh = score.judge(
        Defense("wazuh", "Wazuh", (WAZUH_AGENT,), (score.WAZUH_RULES,)),
        hosts,
        matches,
        [wazuh_event, packet_event],
        ties,
        None,
        set(),
        True,
        _day(),
    )
    packets = score.judge(
        Defense("packets", "Packets", (PACKET_CAPTURE,), ("packets",)),
        hosts,
        matches,
        [wazuh_event, packet_event],
        ties,
        None,
        set(),
        True,
        _day(),
    )

    assert wazuh["ordinary"]["events"] == 1
    assert packets["ordinary"]["events"] == 1
    assert [rule["detector"] for rule in wazuh["ordinary"]["matches"]] == [score.PINNED]
    assert wazuh["ordinary"]["matches"][0]["matches"] == 1
    assert [rule["detector"] for rule in packets["ordinary"]["matches"]] == ["packets"]


def test_capture_closure_checks_manifest_set_and_digest(tmp_path, monkeypatch):
    folder = tmp_path / "raw" / "hosts" / "web" / score.packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    capture = folder / "eth0.pcap"
    capture.write_bytes(b"classic pcap checked by the adapter seam")
    relative = capture.relative_to(tmp_path).as_posix()
    manifest = {"hosts": {"web": {"files": {"eth0.pcap": {"file": relative}}}}}
    monkeypatch.setattr(score.suricata, "capture_files", lambda _: (capture,))

    _, retained = score.capture_inputs(tmp_path, manifest)
    assert retained[0]["integrity"] == "retained closure"

    manifest["hosts"]["web"]["files"]["eth0.pcap"]["sha256"] = hashlib.sha256(
        capture.read_bytes()
    ).hexdigest()
    _, retained = score.capture_inputs(tmp_path, manifest)
    assert retained[0]["integrity"] == "sha256"

    manifest["hosts"]["web"]["files"]["eth0.pcap"]["sha256"] = "0" * 64
    with pytest.raises(suricata.SuricataError, match="recorded SHA-256"):
        score.capture_inputs(tmp_path, manifest)


def test_retained_home_net_is_validated_and_old_runs_name_the_fallback():
    addresses = {"web": ["10.0.0.3"], "db": ["10.0.0.4"], "attacker": ["10.0.0.9"]}
    retained = {
        "home_hosts": ["db", "web"],
        "home_net": ["10.0.0.3", "10.0.0.4"],
    }

    assert score.packet_home_net(retained, addresses, ["db", "web"], ["web"]) == (
        ["10.0.0.3", "10.0.0.4"],
        "manifest packet_capture.home_net",
    )
    assert score.packet_home_net({}, addresses, ["db", "web"], ["web"]) == (
        ["10.0.0.3", "10.0.0.4"],
        "recorded addresses compatibility fallback",
    )
    with pytest.raises(suricata.SuricataError, match="protected recorded hosts"):
        score.packet_home_net(
            {**retained, "home_net": ["10.0.0.3", "10.0.0.9"]},
            addresses,
            ["db", "web"],
            ["web"],
        )


def test_endpoint_host_names_are_added_only_for_unambiguous_recorded_addresses():
    document = {
        "source": {"ip": "10.0.0.2"},
        "destination": {"ip": "10.0.0.3"},
    }

    score.name_network_endpoints(
        document,
        {"client": ["10.0.0.2"], "web": ["10.0.0.3"], "alias": ["10.0.0.3"]},
    )

    assert document["source"]["domain"] == "client"
    assert "domain" not in document["destination"]


def test_suricata_match_keeps_the_canonical_event_sensor_id_and_tie(tmp_path, monkeypatch):
    key = ["transaction", "eth0.pcap", "1:test", "http", 7]
    alert = {"event_type": "alert", "alert": {"severity": 1}}
    parent = {
        "@timestamp": iso(100.0),
        "event": {"id": "network-web-eth0-000001"},
        "observer": {"name": "web"},
        "labels": {
            "sensor": "packet-capture-web",
            "origin": score.STEP,
            "step_id": "s02",
            "tied_by": "address",
        },
    }
    engine = {"name": "Suricata", "version": "8.0.8", "image": "pinned"}
    monkeypatch.setattr(score.rulesets, "held", lambda *args: tmp_path / "rules")
    monkeypatch.setattr(score.rulesets, "digest", lambda *args: "digest")
    monkeypatch.setattr(
        score.suricata,
        "evaluate",
        lambda *args, **kwargs: {
            "engine": engine,
            "rules": 1,
            "rule file count": 1,
            "rule files": ["rules/test.rules"],
            "loaded": 1,
            "failed": 0,
            "load errors": [],
            "records": [],
            "alerts": [alert],
            "alert event keys": [key],
        },
    )

    def alert_mapper(raw, event_document, rule_set, *, engine):
        assert raw is alert
        assert event_document is parent
        assert rule_set == "packet-set"
        return {
            "@timestamp": iso(101.0),
            "rule": {"id": "1:999", "name": "packet match"},
            "labels": {
                **event_document["labels"],
                "event_id": event_document["event"]["id"],
                "level": "high",
            },
        }

    monkeypatch.setattr(score.ecs, "network_alert", alert_mapper)
    monkeypatch.setattr(score.ecs, "write", lambda path, documents: len(documents))

    result, matches = score.after_suricata(
        tmp_path,
        RuleSet("packet-set", "suricata", repo="example/rules", commit="a" * 40),
        "suricata:test@sha256:" + "a" * 64,
        {},
        {"web": tmp_path / "captures"},
        ["10.0.0.3"],
        [parent],
        [(score.STEP, None, "s02", "address")],
        {("web", score._frozen(key)): 0},
    )

    assert result["evaluated"] is True
    assert result["rule file count"] == 1
    assert result["rule files"] == ["rules/test.rules"]
    assert result["load errors"] == []
    assert matches is not None
    assert {name: matches[0][name] for name in ("sensor", "event_id", "origin", "step", "tied_by")} == {
        "sensor": "packet-capture-web",
        "event_id": "network-web-eth0-000001",
        "origin": score.STEP,
        "step": "s02",
        "tied_by": "address",
    }


def test_network_telemetry_records_exact_compressed_file_identity(tmp_path, monkeypatch):
    raw = {"pcap_filename": "/captures/eth0.pcap"}
    document = network_event("10.0.0.2", "10.0.0.3", 100.0, 101.0)
    document["event"]["id"] = "network-web-eth0-000001"
    engine = {"name": "Suricata", "version": "8.0.8", "image": "example@sha256:" + "a" * 64}
    captures = tmp_path / "captures"

    monkeypatch.setattr(
        score,
        "capture_inputs",
        lambda out, capture: ({"web": captures}, [{"file": "raw/hosts/web/packets/eth0.pcap"}]),
    )
    monkeypatch.setattr(score, "packet_home_net", lambda *args: (["10.0.0.3"], "manifest"))
    monkeypatch.setattr(
        score.suricata,
        "telemetry",
        lambda *args: {
            "records": [raw],
            "alerts": [],
            "alert event keys": [],
            "engine": engine,
            "read": 1,
        },
    )
    monkeypatch.setattr(
        score.suricata,
        "record_index",
        lambda records: {("eth0.pcap", 1): records[0]},
    )
    monkeypatch.setattr(
        score.suricata,
        "event_key",
        lambda record: pytest.fail("score recomputed a context-free event key"),
    )
    monkeypatch.setattr(score, "_capture_interface", lambda record: "eth0")
    monkeypatch.setattr(score, "_network_event_document", lambda *args: document)
    monkeypatch.setattr(
        score,
        "network_attributed",
        lambda *args: [(score.UNATTRIBUTED, None, None, None)],
    )

    section, documents, ties, places, folders, home_net = score.network_telemetry(
        tmp_path,
        engine["image"],
        {},
        {},
        None,
        None,
        {},
        {},
        [],
    )

    path = tmp_path / score.NETWORK_EVENTS_FILE
    assert section["file"] == "events.network.ecs.ndjson.gz"
    assert section["bytes"] == path.stat().st_size
    assert section["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert section["lines"] == 1
    with gzip.open(path, "rt", encoding="utf-8") as source:
        assert [json.loads(line) for line in source] == [document]
    assert documents == [document]
    assert ties == [(score.UNATTRIBUTED, None, None, None)]
    assert list(places) == [("web", ("eth0.pcap", 1))]
    assert list(places.values()) == [0]
    assert folders == {"web": captures}
    assert home_net == ["10.0.0.3"]


def test_record_dispatches_each_rule_kind_and_removes_stale_network_output(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    (logs / "archives").mkdir(parents=True)
    (logs / "alerts").mkdir()
    stale_network = tmp_path / score.NETWORK_EVENTS_FILE
    stale_network.write_text("old\n", encoding="utf-8")
    stale_plain_network = tmp_path / score.LEGACY_NETWORK_EVENTS_FILE
    stale_plain_network.write_text("old\n", encoding="utf-8")
    (tmp_path / "alerts.old.ecs.ndjson").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(score.wazuh, "daily_files", lambda folder: [folder / "fake.json"])
    monkeypatch.setattr(score.ecs, "read", lambda paths: ([], []))
    monkeypatch.setattr(score.ecs, "write", lambda path, documents: len(documents))
    calls: list[str] = []

    def telemetry(*args, **kwargs):
        calls.append("telemetry")
        return (
            {
                "evaluated": True,
                "captures": [{"file": "raw/hosts/web/packets/eth0.pcap"}],
                "lines": 1,
            },
            [network_event("10.0.0.2", "10.0.0.3", 100.0, 101.0)],
            [(score.UNATTRIBUTED, None, None, None)],
            {("key",): 0},
            {"web": tmp_path / "captures"},
            ["10.0.0.3"],
        )

    def sigma_set(*args, **kwargs):
        calls.append("sigma")
        return {"evaluated": True}, []

    def suricata_set(*args, **kwargs):
        calls.append("suricata")
        return {"evaluated": True}, []

    monkeypatch.setattr(score, "network_telemetry", telemetry)
    monkeypatch.setattr(score, "after_the_run", sigma_set)
    monkeypatch.setattr(score, "after_suricata", suricata_set)

    section, result = score.record(
        tmp_path,
        logs,
        "run",
        12,
        rule_sets=(RuleSet("sigma-set", "sigma"), RuleSet("packet-set", "suricata")),
        packet_capture={"hosts": {"web": {}}},
        suricata_image="suricata:test@sha256:" + "a" * 64,
    )

    assert section["error"] is None
    assert result is not None
    assert calls == ["telemetry", "sigma", "suricata"]
    assert not stale_network.exists()
    assert not stale_plain_network.exists()
    assert not (tmp_path / "alerts.old.ecs.ndjson").exists()


def test_packet_rule_set_summary_reports_partial_loads_without_sigma_groups():
    manifest = {
        "range": "one",
        "result": "sealed",
        "score": {
            "rule sets": {
                "packet-set": {
                    "kind": "suricata",
                    "source": "example/rules@" + "a" * 40,
                    "evaluated": True,
                    "engine": {"name": "Suricata", "version": "8.0.8"},
                    "rules": 3,
                    "rule file count": 2,
                    "rule files": ["rules/one.rules", "rules/two.rules"],
                    "loaded": 2,
                    "failed": 1,
                    "load errors": ["one rule could not be parsed"],
                    "file": "alerts.packet-set.ecs.ndjson",
                    "lines": 1,
                    "runs": [
                        {
                            "host": "web",
                            "read counts": {
                                "capture files": 1,
                                "packets": 4,
                                "network records": 1,
                                "alerts": 1,
                            },
                        }
                    ],
                    "rules that matched": [
                        {
                            "rule": "1:990001",
                            "title": "Made-up packet rule",
                            "level": "high",
                            "counts": True,
                            "matches": 1,
                            "on": {"s02 (web)": 1},
                        }
                    ],
                }
            }
        },
    }

    written = "\n".join(score.rule_sets_summary(manifest))

    assert "retained packet captures" in written
    assert "2 loaded and 1 failed" in written
    assert "one rule could not be parsed" in written
    assert "Made-up packet rule" in written

"""Made-up EVE fixtures exercise the packet mapper; they are never presented as range results."""

import copy
from pathlib import Path

import pytest
import yaml

from bluefire_lab.range import ecs

FIXTURE = Path(__file__).parent / "fixtures" / "range" / "ecs" / "ecs-8.17.0-fields.yml"
PINNED = yaml.safe_load(FIXTURE.read_text())
ENGINE = {"name": "Suricata", "version": "8.0.8", "image": "made-up-pinned-image"}


def eve(kind: str, detail: dict, *, app_proto: str | None = None) -> dict:
    raw = {
        "timestamp": "2026-11-26T20:00:00.200000+00:00",
        "flow_id": 7,
        "event_type": kind,
        "pcap_filename": "/captures/eth0.pcap",
        "src_ip": "10.9.0.2",
        "src_port": 44_444,
        "dest_ip": "10.9.0.3",
        "dest_port": 80,
        "proto": "TCP",
        "community_id": "1:made-up-community",
        kind: detail,
    }
    if app_proto:
        raw["app_proto"] = app_proto
    return raw


def http_raw() -> dict:
    return eve(
        "http",
        {
            "hostname": "web.example.test",
            "url": "/download/tool",
            "http_user_agent": "curl/8.5.0",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200,
        },
        app_proto="http",
    )


def parent_event() -> dict:
    return ecs.network_event(
        http_raw(),
        "web",
        "eth0",
        "network-2",
        "ordinary",
        "browse",
        "s01",
        "window",
        ENGINE,
    )


def alert_raw(severity: int = 1, action: str = "allowed") -> dict:
    raw = eve("alert", {}, app_proto="http")
    raw.pop("alert")
    raw["timestamp"] = "2026-11-26T20:00:00.210000+00:00"
    raw["alert"] = {
        "action": action,
        "gid": 1,
        "signature_id": 2_001_219,
        "rev": 7,
        "signature": "ET MADE UP HTTP tool download",
        "category": "Made Up Activity",
        "severity": severity,
    }
    return raw


def test_a_flow_is_packet_sensor_telemetry_with_directional_and_total_counts() -> None:
    raw = eve(
        "flow",
        {
            "start": "2026-11-26T20:00:00.100000+00:00",
            "end": "2026-11-26T20:00:01.600000+00:00",
            "pkts_toserver": 2,
            "pkts_toclient": 1,
            "bytes_toserver": 90,
            "bytes_toclient": 50,
        },
        app_proto="http",
    )
    # Offline analysis can flush a flow long after its last captured packet.
    raw["timestamp"] = "2026-11-26T20:12:00.000000+00:00"

    mapped = ecs.network_event(
        raw,
        "web",
        "eth0",
        "network-1",
        "step",
        step="s01",
        tied_by="endpoint",
        engine=ENGINE,
    )

    assert mapped["@timestamp"] == "2026-11-26T20:00:01.600000Z"
    assert mapped["event"] == {
        "kind": "event",
        "id": "network-1",
        "dataset": "suricata.eve",
        "module": "suricata",
        "category": ["network"],
        "type": ["connection"],
        "start": "2026-11-26T20:00:00.100000Z",
        "end": "2026-11-26T20:00:01.600000Z",
        "duration": 1_500_000_000,
    }
    assert mapped["observer"] == {
        "name": "web",
        "vendor": "OISF",
        "product": "Suricata",
        "type": "ids",
        "version": "8.0.8",
        "ingress": {"interface": {"name": "eth0"}},
    }
    assert mapped["host"] == {"name": "web"}
    assert mapped["source"] == {"ip": "10.9.0.2", "port": 44_444, "packets": 2, "bytes": 90}
    assert mapped["destination"] == {"ip": "10.9.0.3", "port": 80, "packets": 1, "bytes": 50}
    assert mapped["network"] == {
        "type": "ipv4",
        "transport": "tcp",
        "protocol": "http",
        "community_id": "1:made-up-community",
        "packets": 3,
        "bytes": 140,
    }
    assert mapped["related"]["ip"] == ["10.9.0.2", "10.9.0.3"]
    assert mapped["message"] == "TCP 10.9.0.2:44444 to 10.9.0.3:80: 3 packets, 140 bytes"
    assert mapped["labels"] == {
        "origin": "step",
        "time_source": "pcap-flow-end",
        "sensor": "packet-capture-web",
        "step_id": "s01",
        "tied_by": "endpoint",
    }
    assert mapped["suricata"] == raw and mapped["suricata"] is not raw
    assert mapped["suricata"]["timestamp"] == "2026-11-26T20:12:00.000000+00:00"


@pytest.mark.parametrize(
    ("missing", "message"),
    [("start", "flow.start"), ("end", "flow.end")],
)
def test_a_flow_requires_both_intrinsic_packet_boundaries(missing: str, message: str) -> None:
    raw = eve(
        "flow",
        {
            "start": "2026-11-26T20:00:00.100000+00:00",
            "end": "2026-11-26T20:00:01.600000+00:00",
        },
    )
    raw["flow"].pop(missing)

    with pytest.raises(ecs.ConversionError, match=message):
        ecs.network_event(raw, "web", "eth0", "network-missing-boundary", "unattributed")


def test_protocol_records_map_http_tls_ssh_and_dns_evidence() -> None:
    http = ecs.network_event(http_raw(), "web", "eth0", "network-http", "ordinary", engine=ENGINE)
    tls = ecs.network_event(
        eve("tls", {"sni": "web.example.test", "version": "TLS 1.3"}, app_proto="tls"),
        "web",
        "eth0",
        "network-tls",
        "ordinary",
        engine=ENGINE,
    )
    ssh = ecs.network_event(
        eve(
            "ssh",
            {
                "client": {"proto_version": "2.0", "software_version": "OpenSSH_9.6"},
                "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.3"},
            },
            app_proto="ssh",
        ),
        "web",
        "eth0",
        "network-ssh",
        "ordinary",
        engine=ENGINE,
    )
    dns_raw = eve(
        "dns",
        {
            "type": "answer",
            "id": 12,
            "rrname": "web.example.test",
            "rrtype": "A",
            "rcode": "NOERROR",
            "answers": [{"rrname": "web.example.test", "rrtype": "A", "rdata": "10.9.0.3", "ttl": 60}],
        },
        app_proto="dns",
    )
    dns_raw.update(proto="UDP", src_port=53, dest_port=53_000)
    dns = ecs.network_event(dns_raw, "web", "eth0", "network-dns", "ordinary", engine=ENGINE)

    assert all(document["@timestamp"] == "2026-11-26T20:00:00.200000Z" for document in (http, tls, ssh, dns))
    assert all(document["labels"]["time_source"] == "pcap" for document in (http, tls, ssh, dns))
    assert http["event"]["type"] == ["protocol"]
    assert http["http"] == {
        "request": {"method": "GET"},
        "response": {"status_code": 200},
        "version": "1.1",
    }
    assert http["url"] == {
        "original": "/download/tool",
        "path": "/download/tool",
        "domain": "web.example.test",
    }
    assert http["user_agent"] == {"original": "curl/8.5.0"}
    assert http["message"] == "HTTP GET /download/tool returned 200; user agent curl/8.5.0"
    assert tls["tls"] == {
        "client": {"server_name": "web.example.test"},
        "version": "1.3",
        "version_protocol": "tls",
    }
    assert tls["message"] == "TLS server web.example.test, version 1.3"
    assert ssh["network"]["protocol"] == "ssh"
    assert ssh["message"] == "SSH client 2.0 / OpenSSH_9.6; server 2.0 / OpenSSH_9.3"
    assert "ssh" not in ssh
    assert dns["dns"] == {
        "id": "12",
        "type": "answer",
        "question": {"name": "web.example.test", "type": "A"},
        "response_code": "NOERROR",
        "answers": [{"name": "web.example.test", "type": "A", "data": "10.9.0.3", "ttl": 60}],
        "resolved_ip": ["10.9.0.3"],
    }
    assert dns["message"] == "DNS response A web.example.test (NOERROR): 10.9.0.3"
    assert all(len(document["message"]) <= ecs.NETWORK_MESSAGE_LIMIT for document in (http, tls, ssh, dns))


def test_an_alert_inherits_the_exact_packet_event_tie_and_sensor_without_an_event_created() -> None:
    parent = parent_event()
    parent["source"]["domain"] = "client"
    parent["destination"]["domain"] = "web"
    raw = alert_raw()

    mapped = ecs.network_alert(raw, parent, "et-open", engine=ENGINE)

    assert mapped["@timestamp"] == "2026-11-26T20:00:00.210000Z"
    assert mapped["event"] == {
        "kind": "alert",
        "dataset": "suricata.alert",
        "module": "suricata",
        "category": ["network", "intrusion_detection"],
        "type": ["allowed"],
        "action": "allowed",
        "severity": 1,
    }
    assert "created" not in mapped["event"] and "id" not in mapped["event"]
    assert mapped["labels"] == {
        "origin": "ordinary",
        "time_source": "pcap",
        "job": "browse",
        "sensor": "packet-capture-web",
        "step_id": "s01",
        "tied_by": "window",
        "event_id": "network-2",
        "level": "high",
    }
    assert mapped["source"] == parent["source"] and mapped["destination"] == parent["destination"]
    assert mapped["observer"] == parent["observer"]
    assert mapped["rule"] == {
        "id": "1:2001219",
        "name": "ET MADE UP HTTP tool download",
        "description": "Made Up Activity",
        "ruleset": "et-open",
        "version": "7",
    }
    assert mapped["suricata"] == raw and mapped["suricata"] is not raw


@pytest.mark.parametrize(
    ("priority", "level"),
    [(1, "high"), (2, "medium"), (3, "low"), (4, "informational")],
)
def test_alert_priority_has_the_recordings_level_words(priority: int, level: str) -> None:
    assert ecs.network_alert(alert_raw(priority), parent_event(), "et-open")["labels"]["level"] == level


def test_network_documents_use_only_the_pinned_ecs_8_17_fields_and_categories() -> None:
    event = parent_event()
    alert = ecs.network_alert(alert_raw(), event, "et-open", engine=ENGINE)
    fields = PINNED["fields"]

    assert PINNED["tag"] == f"v{ecs.VERSION}"
    assert {name: kind for name, kind in ecs.FIELDS.items() if fields.get(name) != kind} == {}
    for document in (event, alert):
        assert "suricata" in ecs.names(document)
        for name in set(ecs.names(document)) - {"labels", "suricata"}:
            assert name in ecs.FIELDS and fields[name] == ecs.FIELDS[name]
        categorization = document["event"]
        assert set(categorization["category"]) <= set(PINNED["allowed_values"]["event.category"])
        assert set(categorization["type"]) <= set(PINNED["allowed_values"]["event.type"])
        for category in categorization["category"]:
            assert set(categorization["type"]) <= set(PINNED["expected_event_types"][category])


def test_raw_suricata_evidence_is_opaque_to_ecs_field_validation() -> None:
    raw = http_raw()
    raw["made_up_new_suricata_field"] = {"nested": {"anything": True}}

    mapped = ecs.network_event(raw, "web", "eth0", "network-raw", "unattributed")

    assert mapped["suricata"] == copy.deepcopy(raw)
    assert "suricata.made_up_new_suricata_field.nested.anything" not in ecs.names(mapped)

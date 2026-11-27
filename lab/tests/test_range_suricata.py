"""Offline Suricata reads held PCAPs and rules without inventing network evidence."""

import json
import re
import struct
import subprocess
from pathlib import Path

import pytest

from bluefire_lab.range import suricata


def write_pcap(path: Path) -> None:
    payload = b"made-up-packet"
    path.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 262_144, 1)
        + struct.pack("<IIII", 1_700_000_000, 1, len(payload), len(payload))
        + payload
    )


def held_rules(path: Path) -> None:
    (path / "nested").mkdir(parents=True)
    (path / "classification.config").write_text("config classification: made-up,A made-up class,1\n")
    (path / "one.rules").write_text('alert tcp any any -> any any (msg:"one"; sid:1; rev:1;)\n')
    (path / "nested" / "two.rules").write_text('alert udp any any -> any any (msg:"two"; sid:2; rev:1;)\n')


def network(
    kind: str = "http",
    *,
    flow_id: int = 7,
    community_id: str = "1:stable-community",
    tx_id: int | None = 3,
    timestamp: str = "2026-11-26T20:00:00.200000+00:00",
    reverse: bool = False,
) -> dict:
    source = ("10.9.0.2", 44_444)
    destination = ("10.9.0.3", 80)
    if reverse:
        source, destination = destination, source
    raw = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": kind,
        "pcap_filename": "/captures/eth0.pcap",
        "src_ip": source[0],
        "src_port": source[1],
        "dest_ip": destination[0],
        "dest_port": destination[1],
        "proto": "TCP",
        "app_proto": "http",
        "community_id": community_id,
        kind: (
            {
                "pkts_toserver": 2,
                "pkts_toclient": 1,
                "bytes_toserver": 90,
                "bytes_toclient": 50,
            }
            if kind == "flow"
            else {"hostname": "web", "url": "/"}
        ),
    }
    if tx_id is not None:
        raw["tx_id"] = tx_id
    return raw


def alert(
    *,
    flow_id: int = 7,
    community_id: str = "1:stable-community",
    tx_id: int | None = 3,
    severity: int = 1,
) -> dict:
    raw = {
        "timestamp": "2026-11-26T20:00:00.210000+00:00",
        "flow_id": flow_id,
        "event_type": "alert",
        "pcap_filename": "/captures/eth0.pcap",
        "src_ip": "10.9.0.2",
        "src_port": 44_444,
        "dest_ip": "10.9.0.3",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "community_id": community_id,
        "alert": {
            "signature_id": 2_001_219,
            "signature": "ET MADE UP",
            "category": "Made Up",
            "severity": severity,
        },
    }
    if tx_id is not None:
        raw["tx_id"] = tx_id
    return raw


def write_eve(path: Path, lines: list[dict]) -> None:
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))


def output_folder(arguments: list[str]) -> Path:
    mount = next(
        arguments[index + 1]
        for index, value in enumerate(arguments)
        if value == "--mount" and "target=/output" in arguments[index + 1]
    )
    source = next(part.removeprefix("source=") for part in mount.split(",") if part.startswith("source="))
    return Path(source)


def capture_folder(arguments: list[str]) -> Path:
    mount = next(
        arguments[index + 1]
        for index, value in enumerate(arguments)
        if value == "--mount" and "target=/captures" in arguments[index + 1]
    )
    source = next(part.removeprefix("source=") for part in mount.split(",") if part.startswith("source="))
    return Path(source)


def option(arguments: list[str], name: str) -> str:
    return arguments[arguments.index(name) + 1]


def successful_output(arguments: list[str], lines: list[dict], loaded: int = 2, packets: int = 1) -> None:
    output = output_folder(arguments)
    write_eve(output / "eve.json", lines)
    (output / "suricata.log").write_text(
        "This is Suricata version 8.0.8 RELEASE running in SYSTEM mode\n"
        f"{loaded} rules successfully loaded, 0 rules failed\n"
    )
    (output / "stats.log").write_text(
        "Counter | TM Name | Value\n"
        f"decoder.pkts | Total | {packets}\n"
        "decoder.bytes | Total | 900\n"
        "flow.memuse | Total | 1,024\n"
    )


def test_evaluate_uses_the_exact_offline_security_boundary_and_held_files(tmp_path: Path) -> None:
    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    (captures / "eth0.log").write_text("1 packet captured\n")
    output = tmp_path / "engine"
    calls: list[tuple[list[str], float]] = []
    modes: list[int] = []
    staged: list[Path] = []
    cidfiles: list[Path] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append((arguments, timeout))
        modes.append(output_folder(arguments).stat().st_mode & 0o777)
        staged.append(capture_folder(arguments))
        cidfiles.append(Path(option(arguments, "--cidfile")))
        assert [path.name for path in capture_folder(arguments).iterdir()] == ["eth0.pcap"]
        assert (capture_folder(arguments).stat().st_mode & 0o777) == 0o555
        successful_output(arguments, [network("flow", tx_id=None), network(), alert()])
        return subprocess.CompletedProcess(arguments, 0, "", "")

    found = suricata.evaluate(
        suricata.IMAGE,
        rules,
        captures,
        ["10.9.0.4", "10.9.0.3", "10.9.0.3"],
        output,
        runner=runner,
    )

    command = calls[0][0]
    container_name = option(command, "--name")
    cidfile = Path(option(command, "--cidfile"))
    staged_folder = capture_folder(command)
    assert re.fullmatch(r"bluefire-suricata-[0-9a-f]{24}", container_name)
    expected = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--cidfile",
        str(cidfile),
        "--network",
        "none",
        "--pull",
        "never",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--user",
        suricata.CONTAINER_USER,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,source={staged_folder},target=/captures,readonly",
        "--mount",
        f"type=bind,source={rules.resolve()},target=/rules,readonly",
        "--mount",
        f"type=bind,source={output.resolve()},target=/output",
        "--entrypoint",
        "/usr/bin/suricata",
        suricata.IMAGE,
        "-c",
        "/etc/suricata/suricata.yaml",
        "-r",
        "/captures",
        "--pcap-file-recursive",
        "--runmode",
        "single",
        "-l",
        "/output",
        "-k",
        "none",
        "--set",
        "vars.address-groups.HOME_NET=[10.9.0.3,10.9.0.4]",
        "--set",
        "default-rule-path=/rules",
        "--set",
        "rule-files.0=nested/two.rules",
        "--set",
        "rule-files.1=one.rules",
        "--set",
        "classification-file=/rules/classification.config",
        "--set",
        "outputs.1.eve-log.enabled=yes",
        "--set",
        "outputs.1.eve-log.filename=eve.json",
        "--set",
        "outputs.1.eve-log.filetype=regular",
        "--set",
        "outputs.1.eve-log.pcap-file=yes",
        "--set",
        "outputs.1.eve-log.types=[alert,flow,http,tls,ssh,dns]",
        "--set",
        "outputs.1.eve-log.types.32.stats.enabled=no",
        "--set",
        "outputs.1.eve-log.community-id=yes",
        "--set",
        "outputs.1.eve-log.community-id-seed=0",
        "--set",
        "stats.enabled=yes",
        "--set",
        "stats.interval=1",
        "--set",
        "outputs.2.stats.enabled=yes",
        "--set",
        "outputs.2.stats.filename=stats.log",
        "--set",
        "outputs.2.stats.totals=yes",
        "--set",
        "outputs.2.stats.threads=no",
    ]
    assert calls == [(expected, 900.0)]
    assert modes == [0o733]
    assert output.stat().st_mode & 0o777 == 0o700
    assert staged == [staged_folder] and not staged_folder.exists()
    assert cidfiles == [cidfile] and not cidfile.parent.exists()
    assert (captures / "eth0.log").is_file()
    assert "--privileged" not in expected and "--cap-add" not in expected
    assert expected[expected.index(suricata.IMAGE) + 1] == "-c"
    assert found["engine"] == {
        "name": "Suricata",
        "version": "8.0.8",
        "image": suricata.IMAGE,
    }
    assert found["rule files"] == ["nested/two.rules", "one.rules"]
    assert (found["loaded"], found["read"], found["stats"]["decoder.bytes"]) == (2, 1, 900)
    assert found["read counts"]["independently counted packets"] == 1
    assert found["home_net"] == ["10.9.0.3", "10.9.0.4"]
    assert found["records"][1] == network() and found["alerts"] == [alert()]
    assert found["alert event keys"] == [list(suricata.event_key(network()))]


def test_telemetry_is_a_rule_independent_canonical_pass(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    calls: list[list[str]] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        successful_output(arguments, [network("flow", tx_id=None), network()], loaded=0)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    found = suricata.telemetry(
        suricata.IMAGE,
        captures,
        ["10.9.0.3"],
        tmp_path / "telemetry",
        runner=runner,
    )

    command = calls[0]
    assert "--disable-detection" in command
    assert "--init-errors-fatal" not in command
    assert "rule-files=[]" not in command
    assert "outputs.1.eve-log.types.32.stats.enabled=no" in command
    assert not any("target=/rules" in value for value in command)
    assert (found["rules"], found["loaded"], found["alerts"]) == (0, 0, [])
    assert list(suricata.record_index(found["records"])) == [
        suricata.event_key(found["records"][0]),
        suricata.event_key(found["records"][1]),
    ]


def test_decoder_packet_count_must_equal_the_independent_pcap_count(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        successful_output(arguments, [network("flow", tx_id=None)], loaded=0, packets=2)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="decoded 2 packets.*counted 1"):
        suricata.telemetry(
            suricata.IMAGE,
            captures,
            ["10.9.0.3"],
            tmp_path / "telemetry",
            runner=runner,
        )


def test_every_nonempty_pcap_must_have_a_canonical_network_event(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    write_pcap(captures / "eth1.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        successful_output(arguments, [network("flow", tx_id=None)], loaded=0, packets=2)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="no canonical network event for eth1.pcap"):
        suricata.telemetry(
            suricata.IMAGE,
            captures,
            ["10.9.0.3"],
            tmp_path / "telemetry",
            runner=runner,
        )


def test_eve_is_strict_but_preserves_raw_network_and_alert_records(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    raw_records = [network("flow", tx_id=None), network()]
    raw_alerts = [alert(severity=2)]
    write_eve(path, raw_records + raw_alerts)

    records, alerts = suricata.read_eve(path, {"/captures/eth0.pcap"})

    assert records == raw_records
    assert alerts == raw_alerts
    assert [suricata.severity(value) for value in (1, 2, 3, 4, None, True)] == [
        "high",
        "medium",
        "low",
        "informational",
        "informational",
        "informational",
    ]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("{", "not strict JSON"),
        ("[]\n", "not an object"),
        ("\n", "is blank"),
        (
            json.dumps({key: value for key, value in network().items() if key != "community_id"}) + "\n",
            "has no community_id",
        ),
        (
            json.dumps({**network(), "pcap_filename": "/outside/eth0.pcap"}) + "\n",
            "outside /captures",
        ),
        (
            json.dumps({**network(), "event_type": "stats"}) + "\n",
            "was not configured",
        ),
        (
            '{"timestamp":"x","timestamp":"y"}\n',
            "duplicate key",
        ),
    ],
)
def test_malformed_incomplete_or_out_of_folder_eve_is_refused(
    tmp_path: Path, text: str, message: str
) -> None:
    path = tmp_path / "eve.json"
    path.write_text(text)

    with pytest.raises(suricata.SuricataError, match=message):
        suricata.read_eve(path)


def test_alert_linking_prefers_its_application_transaction_then_uses_flow() -> None:
    flow = network("flow", tx_id=None)
    first = network(tx_id=1)
    second = network(tx_id=2)

    assert suricata.link_alert(alert(tx_id=2), [flow, first, second]) is second
    assert suricata.link_alert(alert(tx_id=8), [flow, first, second]) is flow

    with pytest.raises(suricata.SuricataError, match="more than one matching application"):
        suricata.link_alert(alert(tx_id=None), [flow, first, second])
    with pytest.raises(suricata.SuricataError, match="no real non-alert record"):
        suricata.link_alert(alert(flow_id=99), [flow, first, second])


def test_an_unknown_alert_capture_links_to_one_real_flow_without_rewriting_it() -> None:
    flow = network("flow", tx_id=None)
    raw_alert = {**alert(tx_id=None), "pcap_filename": "unknown"}

    assert suricata.link_alert(raw_alert, [flow]) is flow
    assert suricata.alert_event_key(raw_alert, [flow]) == suricata.event_key(flow)
    assert raw_alert["pcap_filename"] == "unknown"


def test_an_unknown_alert_capture_refuses_an_ambiguous_or_missing_flow() -> None:
    raw_alert = {**alert(), "pcap_filename": "unknown"}
    first = network()
    second = {
        **network("flow", tx_id=None),
        "pcap_filename": "/captures/eth1.pcap",
    }

    with pytest.raises(suricata.SuricataError, match="spans more than one input capture"):
        suricata.link_alert(raw_alert, [first, second])
    with pytest.raises(suricata.SuricataError, match="no real non-alert record"):
        suricata.link_alert(raw_alert, [])


def test_unknown_is_a_valid_raw_capture_name_only_for_alerts(tmp_path: Path) -> None:
    raw_alert = {**alert(), "pcap_filename": "unknown"}
    path = tmp_path / "eve.json"
    write_eve(path, [raw_alert])

    records, alerts = suricata.read_eve(path, {"/captures/eth0.pcap"})

    assert records == []
    assert alerts == [raw_alert]
    write_eve(path, [{**network(), "pcap_filename": "unknown"}])
    with pytest.raises(suricata.SuricataError, match="outside /captures"):
        suricata.read_eve(path, {"/captures/eth0.pcap"})


def test_flow_ids_can_change_between_passes_without_changing_alert_identity() -> None:
    canonical = network(flow_id=7, tx_id=4)
    judged = network(flow_id=99, tx_id=4)
    first_alert = alert(flow_id=7, tx_id=4)
    second_alert = alert(flow_id=99, tx_id=4)

    assert suricata.alert_event_key(first_alert, [canonical]) == (
        "network",
        "eth0.pcap",
        "1:stable-community",
        "http",
        4,
        None,
        "tcp",
        "10.9.0.2",
        44_444,
        "10.9.0.3",
        80,
        "2026-11-26T20:00:00.200000Z",
    )
    assert suricata.alert_event_key(first_alert, [canonical]) == suricata.alert_event_key(
        second_alert, [judged]
    )


def test_flow_fallback_key_normalizes_direction_time_and_addresses() -> None:
    first = network(
        "flow",
        flow_id=7,
        community_id="1:stable-community",
        tx_id=None,
        timestamp="2026-11-26T20:00:00+00:00",
    )
    second = network(
        "flow",
        flow_id=999,
        community_id="1:stable-community",
        tx_id=None,
        timestamp="2026-11-26T14:00:00-06:00",
        reverse=True,
    )

    assert suricata.event_key(first) == suricata.event_key(second)


def test_dns_query_and_response_of_one_transaction_have_distinct_occurrences() -> None:
    query = {
        **network("dns", tx_id=8, timestamp="2026-11-26T20:00:00.100000+00:00"),
        "dns": {"type": "query", "id": 42, "rrname": "web"},
    }
    response = {
        **network(
            "dns",
            tx_id=8,
            timestamp="2026-11-26T20:00:00.200000+00:00",
            reverse=True,
        ),
        "dns": {"type": "answer", "id": 42, "rrname": "web"},
    }
    query_alert = {
        **alert(tx_id=8),
        "app_proto": "dns",
        "timestamp": query["timestamp"],
    }
    response_alert = {
        **alert(tx_id=8),
        "app_proto": "dns",
        "timestamp": response["timestamp"],
        "src_ip": response["src_ip"],
        "src_port": response["src_port"],
        "dest_ip": response["dest_ip"],
        "dest_port": response["dest_port"],
    }

    assert suricata.event_key(query) != suricata.event_key(response)
    assert suricata.link_alert(query_alert, [query, response]) is query
    assert suricata.link_alert(response_alert, [query, response]) is response


def test_stable_keys_keep_identical_transactions_on_two_interfaces_distinct() -> None:
    first = network(flow_id=7, tx_id=4)
    second = {**network(flow_id=99, tx_id=4), "pcap_filename": "/captures/eth1.pcap"}
    first_alert = alert(flow_id=7, tx_id=4)
    second_alert = {**alert(flow_id=99, tx_id=4), "pcap_filename": "/captures/eth1.pcap"}

    assert suricata.event_key(first) != suricata.event_key(second)
    assert suricata.alert_event_key(first_alert, [first]) != suricata.alert_event_key(second_alert, [second])


def test_duplicate_stable_events_and_unmatched_engine_alerts_are_refused(tmp_path: Path) -> None:
    first = network(flow_id=7)
    duplicate = network(flow_id=99)
    with pytest.raises(suricata.SuricataError, match="more than one network record"):
        suricata.record_index([first, duplicate])

    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        successful_output(arguments, [alert()])
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="no real non-alert record"):
        suricata.evaluate(
            suricata.IMAGE,
            rules,
            captures,
            ["10.9.0.3"],
            tmp_path / "engine",
            runner=runner,
        )


def test_unpinned_images_are_refused_before_docker(tmp_path: Path) -> None:
    assert suricata.valid_image(suricata.IMAGE)
    assert not suricata.valid_image("jasonish/suricata:8.0.8")
    called = False

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="tag and immutable sha256"):
        suricata.evaluate(
            "jasonish/suricata:8.0.8",
            tmp_path,
            tmp_path,
            [],
            tmp_path / "out",
            runner=runner,
        )
    assert called is False


def test_output_permissions_are_restored_when_the_engine_times_out(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    output = tmp_path / "engine"
    calls: list[list[str]] = []
    transient: list[Path] = []
    container_id = "a" * 64

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[1] == "run":
            assert output_folder(arguments).stat().st_mode & 0o777 == 0o733
            transient.extend((capture_folder(arguments), Path(option(arguments, "--cidfile")).parent))
            Path(option(arguments, "--cidfile")).write_text(container_id)
            raise subprocess.TimeoutExpired(arguments, timeout)
        assert arguments == ["docker", "rm", "--force", container_id]
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="took longer"):
        suricata.telemetry(
            suricata.IMAGE,
            captures,
            ["10.9.0.3"],
            output,
            runner=runner,
        )

    assert output.stat().st_mode & 0o777 == 0o700
    assert len(calls) == 2
    assert all(not path.exists() for path in transient)


def test_start_failure_removes_only_the_unique_named_container(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    calls: list[list[str]] = []
    transient: list[Path] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[1] == "run":
            transient.extend((capture_folder(arguments), Path(option(arguments, "--cidfile")).parent))
            raise OSError("made-up Docker start failure")
        assert arguments == ["docker", "rm", "--force", option(calls[0], "--name")]
        return subprocess.CompletedProcess(arguments, 1, "", "not found")

    with pytest.raises(suricata.SuricataError, match="could not be started"):
        suricata.telemetry(
            suricata.IMAGE,
            captures,
            ["10.9.0.3"],
            tmp_path / "engine",
            runner=runner,
        )

    assert len(calls) == 2
    assert all(not path.exists() for path in transient)


def test_capture_files_refuses_a_link_even_when_it_points_to_a_classic_pcap(
    tmp_path: Path,
) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    real = tmp_path / "outside.pcap"
    write_pcap(real)
    (captures / "eth0.pcap").symlink_to(real)

    with pytest.raises(suricata.SuricataError, match="is a link"):
        suricata.capture_files(captures)


def test_capture_files_refuses_a_nested_pcap_the_manifest_cannot_name(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    nested = captures / "unexpected"
    nested.mkdir(parents=True)
    write_pcap(nested / "eth0.pcap")

    with pytest.raises(suricata.SuricataError, match="not a top-level web PCAP"):
        suricata.capture_files(captures)


def test_a_rule_pack_without_classifications_uses_the_pinned_images_config(
    tmp_path: Path,
) -> None:
    rules = tmp_path / "held"
    rules.mkdir()
    (rules / "only.rules").write_text('alert tcp any any -> any any (msg:"one"; sid:1; rev:1;)\n')
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    calls: list[list[str]] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        successful_output(arguments, [network("flow", tx_id=None)], loaded=1)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    found = suricata.evaluate(
        suricata.IMAGE,
        rules,
        captures,
        ["10.9.0.3"],
        tmp_path / "engine",
        runner=runner,
    )

    assert not any(value.startswith("classification-file=") for value in calls[0])
    assert (found["rules"], found["rule file count"], found["loaded"]) == (1, 1, 1)


def test_partial_rule_loading_keeps_real_results_and_bounded_reasons(tmp_path: Path) -> None:
    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        output = output_folder(arguments)
        write_eve(output / "eve.json", [network("flow", tx_id=None)])
        (output / "suricata.log").write_text(
            "This is Suricata version 8.0.8 RELEASE running in SYSTEM mode\n"
            "Error: detect: invalid signature in /rules/one.rules at line 1\n"
            "1 rules successfully loaded, 1 rules failed\n"
        )
        (output / "stats.log").write_text("decoder.pkts | Total | 1\n")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    found = suricata.evaluate(
        suricata.IMAGE,
        rules,
        captures,
        ["10.9.0.3"],
        tmp_path / "engine",
        runner=runner,
    )

    assert (found["rules"], found["loaded"], found["failed"]) == (2, 1, 1)
    assert found["load errors"] == ["Error: detect: invalid signature in /rules/one.rules at line 1"]

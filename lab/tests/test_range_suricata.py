"""Offline Suricata reads held PCAPs and rules without inventing network evidence."""

import json
import re
import struct
import subprocess
from pathlib import Path

import pytest
import yaml

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
                "start": "2026-11-26T20:00:00.000000+00:00",
                "end": "2026-11-26T20:00:01.000000+00:00",
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


def eve_config_file(arguments: list[str]) -> Path:
    mount = next(
        arguments[index + 1]
        for index, value in enumerate(arguments)
        if value == "--mount" and f"target={suricata.EVE_CONFIG_TARGET}" in arguments[index + 1]
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


def test_eve_config_is_an_exact_yaml_sequence_of_supported_outputs() -> None:
    parsed = yaml.safe_load(suricata.EVE_CONFIG)

    assert parsed == {
        "outputs": [
            {
                "eve-log": {
                    "enabled": True,
                    "filetype": "regular",
                    "filename": "eve.json",
                    "pcap-file": True,
                    "community-id": True,
                    "community-id-seed": suricata.COMMUNITY_ID_SEED,
                    "types": [
                        {"alert": {"tagged-packets": True}},
                        "flow",
                        {"http": {"extended": True}},
                        {"tls": {"extended": True}},
                        "ssh",
                        "dns",
                    ],
                }
            },
            {
                "stats": {
                    "enabled": True,
                    "filename": "stats.log",
                    "append": False,
                    "totals": True,
                    "threads": False,
                }
            },
        ]
    }
    configured = parsed["outputs"][0]["eve-log"]["types"]
    names = tuple(next(iter(item)) if isinstance(item, dict) else item for item in configured)
    assert names == suricata.EVE_TYPES


def test_evaluate_uses_the_exact_offline_security_boundary_and_held_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    (captures / "eth0.log").write_text("1 packet captured\n")
    output = tmp_path / "engine"
    calls: list[tuple[list[str], float]] = []
    modes: list[int] = []
    staged: list[tuple[Path, list[str]]] = []
    cidfiles: list[Path] = []
    configs: list[Path] = []
    parsed_eve: list[Path] = []
    read_eve = suricata.read_eve

    def observed_read_eve(path: Path, allowed: set[str] | None = None):
        assert path.is_file()
        parsed_eve.append(path)
        return read_eve(path, allowed)

    monkeypatch.setattr(suricata, "read_eve", observed_read_eve)

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append((arguments, timeout))
        modes.append(output_folder(arguments).stat().st_mode & 0o777)
        staged_folder = capture_folder(arguments)
        staged.append((staged_folder, sorted(path.name for path in staged_folder.iterdir())))
        cidfiles.append(Path(option(arguments, "--cidfile")))
        configs.append(eve_config_file(arguments))
        assert [path.name for path in capture_folder(arguments).iterdir()] == ["eth0.pcap"]
        assert (capture_folder(arguments).stat().st_mode & 0o777) == 0o555
        assert eve_config_file(arguments).read_text(encoding="utf-8") == suricata.EVE_CONFIG
        assert eve_config_file(arguments).stat().st_mode & 0o777 == 0o444
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
    config_file = eve_config_file(command)
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
        f"type=bind,source={config_file},target={suricata.EVE_CONFIG_TARGET},readonly",
        "--mount",
        f"type=bind,source={rules.resolve()},target=/rules,readonly",
        "--mount",
        f"type=bind,source={(output / 'pcap-0001').resolve()},target=/output",
        "--entrypoint",
        "/usr/bin/suricata",
        suricata.IMAGE,
        "-c",
        "/etc/suricata/suricata.yaml",
        "--include",
        suricata.EVE_CONFIG_TARGET,
        "-r",
        "/captures/eth0.pcap",
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
        "stats.enabled=yes",
        "--set",
        "stats.interval=1",
    ]
    assert calls == [(expected, 900.0)]
    assert modes == [0o733]
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "pcap-0001").stat().st_mode & 0o777 == 0o700
    assert parsed_eve == [output / "pcap-0001" / "eve.json"]
    assert not (output / "pcap-0001" / "eve.json").exists()
    assert (output / "pcap-0001" / "suricata.log").is_file()
    assert (output / "pcap-0001" / "stats.log").is_file()
    assert [folder for folder, _ in staged] == [staged_folder] and not staged_folder.exists()
    assert cidfiles == [cidfile] and not cidfile.parent.exists()
    assert configs == [config_file] and not config_file.exists()
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
    assert found["runs"] == [
        {
            "capture": "eth0.pcap",
            "folder": "pcap-0001",
            "read": 1,
            "read counts": {
                "packets": 1,
                "independently counted packets": 1,
                "eve records": 3,
                "network records": 2,
                "alerts": 1,
                "bytes": 900,
            },
            "stats": {"decoder.pkts": 1, "decoder.bytes": 900, "flow.memuse": 1024},
        }
    ]
    assert found["read counts"]["independently counted packets"] == 1
    assert found["home_net"] == ["10.9.0.3", "10.9.0.4"]
    assert found["records"][1] == network() and found["alerts"] == [alert()]
    assert found["alert event keys"] == [list(suricata.event_key(found["records"][1], found["records"]))]


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
    assert option(command, "-r") == "/captures/eth0.pcap"
    assert "--pcap-file-recursive" not in command
    assert "--init-errors-fatal" not in command
    assert "rule-files=[]" not in command
    assert option(command, "--include") == suricata.EVE_CONFIG_TARGET
    assert not any(value.startswith("outputs.") for value in command)
    assert not any("target=/rules" in value for value in command)
    assert (found["rules"], found["loaded"], found["alerts"]) == (0, 0, [])
    assert list(suricata.record_index(found["records"])) == list(suricata.record_keys(found["records"]))
    assert not (tmp_path / "telemetry" / "pcap-0001" / "eve.json").exists()
    assert (tmp_path / "telemetry" / "pcap-0001" / "suricata.log").is_file()
    assert (tmp_path / "telemetry" / "pcap-0001" / "stats.log").is_file()


def test_each_capture_has_its_own_process_output_and_aggregated_result(tmp_path: Path) -> None:
    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    write_pcap(captures / "eth1.pcap")
    calls: list[tuple[list[str], float]] = []
    staged: list[tuple[Path, list[str]]] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append((arguments, timeout))
        staged_folder = capture_folder(arguments)
        staged.append((staged_folder, sorted(path.name for path in staged_folder.iterdir())))
        capture = Path(option(arguments, "-r")).name
        record = network(
            "flow",
            flow_id=7 if capture == "eth0.pcap" else 8,
            community_id=f"1:{capture}",
            tx_id=None,
        )
        record["pcap_filename"] = f"/captures/{capture}"
        successful_output(arguments, [record], loaded=2, packets=1)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    found = suricata.evaluate(
        suricata.IMAGE,
        rules,
        captures,
        ["10.9.0.3"],
        tmp_path / "engine",
        runner=runner,
    )

    commands = [call[0] for call in calls]
    assert [option(command, "-r") for command in commands] == [
        "/captures/eth0.pcap",
        "/captures/eth1.pcap",
    ]
    assert all("--pcap-file-recursive" not in command for command in commands)
    assert [output_folder(command).name for command in commands] == ["pcap-0001", "pcap-0002"]
    assert [names for _, names in staged] == [
        ["eth0.pcap"],
        ["eth1.pcap"],
    ]
    assert calls[0][1] == 900.0 and 0 < calls[1][1] <= 900.0
    assert all(not folder.exists() for folder, _ in staged)
    assert (found["rules"], found["loaded"], found["failed"], found["read"]) == (2, 2, 0, 2)
    assert found["stats"] == {"decoder.pkts": 2, "decoder.bytes": 1800}
    assert [run["capture"] for run in found["runs"]] == ["eth0.pcap", "eth1.pcap"]
    assert [run["folder"] for run in found["runs"]] == ["pcap-0001", "pcap-0002"]
    assert not (tmp_path / "engine" / "pcap-0001" / "eve.json").exists()
    assert not (tmp_path / "engine" / "pcap-0002" / "eve.json").exists()
    assert (tmp_path / "engine" / "pcap-0001" / "suricata.log").is_file()
    assert (tmp_path / "engine" / "pcap-0002" / "stats.log").is_file()
    assert [record["pcap_filename"] for record in found["records"]] == [
        "/captures/eth0.pcap",
        "/captures/eth1.pcap",
    ]


def test_rule_loading_must_be_identical_for_every_capture(tmp_path: Path) -> None:
    rules = tmp_path / "held"
    held_rules(rules)
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    write_pcap(captures / "eth1.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        capture = Path(option(arguments, "-r")).name
        record = network("flow", flow_id=7 if capture == "eth0.pcap" else 8, tx_id=None)
        record["pcap_filename"] = f"/captures/{capture}"
        successful_output(
            arguments,
            [record],
            loaded=2 if capture == "eth0.pcap" else 1,
            packets=1,
        )
        return subprocess.CompletedProcess(arguments, 0, "", "")

    output = tmp_path / "engine"
    with pytest.raises(suricata.SuricataError, match="same engine and rule loading"):
        suricata.evaluate(
            suricata.IMAGE,
            rules,
            captures,
            ["10.9.0.3"],
            output,
            runner=runner,
        )
    assert (output / "pcap-0001" / "eve.json").is_file()
    assert (output / "pcap-0002" / "eve.json").is_file()


def test_multiple_captures_share_one_overall_timeout(tmp_path: Path, monkeypatch) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")
    write_pcap(captures / "eth1.pcap")
    moments = iter((0.0, 2.0))
    monkeypatch.setattr(suricata.time, "monotonic", lambda: next(moments))
    calls: list[str] = []

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        capture = Path(option(arguments, "-r")).name
        calls.append(capture)
        record = network("flow", tx_id=None)
        record["pcap_filename"] = f"/captures/{capture}"
        successful_output(arguments, [record], loaded=0, packets=1)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    with pytest.raises(suricata.SuricataError, match="took longer than 1 seconds"):
        suricata.telemetry(
            suricata.IMAGE,
            captures,
            ["10.9.0.3"],
            tmp_path / "telemetry",
            runner=runner,
            timeout=1,
        )
    assert calls == ["eth0.pcap"]


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
    assert (tmp_path / "telemetry" / "pcap-0001" / "eve.json").is_file()


def test_validated_eve_must_be_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    write_pcap(captures / "eth0.pcap")

    def runner(arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        successful_output(arguments, [network("flow", tx_id=None)], loaded=0)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    unlink = Path.unlink

    def refuse_eve(self: Path, *args, **kwargs) -> None:
        if self.name == "eve.json":
            raise PermissionError("refused for test")
        unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_eve)
    with pytest.raises(suricata.SuricataError, match="validated eve.json cannot be removed"):
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
        capture = Path(option(arguments, "-r")).name
        lines = []
        if capture == "eth0.pcap":
            lines = [network("flow", tx_id=None)]
        successful_output(arguments, lines, loaded=0, packets=1)
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
    ("kind", "payload"),
    [
        (
            "fileinfo",
            {"filename": "/", "gaps": False, "size": 36, "state": "CLOSED", "stored": False, "tx_id": 0},
        ),
        (
            "anomaly",
            {"event": "APPLAYER_WRONG_DIRECTION_FIRST_DATA", "layer": "proto_detect", "type": "applayer"},
        ),
    ],
    ids=("stock-files-logger", "stock-anomaly-logger"),
)
def test_stock_eve_outputs_outside_the_declared_sequence_are_refused(
    tmp_path: Path, kind: str, payload: dict
) -> None:
    path = tmp_path / "eve.json"
    raw = {**network(), "event_type": kind, kind: payload}
    raw.pop("tx_id")
    if kind == "anomaly":
        raw.pop("app_proto")
        raw.pop("http")
    write_eve(path, [raw])

    with pytest.raises(suricata.SuricataError, match=rf"event_type {kind!r}, which was not configured"):
        suricata.read_eve(path)
    assert path.is_file()


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


def test_an_alert_before_application_detection_links_only_to_one_later_application_record() -> None:
    raw_alert = alert(tx_id=None)
    raw_alert.pop("app_proto")
    ssh = network("ssh", tx_id=None, timestamp="2026-11-26T20:00:00.214000+00:00")
    ssh.pop("app_proto")
    other_capture_flow = network("flow", tx_id=None)
    other_capture_flow["pcap_filename"] = "/captures/eth1.pcap"

    assert suricata.link_alert(raw_alert, [ssh, other_capture_flow]) is ssh

    tls = {**ssh, "event_type": "tls", "tls": {"subject": "CN=example"}}
    tls.pop("ssh")
    with pytest.raises(suricata.SuricataError, match="no real non-alert record"):
        suricata.link_alert(raw_alert, [ssh, tls, other_capture_flow])


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
    canonical_flow = network("flow", flow_id=7, tx_id=None)
    canonical = network(flow_id=7, tx_id=4)
    judged_flow = network("flow", flow_id=99, tx_id=None)
    judged = network(flow_id=99, tx_id=4)
    first_alert = alert(flow_id=7, tx_id=4)
    second_alert = alert(flow_id=99, tx_id=4)

    assert suricata.alert_event_key(first_alert, [canonical_flow, canonical]) == (
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
        "2026-11-26T20:00:00.000000Z",
        "2026-11-26T20:00:01.000000Z",
    )
    assert suricata.alert_event_key(first_alert, [canonical_flow, canonical]) == suricata.alert_event_key(
        second_alert, [judged_flow, judged]
    )
    assert suricata.alert_event_key(
        alert(flow_id=7, tx_id=None), [canonical_flow]
    ) == suricata.alert_event_key(alert(flow_id=99, tx_id=None), [judged_flow])


def test_flow_key_normalizes_direction_and_ignores_emission_time() -> None:
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
        timestamp="2026-11-26T14:05:00-06:00",
        reverse=True,
    )

    assert suricata.event_key(first) == suricata.event_key(second)


def test_distinct_flows_at_one_emission_time_keep_distinct_occurrences() -> None:
    timestamp = "2026-11-27T04:44:21.377391+00:00"
    first = network("flow", flow_id=7, tx_id=None, timestamp=timestamp)
    second = network("flow", flow_id=99, tx_id=None, timestamp=timestamp)
    first["flow"].update(
        start="2026-11-27T04:37:00.720240+00:00",
        end="2026-11-27T04:37:00.720240+00:00",
    )
    second["flow"].update(
        start="2026-11-27T04:42:20.207246+00:00",
        end="2026-11-27T04:42:20.207246+00:00",
    )

    keys = suricata.record_keys([first, second])

    assert keys[0] != keys[1]
    assert list(suricata.record_index([first, second])) == list(keys)


def test_flow_boundaries_are_required_valid_and_ordered() -> None:
    missing = network("flow", tx_id=None)
    missing["flow"].pop("start")
    invalid = network("flow", tx_id=None)
    invalid["flow"]["start"] = "not-a-time"
    reversed_flow = network("flow", tx_id=None)
    reversed_flow["flow"].update(
        start="2026-11-26T20:00:02+00:00",
        end="2026-11-26T20:00:01+00:00",
    )

    for raw, message in (
        (missing, "flow start"),
        (invalid, "invalid timestamp"),
        (reversed_flow, "flow ends before it starts"),
    ):
        with pytest.raises(suricata.SuricataError, match=message):
            suricata.record_keys([raw])


def test_application_records_require_one_exact_same_pass_flow() -> None:
    application = network("ssh", tx_id=None)
    application["app_proto"] = "ssh"
    with pytest.raises(suricata.SuricataError, match="has no exact flow record"):
        suricata.record_keys([application])

    first = network("flow", tx_id=None)
    duplicate = network("flow", tx_id=None)
    duplicate["flow"].update(
        start="2026-11-26T20:00:00.100000+00:00",
        end="2026-11-26T20:00:01.100000+00:00",
    )
    with pytest.raises(suricata.SuricataError, match="more than one flow record"):
        suricata.record_keys([first, duplicate, application])


def test_ssh_key_uses_its_flow_when_pass_timestamps_and_ids_change() -> None:
    canonical_flow = network("flow", flow_id=7, tx_id=None)
    canonical_ssh = network(
        "ssh",
        flow_id=7,
        tx_id=None,
        timestamp="2026-11-27T04:35:10.358738+00:00",
    )
    canonical_ssh["app_proto"] = "ssh"
    judged_flow = network(
        "flow",
        flow_id=99,
        tx_id=None,
        timestamp="2026-11-27T04:35:09.892128+00:00",
    )
    judged_ssh = network(
        "ssh",
        flow_id=99,
        tx_id=None,
        timestamp="2026-11-27T04:35:09.892128+00:00",
    )
    judged_ssh["app_proto"] = "ssh"
    for flow in (canonical_flow, judged_flow):
        flow["flow"].update(
            start="2026-11-27T04:32:42.262200+00:00",
            end="2026-11-27T04:32:42.276321+00:00",
        )

    assert suricata.event_key(canonical_ssh, [canonical_flow, canonical_ssh]) == suricata.event_key(
        judged_ssh, [judged_flow, judged_ssh]
    )


def test_dns_query_and_response_of_one_transaction_have_distinct_occurrences() -> None:
    flow = network("flow", tx_id=None)
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

    records = [flow, query, response]
    assert suricata.event_key(query, records) != suricata.event_key(response, records)
    assert suricata.link_alert(query_alert, records) is query
    assert suricata.link_alert(response_alert, records) is response


def test_stable_keys_keep_identical_transactions_on_two_interfaces_distinct() -> None:
    first_flow = network("flow", flow_id=7, tx_id=None)
    first = network(flow_id=7, tx_id=4)
    second_flow = {
        **network("flow", flow_id=99, tx_id=None),
        "pcap_filename": "/captures/eth1.pcap",
    }
    second = {**network(flow_id=99, tx_id=4), "pcap_filename": "/captures/eth1.pcap"}
    first_alert = alert(flow_id=7, tx_id=4)
    second_alert = {**alert(flow_id=99, tx_id=4), "pcap_filename": "/captures/eth1.pcap"}

    first_records = [first_flow, first]
    second_records = [second_flow, second]
    assert suricata.event_key(first, first_records) != suricata.event_key(second, second_records)
    assert suricata.alert_event_key(first_alert, first_records) != suricata.alert_event_key(
        second_alert, second_records
    )


def test_duplicate_stable_events_and_unmatched_engine_alerts_are_refused(tmp_path: Path) -> None:
    first = network("flow", flow_id=7, tx_id=None)
    duplicate = network("flow", flow_id=99, tx_id=None)
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
            transient.extend(
                (
                    capture_folder(arguments),
                    eve_config_file(arguments),
                    Path(option(arguments, "--cidfile")).parent,
                )
            )
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
            transient.extend(
                (
                    capture_folder(arguments),
                    eve_config_file(arguments),
                    Path(option(arguments, "--cidfile")).parent,
                )
            )
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

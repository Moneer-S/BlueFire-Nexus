"""Packet capture files are complete, counted independently, and report delivery loss."""

import copy
import hashlib
import struct
from pathlib import Path

import pytest

from bluefire_lab.range import packets

MAGIC = {
    ("<", "microseconds"): b"\xd4\xc3\xb2\xa1",
    (">", "microseconds"): b"\xa1\xb2\xc3\xd4",
    ("<", "nanoseconds"): b"\x4d\x3c\xb2\xa1",
    (">", "nanoseconds"): b"\xa1\xb2\x3c\x4d",
}


def write_pcap(
    path: Path,
    *,
    endian: str = "<",
    resolution: str = "microseconds",
    payload: bytes = b"packet",
    original: int | None = None,
) -> None:
    original = len(payload) if original is None else original
    limit = 1_000_000_000 if resolution == "nanoseconds" else 1_000_000
    path.write_bytes(
        MAGIC[(endian, resolution)]
        + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 262_144, 1)
        + struct.pack(endian + "IIII", 1_700_000_000, limit - 1, len(payload), original)
        + payload
    )


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("resolution", ["microseconds", "nanoseconds"])
def test_a_classic_pcap_is_counted_in_both_byte_orders_and_time_resolutions(
    tmp_path: Path, endian: str, resolution: str
) -> None:
    path = tmp_path / "eth0.pcap"
    write_pcap(path, endian=endian, resolution=resolution)

    found = packets.pcap(path)
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()

    assert found == {
        "bytes": path.stat().st_size,
        "sha256": digest,
        "packets": 1,
        "captured packet bytes": 6,
        "wire packet bytes": 6,
        "whole packets": True,
        "snap length": 262_144,
        "link type": 1,
        "timestamp resolution": resolution,
    }


def test_a_packet_cut_by_the_snapshot_length_is_counted_but_not_called_whole(tmp_path: Path) -> None:
    path = tmp_path / "eth0.pcap"
    write_pcap(path, payload=b"part", original=20)

    found = packets.pcap(path)

    assert found["packets"] == 1
    assert found["captured packet bytes"] == 4
    assert found["wire packet bytes"] == 20
    assert found["whole packets"] is False


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: data[:20], "global header is truncated"),
        (lambda data: data[:30], "packet 1's header is truncated"),
        (lambda data: data[:-1], "packet 1's 6 bytes are truncated"),
    ],
)
def test_a_truncated_capture_is_refused(tmp_path: Path, change, message: str) -> None:
    path = tmp_path / "eth0.pcap"
    write_pcap(path)
    path.write_bytes(change(path.read_bytes()))

    with pytest.raises(packets.CaptureError, match=message):
        packets.pcap(path)


def test_a_forged_record_length_is_streamed_and_refused_without_a_large_allocation(tmp_path: Path) -> None:
    path = tmp_path / "eth0.pcap"
    maximum = 0xFFFFFFFF
    path.write_bytes(
        MAGIC[("<", "microseconds")]
        + struct.pack("<HHIIII", 2, 4, 0, 0, maximum, 1)
        + struct.pack("<IIII", 1_700_000_000, 0, maximum, maximum)
    )

    with pytest.raises(packets.CaptureError, match="4294967295 bytes are truncated"):
        packets.pcap(path)


def packet_word(number: int) -> str:
    return "packet" if number == 1 else "packets"


def tcpdump_log(captured: int = 1, received: int | None = None, dropped: int = 0) -> str:
    received = captured + dropped if received is None else received
    return (
        f"{captured} {packet_word(captured)} captured\n"
        f"{received} {packet_word(received)} received by filter\n"
        f"{dropped} {packet_word(dropped)} dropped by kernel\n"
    )


@pytest.mark.parametrize(("captured", "dropped"), [(0, 0), (1, 0), (2, 1)])
def test_tcpdump_counters_accept_real_singular_and_plural_lines(captured: int, dropped: int) -> None:
    assert packets.tcpdump_counts(tcpdump_log(captured, dropped=dropped)) == {
        "captured": captured,
        "received by filter": captured + dropped,
        "dropped by kernel": dropped,
    }


def test_tcpdump_counters_need_one_complete_final_block() -> None:
    with pytest.raises(packets.CaptureError, match="complete delivery-counter block"):
        packets.tcpdump_counts("1 packet captured\n1 packet received by filter\n")
    with pytest.raises(packets.CaptureError, match="complete delivery-counter block"):
        packets.tcpdump_counts(tcpdump_log() + "2 packets captured\n")


def clean_section(token: str) -> dict:
    return {
        "analysed": False,
        "hosts": {
            "web": {
                "started": True,
                "ready": [
                    {
                        "network": "inside",
                        "interface": "eth0",
                        "token": token,
                        "seen": True,
                    }
                ],
                "stopped": {"cleanly": True},
                "collected": {"copied": True},
            }
        },
    }


def test_analysis_records_each_file_and_calls_a_kernel_drop_a_delivery_gap(tmp_path: Path) -> None:
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    token = "bluefire-ready-packet"
    write_pcap(folder / "eth0.pcap", payload=token.encode())
    (folder / "eth0.log").write_text(tcpdump_log())
    section = clean_section(token)

    clean = packets.analyse(tmp_path, copy.deepcopy(section))

    assert clean["analysed"] is True
    assert clean["delivery_gap"] is False
    assert clean["delivery_findings"] == []
    record = clean["hosts"]["web"]["files"]["eth0.pcap"]
    assert record["packets"] == 1
    assert record["tcpdump"]["dropped by kernel"] == 0
    assert record["xz -9 bytes"] > 0
    with (folder / "eth0.pcap").open("rb") as source:
        assert record["sha256"] == hashlib.file_digest(source, "sha256").hexdigest()

    (folder / "eth0.log").write_text(tcpdump_log(dropped=2))
    dropped = packets.analyse(tmp_path, copy.deepcopy(section))

    assert dropped["delivery_gap"] is True
    assert dropped["delivery_findings"] == ["web: eth0.pcap: 2 packets dropped by the kernel"]


@pytest.mark.parametrize(
    ("broken", "message"),
    [
        ("started", "capture host did not start"),
        ("ready-empty", "has no ready mark"),
        ("ready-failed", "ready mark on inside was not seen"),
        ("ready-no-token", "ready mark on inside names no token"),
        ("stopped", "was not stopped cleanly"),
        ("stopped-error", "capture stop reported an error"),
        ("collected", "was not copied out"),
        ("collected-error", "packet copy reported an error"),
        ("refused", "copy refused 1 archive member"),
    ],
)
def test_analysis_calls_every_lifecycle_failure_a_delivery_gap(
    tmp_path: Path, broken: str, message: str
) -> None:
    token = "bluefire-ready-packet"
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    write_pcap(folder / "eth0.pcap", payload=token.encode())
    (folder / "eth0.log").write_text(tcpdump_log())
    section = clean_section(token)
    entry = section["hosts"]["web"]
    if broken == "started":
        entry["started"] = False
    elif broken == "ready-empty":
        entry["ready"] = []
    elif broken == "ready-failed":
        entry["ready"][0].update({"seen": False, "interface": None})
    elif broken == "ready-no-token":
        entry["ready"][0]["token"] = ""
    elif broken == "stopped":
        entry["stopped"] = {"cleanly": False, "error": "exit 2"}
    elif broken == "stopped-error":
        entry["stopped"]["error"] = "late wrapper warning"
    elif broken == "collected":
        entry["collected"] = {"copied": False, "error": "docker cp failed"}
    elif broken == "collected-error":
        entry["collected"]["error"] = "archive warning"
    else:
        entry["collected"]["refused"] = ["eth0.pcap: a link"]

    found = packets.analyse(tmp_path, section)

    assert found["delivery_gap"] is True
    assert any(message in finding for finding in found["delivery_findings"])


def test_analysis_rejects_an_empty_capture_folder_and_a_filter_count_gap(tmp_path: Path) -> None:
    token = "bluefire-ready-packet"
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    empty = packets.analyse(tmp_path, clean_section(token))

    assert empty["delivery_gap"] is True
    assert "web: the packet capture folder holds no PCAP file" in empty["delivery_findings"]

    write_pcap(folder / "eth0.pcap", payload=token.encode())
    (folder / "eth0.log").write_text(tcpdump_log(received=2))
    counted = packets.analyse(tmp_path, clean_section(token))

    assert counted["delivery_gap"] is True
    assert any("received 2 packets by the filter" in finding for finding in counted["delivery_findings"])


def test_analysis_ties_the_copied_pcap_to_its_ready_mark(tmp_path: Path) -> None:
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    write_pcap(folder / "eth0.pcap", payload=b"another capture")
    (folder / "eth0.log").write_text(tcpdump_log())

    found = packets.analyse(tmp_path, clean_section("bluefire-ready-packet"))

    assert found["delivery_gap"] is True
    assert any("does not hold its ready mark" in finding for finding in found["delivery_findings"])


def test_analysis_is_not_marked_complete_when_validation_raises(tmp_path: Path, monkeypatch) -> None:
    token = "bluefire-ready-packet"
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    write_pcap(folder / "eth0.pcap", payload=token.encode())
    (folder / "eth0.log").write_text(tcpdump_log())
    section = clean_section(token)

    def fail(_path: Path) -> int:
        raise RuntimeError("compression stopped")

    monkeypatch.setattr(packets, "xz_size", fail)
    with pytest.raises(RuntimeError, match="compression stopped"):
        packets.analyse(tmp_path, section)

    assert section["analysed"] is False


def test_packet_report_never_calls_unstarted_or_unanalysed_capture_clean() -> None:
    manifest = {
        "result": "engine error",
        "packet_capture": {
            "analysed": False,
            "delivery_gap": None,
            "delivery_findings": [],
            "collect_error": "RuntimeError: collection stopped",
            "hosts": {"web": {"started": False, "files": {}}},
        },
    }

    report = packets.markdown(manifest)

    assert "no capture host started" in report
    assert "Delivery gap: not assessed." in report
    assert "Collection or analysis error: RuntimeError: collection stopped" in report
    assert "Delivery gap: no." not in report

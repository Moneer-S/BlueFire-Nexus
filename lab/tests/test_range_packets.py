"""Packet capture files are complete, counted independently, and report delivery loss."""

import copy
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

    assert found == {
        "bytes": path.stat().st_size,
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


def tcpdump_log(dropped: int = 0) -> str:
    return f"1 packets captured\n1 packets received by filter\n{dropped} packets dropped by kernel\n"


def test_tcpdump_counters_need_all_three_lines() -> None:
    assert packets.tcpdump_counts(tcpdump_log()) == {
        "captured": 1,
        "received by filter": 1,
        "dropped by kernel": 0,
    }
    with pytest.raises(packets.CaptureError, match="dropped by kernel"):
        packets.tcpdump_counts("1 packets captured\n1 packets received by filter\n")


def test_analysis_records_each_file_and_calls_a_kernel_drop_a_delivery_gap(tmp_path: Path) -> None:
    folder = tmp_path / "raw" / "hosts" / "web" / packets.CAPTURE_DIR
    folder.mkdir(parents=True)
    write_pcap(folder / "eth0.pcap")
    (folder / "eth0.log").write_text(tcpdump_log())
    section = {"hosts": {"web": {"ready": [{"interface": "eth0"}]}}}

    clean = packets.analyse(tmp_path, copy.deepcopy(section))

    assert clean["delivery_gap"] is False
    assert clean["delivery_findings"] == []
    assert clean["hosts"]["web"]["files"]["eth0.pcap"]["packets"] == 1
    assert clean["hosts"]["web"]["files"]["eth0.pcap"]["tcpdump"]["dropped by kernel"] == 0
    assert clean["hosts"]["web"]["files"]["eth0.pcap"]["xz -9 bytes"] > 0

    (folder / "eth0.log").write_text(tcpdump_log(2))
    dropped = packets.analyse(tmp_path, copy.deepcopy(section))

    assert dropped["delivery_gap"] is True
    assert dropped["delivery_findings"] == ["web: eth0.pcap: 2 packets dropped by the kernel"]

"""Packet captures made inside a range host: validation, delivery counts and a short report.

tcpdump writes one classic-PCAP file per non-loopback interface. The engine
stops it cleanly before collection. This module reads those files without a
packet library so a truncated record cannot be mistaken for delivered
telemetry, and reads tcpdump's own counters beside them. A packet dropped by
the kernel is a delivery finding of the sensor, as a lost log line is for the
host sensor.
"""

from __future__ import annotations

import hashlib
import lzma
import re
import struct
from pathlib import Path

CAPTURE_DIR = "var/log/bluefire/packets"
MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}
COUNTER_NAMES = ("captured", "received by filter", "dropped by kernel")
COUNTER_BLOCK = re.compile(
    r"(?m)^([0-9]+) packets? captured\r?\n"
    r"([0-9]+) packets? received by filter\r?\n"
    r"([0-9]+) packets? dropped by kernel$"
)


class CaptureError(ValueError):
    """A capture or tcpdump's delivery counters cannot be read."""


def pcap(path: Path) -> dict:
    """Read one classic-PCAP file and return its independent delivery counts."""

    size = path.stat().st_size
    with path.open("rb") as source:
        digest = hashlib.sha256()

        def read(size_: int) -> bytes:
            block_ = source.read(size_)
            digest.update(block_)
            return block_

        header = read(24)
        if len(header) != 24:
            raise CaptureError("the global header is truncated")
        byte_order = MAGIC.get(header[:4])
        if byte_order is None:
            raise CaptureError("the file is not classic PCAP, or its byte order is unknown")
        endian, resolution = byte_order
        try:
            major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack(endian + "HHIIII", header[4:])
        except struct.error as error:
            raise CaptureError(f"the global header cannot be read: {error}") from error
        if (major, minor) != (2, 4):
            raise CaptureError(f"the PCAP version is {major}.{minor}, not 2.4")
        if snaplen <= 0:
            raise CaptureError("the PCAP snap length is not positive")

        packets = captured = wire = 0
        whole = True
        while True:
            record = read(16)
            if not record:
                break
            if len(record) != 16:
                raise CaptureError(f"packet {packets + 1}'s header is truncated")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", record)
            limit = 1_000_000_000 if resolution == "nanoseconds" else 1_000_000
            if fraction >= limit:
                raise CaptureError(f"packet {packets + 1}'s timestamp fraction is outside one second")
            if included > snaplen or included > original:
                raise CaptureError(
                    f"packet {packets + 1} says it kept {included} of {original} bytes with snap length {snaplen}"
                )
            remaining = included
            while remaining:
                block = read(min(remaining, 1024 * 1024))
                if not block:
                    raise CaptureError(f"packet {packets + 1}'s {included} bytes are truncated")
                remaining -= len(block)
            packets += 1
            captured += included
            wire += original
            whole = whole and included == original
            # Reading the value catches a corrupt struct while keeping this parser independent of packet contents.
            _ = seconds
    return {
        "bytes": size,
        "sha256": digest.hexdigest(),
        "packets": packets,
        "captured packet bytes": captured,
        "wire packet bytes": wire,
        "whole packets": whole,
        "snap length": snaplen,
        "link type": link_type,
        "timestamp resolution": resolution,
    }


def tcpdump_counts(text: str) -> dict[str, int]:
    """The three delivery counters tcpdump writes when it exits cleanly."""

    clean = text.rstrip("\r\n")
    blocks = list(COUNTER_BLOCK.finditer(clean))
    if not blocks or blocks[-1].end() != len(clean):
        raise CaptureError("tcpdump's log does not end with one complete delivery-counter block")
    return {name: int(value) for name, value in zip(COUNTER_NAMES, blocks[-1].groups(), strict=True)}


def contains(path: Path, value: str) -> bool:
    """Whether a file contains a short readiness token, without reading the file whole."""

    wanted = value.encode("utf-8")
    if not wanted:
        return False
    overlap = b""
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            combined = overlap + block
            if wanted in combined:
                return True
            overlap = combined[-(len(wanted) - 1) :] if len(wanted) > 1 else b""
    return False


def xz_size(path: Path) -> int:
    """How many bytes the capture takes with the xz preset 9 used by the hosted run's report."""

    compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=9)
    total = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            total += len(compressor.compress(block))
    return total + len(compressor.flush())


def analyse(out: Path, capture: dict) -> dict:
    """Validate every copied capture and add per-file delivery facts to the manifest section."""

    capture["analysed"] = False
    findings: list[str] = []
    if capture.get("collect_error"):
        findings.append(f"packet capture finalization failed: {capture['collect_error']}")
    raw = Path(out) / "raw" / "hosts"
    hosts = capture.get("hosts") or {}
    if not hosts:
        findings.append("the packet capture names no host")
    for host, entry in hosts.items():
        if entry.get("started") is not True:
            findings.append(f"{host}: the packet capture host did not start")
        ready = entry.get("ready")
        marks = ready if isinstance(ready, list) else []
        if not marks:
            findings.append(f"{host}: the packet capture has no ready mark")
        for number, mark in enumerate(marks, start=1):
            where = mark.get("network") or f"mark {number}"
            if mark.get("seen") is not True:
                findings.append(f"{host}: the ready mark on {where} was not seen")
            elif not mark.get("interface"):
                findings.append(f"{host}: the ready mark on {where} names no interface")
            elif not isinstance(mark.get("token"), str) or not mark["token"]:
                findings.append(f"{host}: the ready mark on {where} names no token")

        stopped = entry.get("stopped")
        if not isinstance(stopped, dict):
            findings.append(f"{host}: the packet capture was not stopped cleanly")
        elif stopped.get("cleanly") is not True:
            detail = f": {stopped['error']}" if stopped.get("error") else ""
            findings.append(f"{host}: the packet capture was not stopped cleanly{detail}")
        elif stopped.get("error"):
            findings.append(f"{host}: the packet capture stop reported an error: {stopped['error']}")

        collected = entry.get("collected")
        if not isinstance(collected, dict):
            findings.append(f"{host}: the packet capture was not copied out")
        else:
            if collected.get("copied") is not True:
                detail = f": {collected['error']}" if collected.get("error") else ""
                findings.append(f"{host}: the packet capture was not copied out{detail}")
            elif collected.get("error"):
                findings.append(f"{host}: the packet copy reported an error: {collected['error']}")
            refused = collected.get("refused") or []
            if refused:
                findings.append(f"{host}: the packet copy refused {len(refused)} archive member(s)")

        folder = raw / host / CAPTURE_DIR
        expected = {mark["interface"] for mark in marks if mark.get("seen") is True and mark.get("interface")}
        by_interface = {
            interface: [mark for mark in marks if mark.get("interface") == interface]
            for interface in expected
        }
        files: dict[str, dict] = {}
        if not folder.is_dir():
            findings.append(f"{host}: the packet capture folder was not copied out")
            entry["files"] = files
            continue
        pcaps = sorted(path for path in folder.glob("*.pcap") if path.is_file() and not path.is_symlink())
        if not pcaps:
            findings.append(f"{host}: the packet capture folder holds no PCAP file")
        seen = {path.stem for path in pcaps}
        for interface in sorted(expected - seen):
            findings.append(f"{host}: {interface}.pcap was not copied out")
        for interface in sorted(seen - expected):
            findings.append(f"{host}: {interface}.pcap has no ready mark")
        for path in pcaps:
            relative = path.relative_to(out).as_posix()
            record: dict = {"file": relative}
            try:
                record.update(pcap(path))
                record["xz -9 bytes"] = xz_size(path)
                for mark in by_interface.get(path.stem, []):
                    token = mark.get("token")
                    if isinstance(token, str) and token and not contains(path, token):
                        findings.append(
                            f"{host}: {path.name} does not hold its ready mark on {mark.get('network')}"
                        )
            except (OSError, CaptureError) as error:
                record["error"] = str(error)
                findings.append(f"{host}: {path.name}: {error}")
                files[path.name] = record
                continue
            log = path.with_suffix(".log")
            try:
                counts = tcpdump_counts(log.read_text(encoding="utf-8", errors="replace"))
                record["tcpdump"] = counts
            except (OSError, CaptureError) as error:
                record["counter error"] = str(error)
                findings.append(f"{host}: {log.name}: {error}")
                counts = {}
            if record["packets"] == 0:
                findings.append(f"{host}: {path.name} holds no packet")
            if not record["whole packets"]:
                findings.append(f"{host}: {path.name} holds a packet cut by its snapshot length")
            if counts.get("captured") is not None and counts["captured"] != record["packets"]:
                findings.append(
                    f"{host}: {path.name} holds {record['packets']} packets and tcpdump says it captured "
                    f"{counts['captured']}"
                )
            if counts and counts["received by filter"] != counts["captured"] + counts["dropped by kernel"]:
                findings.append(
                    f"{host}: {path.name}: tcpdump received {counts['received by filter']} packets by the "
                    f"filter, captured {counts['captured']} and dropped {counts['dropped by kernel']}"
                )
            if counts.get("dropped by kernel", 0):
                findings.append(
                    f"{host}: {path.name}: {counts['dropped by kernel']} packets dropped by the kernel"
                )
            files[path.name] = record
        entry["files"] = files
    capture["delivery_findings"] = findings
    capture["delivery_gap"] = bool(findings)
    capture["analysed"] = True
    return capture


def markdown(manifest: dict) -> str:
    """A short packet-delivery report for a run's summary."""

    capture = manifest.get("packet_capture") or {}
    lines = ["# Packet capture", ""]
    if not capture:
        return "\n".join(lines + ["This range asked for no packet capture.", ""])
    hosts = capture.get("hosts") or {}
    started = sum(1 for entry in hosts.values() if entry.get("started") is True)
    if not started:
        introduction = "Packet capture was requested, but no capture host started."
    elif started != len(hosts):
        introduction = f"tcpdump started on {started} of {len(hosts)} packet capture hosts."
    else:
        introduction = "tcpdump started inside each listed packet capture host."
    lines += [
        introduction + " It was configured for whole packets on each non-loopback range interface and left "
        "out ports 1514 and 1515, the host sensors' channel to the manager.",
        "",
        "| Host | Interface | Packets | Kernel drops | Raw bytes | xz -9 bytes |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for host, entry in hosts.items():
        for name, record in (entry.get("files") or {}).items():
            counts = record.get("tcpdump") or {}
            lines.append(
                f"| {host} | {name.removesuffix('.pcap')} | {record.get('packets', 'not read')} | "
                f"{counts.get('dropped by kernel', 'not read')} | {record.get('bytes', 'not read')} | "
                f"{record.get('xz -9 bytes', 'not read')} |"
            )
    gap = capture.get("delivery_gap")
    if capture.get("analysed") is not True or gap is None:
        delivery = "not assessed"
    else:
        delivery = "yes" if gap else "no"
    lines += ["", f"Delivery gap: {delivery}."]
    if capture.get("collect_error"):
        lines.append(f"Collection or analysis error: {str(capture['collect_error']).replace(chr(10), ' ')}")
    for finding in capture.get("delivery_findings") or []:
        lines.append(f"- {finding}")
    return "\n".join(lines) + "\n"

"""Exercise production packet-capture capacity and stopping against a real Linux veth."""

from __future__ import annotations

import argparse
import json
import secrets
import shlex
import subprocess
import time
from pathlib import Path

from bluefire_lab.range import build, engine, packets
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
LABEL = "bluefire.lab.range"
BURST_PACKETS = 32
BURST_PAYLOAD_BYTES = 1_400


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one bounded Docker command and retain its output for a useful failure."""

    done = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if check and done.returncode:
        detail = (done.stderr or done.stdout).strip()[:500]
        raise RuntimeError(f"{shlex.join(arguments[:3])} exited {done.returncode}: {detail}")
    return done


def wait_for_capture(container: str) -> str:
    """Return the sole armed interface once tcpdump has written its PCAP header."""

    script = (
        f"set -- {build.CAPTURE_RUN}/*{build.CAPTURE_ARMED_SUFFIX}; "
        '[ "$#" -eq 1 ] && [ -s "$1" ] || exit 1; '
        "iface=${1##*/}; iface=${iface%.armed}; "
        f'[ -s "{build.CAPTURE_DIR}/$iface.pcap" ] || exit 1; printf "%s" "$iface"'
    )
    deadline = time.monotonic() + 20
    last = "capture wrapper did not arm"
    while time.monotonic() < deadline:
        done = command("docker", "exec", container, "bash", "-c", script, check=False)
        if done.returncode == 0 and done.stdout.strip():
            return done.stdout.strip()
        last = (done.stderr or done.stdout).strip() or last
        time.sleep(0.1)
    raise RuntimeError(last)


def stress_capture(watched: str, peer: str, interface: str, token: str) -> bool:
    """Hold the real tcpdump reader across a bounded kernel-delivered burst, then wait for its tail."""

    pid_file = f"{build.CAPTURE_RUN}/{interface}{build.CAPTURE_ARMED_SUFFIX}"
    signal = f'pid=$(cat {shlex.quote(pid_file)}); kill -STOP "$pid"; kill -0 "$pid"'
    command("docker", "exec", watched, "bash", "-c", signal)
    payload = (
        "$socket=socket_create(AF_INET, SOCK_DGRAM, SOL_UDP); "
        f'$body=str_repeat("x", {BURST_PAYLOAD_BYTES}); '
        f'$tail=str_pad("{token}", {BURST_PAYLOAD_BYTES}, "x"); '
        f"for ($i=0; $i<{BURST_PACKETS}; $i++) {{ "
        f"$data=($i=={BURST_PACKETS - 1}) ? $tail : $body; "
        'if (socket_sendto($socket, $data, strlen($data), 0, "web", 62043) !== strlen($data)) '
        "{ exit(91); } }"
    )
    try:
        command("docker", "exec", peer, "php", "-r", payload)
    finally:
        resume = f'pid=$(cat {shlex.quote(pid_file)}); kill -CONT "$pid"; kill -0 "$pid"'
        command("docker", "exec", watched, "bash", "-c", resume)

    pcap = f"{build.CAPTURE_DIR}/{interface}.pcap"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        found = command("docker", "exec", watched, "grep", "-aFq", "--", token, pcap, check=False)
        if found.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def exercise(image: str, out: Path) -> dict:
    """Hold a bounded burst, send one tail packet, then stop, copy and validate the real capture."""

    suffix = secrets.token_hex(4)
    network = f"bluefire-lab-capture-stop-{suffix}"
    watched = f"{network}-web"
    peer = f"{network}-peer"
    label = f"{LABEL}=capture-stop-{suffix}"
    created: list[str] = []
    network_created = False
    try:
        command(
            "docker",
            "network",
            "create",
            "--internal",
            "-o",
            "com.docker.network.bridge.gateway_mode_ipv4=isolated",
            "--label",
            label,
            network,
        )
        network_created = True
        watched_id = command(
            "docker",
            "create",
            "--name",
            watched,
            "--network",
            network,
            "--network-alias",
            "web",
            "--label",
            label,
            "--pull",
            "never",
            image,
        ).stdout.strip()
        created.append(watched)
        command("docker", "start", watched_id)
        interface = wait_for_capture(watched_id)

        command(
            "docker",
            "create",
            "--name",
            peer,
            "--network",
            network,
            "--network-alias",
            "peer",
            "--label",
            label,
            "--entrypoint",
            "sleep",
            "--pull",
            "never",
            image,
            "infinity",
        )
        created.append(peer)
        command("docker", "start", peer)

        burst_token = f"bluefire-capture-burst-tail-{suffix}"
        burst_tail_seen = stress_capture(watched_id, peer, interface, burst_token)

        out.mkdir(parents=True, exist_ok=False)
        run = engine.Run(range_spec.load(RANGE_ONE), RANGE_ONE.name, out, None, 0)
        run.containers = {"web": watched_id}
        run.write = lambda: None
        capture = run.manifest["packet_capture"]
        entry = capture["hosts"]["web"]
        entry["started"] = True
        token = f"bluefire-capture-tail-{suffix}"
        entry["ready"] = [
            {
                "network": "capture-stop",
                "interface": interface,
                "token": token,
                "seen": True,
            }
        ]
        execute = run.execute
        sent = False

        def send_tail_then_stop(
            identifier: str,
            script: str,
            timeout: float,
            tag: str = "engine:seal",
            user: str = "root",
        ) -> subprocess.CompletedProcess:
            nonlocal sent
            if sent:
                raise AssertionError("capture stop executed more than once")
            sent = True
            tail = f'printf "%s" {shlex.quote(token)} > /dev/udp/peer/62042 || exit 90; '
            return execute(identifier, tail + script, timeout, tag, user)

        run.execute = send_tail_then_stop
        run.stop_captures()
        if not sent:
            raise AssertionError("capture stop did not send its tail packet")
        run.collect_captures()
        run.analyse_captures()

        record = entry["files"].get(f"{interface}.pcap") or {}
        counts = record.get("tcpdump") or {}
        pcap_path = out / record.get("file", "missing")
        assertions = {
            "stopped cleanly": entry["stopped"].get("cleanly") is True,
            "copied": entry["collected"].get("copied") is True,
            "analysed": capture["analysed"] is True,
            "complete delivery": capture["delivery_gap"] is False,
            "burst tail retained": burst_tail_seen and packets.contains(pcap_path, burst_token),
            "burst packet floor": record.get("packets", 0) >= BURST_PACKETS,
            "tail token retained": pcap_path.is_file() and packets.contains(pcap_path, token),
            "PCAP equals captured": record.get("packets") == counts.get("captured"),
            "received equals captured plus dropped": counts.get("received by filter")
            == counts.get("captured", -1) + counts.get("dropped by kernel", -1),
            "zero kernel drops": counts.get("dropped by kernel") == 0,
        }
        failed = [name for name, passed in assertions.items() if not passed]
        if failed:
            detail = {
                "failed": failed,
                "delivery_findings": capture["delivery_findings"],
                "stopped": entry["stopped"],
                "collected": entry["collected"],
                "file": record,
            }
            raise AssertionError(json.dumps(detail, indent=2, sort_keys=True))
        return {
            "interface": interface,
            "packets": record["packets"],
            "burst packets sent": BURST_PACKETS,
            "received by filter": counts["received by filter"],
            "dropped by kernel": counts["dropped by kernel"],
        }
    finally:
        for container in reversed(created):
            command("docker", "rm", "-f", container, check=False)
        if network_created:
            command("docker", "network", "rm", network, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="already-built range host image")
    parser.add_argument("--out", required=True, type=Path, help="new folder for copied capture evidence")
    arguments = parser.parse_args()
    result = exercise(arguments.image, arguments.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

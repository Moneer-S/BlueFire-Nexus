"""A container as the lab target: a throwaway copy of an image, started by the lab.

The tests then run inside the container, and the sensors stay on the machine that hosts
it, which is not a target. The container gets no way out: it sits on one internal network,
with none of the settings that would let what runs in it reach the host, and the lab checks
both before the first test and after the last, from inside the container's own network
namespace with the host's tools, so that a tool missing in the image cannot pass the check.

Everything here is created with the label bluefire-lab=1 and removed by that label.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

LABEL = "bluefire-lab=1"
# An address outside every lab network, for the probes that must fail: a public resolver.
OUTSIDE_V4, OUTSIDE_V6, METADATA = "1.1.1.1", "2606:4700:4700::1111", "169.254.169.254"
OUTSIDE_NAME = "github.com"
PROBE_PORT = 47113


def sh(*command: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, capture_output=True, text=True, errors="replace", timeout=timeout, check=False
    )


def docker(*arguments: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return sh("sudo", "docker", *arguments, timeout=timeout)


def start(image: str, run_id: str, read_only: list[str]) -> dict:
    """Create the internal network and the container, the image started with its own command.

    read_only are folders of the host that the container sees read-only at the same paths:
    the executor and the test definitions, filled before the container exists."""

    name, network = f"bluefire-lab-target-{run_id}", f"bluefire-lab-{run_id}"
    made = docker("network", "create", "--internal", "--label", LABEL, network)
    if made.returncode != 0:
        raise SystemExit(f"docker could not create the internal network: {made.stderr.strip()}")
    mounts = [argument for folder in read_only for argument in ("--volume", f"{folder}:{folder}:ro")]
    made = docker("run", "--detach", "--name", name, "--label", LABEL, "--network", network, *mounts, image)
    if made.returncode != 0:
        raise SystemExit(f"docker could not start the image {image}: {made.stderr.strip()}")
    return {"container": name, "network": network, "image": image, "read_only": read_only}


def inspect(target: dict) -> tuple[dict, dict]:
    """What the runtime says the container and its network are."""

    container = json.loads(docker("inspect", target["container"]).stdout or "[{}]")[0]
    network = json.loads(docker("network", "inspect", target["network"]).stdout or "[{}]")[0]
    return container, network


def refusals(container: dict, network: dict, target: dict) -> list[str]:
    """Why the lab will not run tests in this container: each setting, read back from the
    runtime, with which what runs in the container could leave it. Empty when there is none."""

    host, found = container.get("HostConfig") or {}, []
    if not (container.get("State") or {}).get("Running"):
        found.append("the container is not running: the image's own command ended")
    if host.get("Privileged"):
        found.append("the container is privileged")
    if host.get("CapAdd"):
        found.append(f"the container has added capabilities: {', '.join(host['CapAdd'])}")
    if host.get("Devices"):
        found.append("the container has a device of the host")
    for setting, name in (
        ("NetworkMode", "network"),
        ("PidMode", "process"),
        ("IpcMode", "IPC"),
        ("UTSMode", "UTS"),
    ):
        if host.get(setting) == "host":
            found.append(f"the container shares the host's {name} namespace")
    if host.get("PortBindings") or host.get("PublishAllPorts"):
        found.append("the container publishes a port")
    if (host.get("RestartPolicy") or {}).get("Name") not in ("", "no", None):
        found.append("the container has a restart policy")
    for option in host.get("SecurityOpt") or []:
        if "unconfined" in option:
            found.append(f"the container runs with {option}")
    for mount in container.get("Mounts") or []:
        source = mount.get("Source", "")
        if "docker.sock" in source:
            found.append("the container has the Docker socket")
        elif mount.get("RW") or source not in target["read_only"]:
            found.append(f"the container has a folder of the host it may not have, or may write to: {source}")
    networks = sorted((container.get("NetworkSettings") or {}).get("Networks") or {})
    if networks != [target["network"]]:
        found.append(f"the container is on the networks {', '.join(networks) or 'none'}, not only on its own")
    if not network.get("Internal"):
        found.append(f"the network {target['network']} is not internal: it has a route out")
    return found


def probe(description: str, expect: str, *command: str) -> dict:
    """One probe of the check: a command, whether it had to succeed or to fail, and whether it did."""

    try:
        done = sh(*command, timeout=20)
        succeeded, said = done.returncode == 0, (done.stdout + done.stderr).strip()[-300:]
    except subprocess.TimeoutExpired:
        succeeded, said = False, "no answer within 20 s"
    return {
        "probe": description,
        "expected": expect,
        "command": " ".join(command),
        "succeeded": succeeded,
        "held": succeeded == (expect == "succeeds"),
        "said": said,
    }


def addresses_of_host() -> list[str]:
    """The IPv4 addresses of the host on every interface but loopback."""

    found = sh("ip", "-4", "-o", "addr", "show").stdout
    return sorted({line.split()[3].split("/")[0] for line in found.splitlines() if " lo " not in line})


def check(pid: str, nameservers: list[str]) -> list[dict]:
    """Probe what the container can reach, by TCP, with the host's tools inside the container's
    network namespace. Two probes from the host must succeed, or the others show nothing. Every
    probe from the container must fail: an outside address over IPv4 and IPv6, the cloud
    metadata address, a listener the lab opens on the host for the check, and a name lookup."""

    inside = ("sudo", "nsenter", "--target", pid, "--net")
    curl = ("curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "5", "--noproxy", "*")
    empty = tempfile.mkdtemp(prefix="bluefire-lab-listener-")
    listener = subprocess.Popen(
        ["python3", "-m", "http.server", str(PROBE_PORT), "--bind", "0.0.0.0", "--directory", empty],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        sh("sleep", "1")
        hosts = addresses_of_host()
        results = [
            probe("from the host to an outside address", "succeeds", *curl, f"https://{OUTSIDE_V4}/"),
            probe("from the host to its own listener", "succeeds", *curl, f"http://127.0.0.1:{PROBE_PORT}/"),
            probe(
                "from the container to an outside address over IPv4",
                "fails",
                *inside,
                *curl,
                f"https://{OUTSIDE_V4}/",
            ),
            probe(
                "from the container to an outside address over IPv6",
                "fails",
                *inside,
                *curl,
                f"https://[{OUTSIDE_V6}]/",
            ),
            probe(
                "from the container to the cloud metadata address",
                "fails",
                *inside,
                *curl,
                f"http://{METADATA}/",
            ),
        ]
        for address in hosts:
            what = f"from the container to the listener on the host at {address}"
            results.append(probe(what, "fails", *inside, *curl, f"http://{address}:{PROBE_PORT}/"))
        for server in nameservers:
            what = f"a lookup of {OUTSIDE_NAME} from the container at its name server {server}"
            dig = ("dig", "+tcp", "+time=3", "+tries=1", "+short", f"@{server}", OUTSIDE_NAME)
            # dig ends without error when the server answers with no address, so the answer decides.
            results.append(probe(what, "fails", *inside, "sh", "-c", f"{' '.join(dig)} | grep -q ."))
    finally:
        listener.terminate()
        os.rmdir(empty)
    return results


def leash(target: dict) -> dict:
    """The container's settings read back from the runtime, and the check made from it. The
    leash held when no setting is refused and every probe came out as it had to."""

    container, network = inspect(target)
    pid = str((container.get("State") or {}).get("Pid") or "")
    refused = refusals(container, network, target)
    resolv = docker("exec", target["container"], "cat", "/etc/resolv.conf").stdout
    servers = [
        line.split()[1]
        for line in resolv.splitlines()
        if line.startswith("nameserver") and len(line.split()) > 1
    ]
    probes = check(pid, servers or ["127.0.0.11"]) if pid not in ("", "0") else []
    return {
        "refused": refused,
        "probes": probes,
        "held": not refused and bool(probes) and all(found["held"] for found in probes),
    }


def close_host(target: dict, on: bool = True) -> None:
    """Have the host answer nothing from the container's network: Docker keeps an internal
    network away from other networks, not from the host's own addresses."""

    network = json.loads(docker("network", "inspect", target["network"]).stdout or "[{}]")[0]
    bridge = "br-" + network.get("Id", "")[:12]
    for tables in ("iptables", "ip6tables"):
        sh("sudo", tables, "-I" if on else "-D", "INPUT", "-i", bridge, "-j", "REJECT")


def remove() -> list[str]:
    """Remove every container and network of the lab, by its label, and say what is left."""

    for kind in (("ps", "--all"), ("network", "ls")):
        found = docker(*kind, "--filter", f"label={LABEL}", "--quiet").stdout.split()
        if found:
            docker(*(("rm", "--force") if kind[0] == "ps" else ("network", "rm")), *found)
    left = docker("ps", "--all", "--filter", f"label={LABEL}", "--quiet").stdout.split()
    return left + docker("network", "ls", "--filter", f"label={LABEL}", "--quiet").stdout.split()

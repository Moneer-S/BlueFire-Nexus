"""Read a range's spec file, and derive from it the probes that show its segmentation.

This reads the parts that bring a range up: `range`, `version`, `prefix`,
`docker`, `networks` and `hosts`. The other sections of a spec (the published
tests, the defense, the activity, the path and the keys that plant a host's
contents) are accepted here and read by the parts of the lab that use them.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

KEYS = {"range", "version", "prefix", "docker", "networks", "hosts"}
LATER_KEYS = {"sentence", "atomic_red_team", "executor", "base", "defense", "activity", "path"}
HOST_KEYS = {"kind", "role", "networks", "listens", "image"}
LATER_HOST_KEYS = {
    "packages",
    "services",
    "accounts",
    "keys",
    "known_hosts",
    "dirs",
    "files",
    "database",
    "sshd",
    "serve",
    "atomics_src",
    "agent",
    "watch",
}
KINDS = ("attacker", "internet", "host", "defense")
# The isolated gateway mode, which leaves the Docker host without an address on a range network,
# came with Docker Engine 28.
MIN_ENGINE = 28
PREFIX = "bluefire-lab-"
NAME = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})\Z")


class SpecError(ValueError):
    """A spec file the lab refuses, with the reason."""


@dataclass(frozen=True)
class Host:
    name: str
    kind: str
    role: str
    networks: tuple[str, ...]
    listens: tuple[int, ...]
    image: str | None

    @property
    def digest(self) -> str | None:
        found = IMAGE.match(self.image or "")
        return found.group(2) if found else None


@dataclass(frozen=True)
class Spec:
    range: str
    version: int
    prefix: str
    min_engine: int
    networks: tuple[str, ...]
    hosts: dict[str, Host]
    text: str = ""

    def network_name(self, network: str) -> str:
        return f"{self.prefix}-{network}"

    def container_name(self, host: str) -> str:
        return f"{self.prefix}-{host}"

    def members(self, network: str) -> list[str]:
        return [host.name for host in self.hosts.values() if network in host.networks]

    def shared(self, one: str, other: str) -> list[str]:
        return [network for network in self.hosts[one].networks if network in self.hosts[other].networks]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()


@dataclass(frozen=True)
class Probe:
    """One TCP connection the seal tries: from a host to a port on another host's address."""

    source: str
    target: str
    network: str  # the network whose address of the target is used
    port: int
    must: str  # "connect" or "fail"

    @property
    def label(self) -> str:
        return f"{self.source} -> {self.target}@{self.network}:{self.port}"


def load(path: Path) -> Spec:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise SpecError("the spec must be UTF-8 text") from error
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise SpecError(f"the spec is not valid YAML: {error}") from error
    return parse(data, text)


def parse(data: object, text: str = "") -> Spec:
    if not isinstance(data, dict):
        raise SpecError(
            "the spec must be a mapping with the keys range, version, prefix, docker, networks and hosts"
        )
    unknown = sorted(str(key) for key in data if key not in KEYS | LATER_KEYS)
    if unknown:
        raise SpecError(f"unknown key at the top of the spec: {', '.join(unknown)}")
    missing = sorted(KEYS - set(data))
    if missing:
        raise SpecError(f"the spec lacks: {', '.join(missing)}")

    name = data["range"]
    if not isinstance(name, str) or not NAME.match(name):
        raise SpecError("range must be a name of lower-case letters, digits and single hyphens")
    if data["version"] != 1 or isinstance(data["version"], bool):
        raise SpecError("version must be 1")
    prefix = data["prefix"]
    if not isinstance(prefix, str) or not prefix.startswith(PREFIX) or not NAME.match(prefix):
        raise SpecError(
            f"prefix must start with {PREFIX} and hold only lower-case letters, digits and single hyphens"
        )

    docker = data["docker"]
    if not isinstance(docker, dict) or set(docker) != {"min_engine"}:
        raise SpecError("docker must be {min_engine: <major version>} and nothing else")
    min_engine = docker["min_engine"]
    if not isinstance(min_engine, int) or isinstance(min_engine, bool) or min_engine < MIN_ENGINE:
        raise SpecError(
            f"docker.min_engine must be {MIN_ENGINE} or later: older engines cannot leave the host "
            "without an address on a range network (the isolated gateway mode)"
        )

    networks = data["networks"]
    if not isinstance(networks, dict) or not networks:
        raise SpecError("networks must name at least one network")
    for network, settings in networks.items():
        if not isinstance(network, str) or not NAME.match(network):
            raise SpecError(f"network name {network!r} must be lower-case letters, digits and single hyphens")
        if settings not in (None, {}):
            raise SpecError(
                f"network {network} has settings, and networks take none: every range network is created "
                "internal, with the isolated gateway mode and without IPv6"
            )

    hosts_data = data["hosts"]
    if not isinstance(hosts_data, dict) or not hosts_data:
        raise SpecError("hosts must name at least one host")
    hosts = {}
    for host, settings in hosts_data.items():
        if not isinstance(host, str) or not NAME.match(host):
            raise SpecError(f"host name {host!r} must be lower-case letters, digits and single hyphens")
        hosts[host] = _host(host, settings, networks)

    for network in networks:
        if not any(network in host.networks for host in hosts.values()):
            raise SpecError(f"network {network} has no host")
    spec = Spec(name, 1, prefix, min_engine, tuple(networks), hosts, text)
    for host in hosts:
        if not any(probe.source == host and probe.must == "connect" for probe in matrix(spec)):
            raise SpecError(
                f"host {host} shares a network with no host that listens, so the seal would have no "
                "connection from it that must work, and its failed probes would prove nothing"
            )
    return spec


def _host(name: str, settings: object, networks: dict) -> Host:
    if not isinstance(settings, dict):
        raise SpecError(f"host {name} must be a mapping")
    unknown = sorted(str(key) for key in settings if key not in HOST_KEYS | LATER_HOST_KEYS)
    if unknown:
        raise SpecError(f"host {name} has unknown keys: {', '.join(unknown)}")
    kind = settings.get("kind")
    if kind not in KINDS:
        raise SpecError(f"host {name}: kind must be one of {', '.join(KINDS)}")
    role = settings.get("role")
    if not isinstance(role, str) or not role.strip():
        raise SpecError(f"host {name}: role must say in words what the host is")
    joined = settings.get("networks")
    if not isinstance(joined, list) or not joined:
        raise SpecError(f"host {name}: networks must list at least one network")
    for network in joined:
        if not isinstance(network, str):
            raise SpecError(f"host {name}: networks must list network names")
        if network not in networks:
            raise SpecError(f"host {name} joins network {network}, which networks does not declare")
    if len(set(joined)) != len(joined):
        raise SpecError(f"host {name} lists a network twice")
    listens = settings.get("listens", [])
    if not isinstance(listens, list) or not all(
        isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 for port in listens
    ):
        raise SpecError(f"host {name}: listens must be a list of TCP ports")
    if len(set(listens)) != len(listens):
        raise SpecError(f"host {name} lists a port twice")
    image = settings.get("image")
    if image is not None and (not isinstance(image, str) or not IMAGE.match(image)):
        raise SpecError(f"host {name}: image must be pinned by digest, as in name:tag@sha256:<64 hex digits>")
    return Host(name, kind, role.strip(), tuple(joined), tuple(listens), image)


def matrix(spec: Spec) -> list[Probe]:
    """The segmentation probes, in a fixed order.

    Every ordered pair of hosts that share a network must connect on each port
    the target listens on, at the target's address in each shared network.
    Every pair that shares none must fail, on the target's first listening port
    (22 when it has none), at each of the target's addresses.
    """

    probes = []
    for source in spec.hosts:
        for target, host in spec.hosts.items():
            if target == source:
                continue
            shared = spec.shared(source, target)
            if shared:
                probes += [
                    Probe(source, target, network, port, "connect")
                    for port in host.listens
                    for network in shared
                ]
            else:
                port = host.listens[0] if host.listens else 22
                probes += [Probe(source, target, network, port, "fail") for network in host.networks]
    return probes

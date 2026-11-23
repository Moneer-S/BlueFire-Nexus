"""Read a range's spec file, and derive from it the probes that show its segmentation.

This reads the parts that bring a range up: `range`, `version`, `prefix`,
`docker`, `networks`, `hosts`, the `base` that hosts without an image of their
own are built from, and the `defense`: a Wazuh manager and the agents baked
into the hosts. The other sections of a spec (the published tests, the
activity, the path and the keys that plant a host's contents) are accepted here
and read by the parts of the lab that use them.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KEYS = {"range", "version", "prefix", "docker", "networks", "hosts"}
READ_KEYS = {"base", "defense"}
LATER_KEYS = {"sentence", "atomic_red_team", "executor", "activity", "path"}
HOST_KEYS = {"kind", "role", "networks", "listens", "image", "agent", "watch", "packages", "services"}
LATER_HOST_KEYS = {
    "accounts",
    "keys",
    "known_hosts",
    "dirs",
    "files",
    "database",
    "sshd",
    "serve",
    "atomics_src",
}
KINDS = ("attacker", "internet", "host", "defense")
# The isolated gateway mode, which leaves the Docker host without an address on a range network,
# came with Docker Engine 28.
MIN_ENGINE = 28
PREFIX = "bluefire-lab-"
NAME = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})\Z")
SNAPSHOT = re.compile(r"[0-9]{8}T[0-9]{6}Z\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
AGENT_VERSION = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+\Z")
SHA512 = re.compile(r"[0-9a-f]{128}\Z")
# A path Wazuh can watch: absolute, no spaces, no commas (its folder lists are comma separated)
# and nothing that would need escaping in its XML configuration.
WATCH_PATH = re.compile(r"/[A-Za-z0-9._/-]*\Z")
# Features of the Wazuh agent that a spec may switch off, each by its own setting.
OFF = ("command_monitoring", "sca", "rootcheck", "syscollector")
# Log formats whose files the delivery count has been shown to read line by line.
LOG_FORMATS = ("syslog",)
# The services a host's start script can start, and the package each one needs.
SERVICES = {"sshd": "openssh-server"}
# Agents connect to the manager on 1514 and enroll on 1515.
MANAGER_PORTS = (1514, 1515)


class SpecError(ValueError):
    """A spec file the lab refuses, with the reason."""


@dataclass(frozen=True)
class Log:
    path: str
    format: str


@dataclass(frozen=True)
class Watch:
    """What an agent collects: log files, and folders whose files it watches in real time."""

    logs: tuple[Log, ...] = ()
    fim_realtime: tuple[str, ...] = ()

    def merged(self, other: Watch) -> Watch:
        logs = list(self.logs) + [log for log in other.logs if log.path not in {x.path for x in self.logs}]
        folders = list(self.fim_realtime) + [f for f in other.fim_realtime if f not in self.fim_realtime]
        return Watch(tuple(logs), tuple(folders))


@dataclass(frozen=True)
class Base:
    image: str
    apt_snapshot: str


@dataclass(frozen=True)
class Wazuh:
    manager_image: str
    agent_version: str
    agent_sha512: str
    alert_level: int
    off: tuple[str, ...]

    @property
    def version(self) -> str:
        """The Wazuh version, as in 4.14.10."""

        return AGENT_VERSION.match(self.agent_version).group(1)


@dataclass(frozen=True)
class Host:
    name: str
    kind: str
    role: str
    networks: tuple[str, ...]
    listens: tuple[int, ...]
    image: str | None
    agent: bool = False
    watch: Watch = field(default_factory=Watch)
    packages: tuple[str, ...] = ()
    services: tuple[str, ...] = ()

    @property
    def digest(self) -> str | None:
        found = IMAGE.match(self.image or "")
        return found.group(2) if found else None

    @property
    def built(self) -> bool:
        """True when the lab builds the host's image from the spec, rather than running a pinned image."""

        return self.image is None


@dataclass(frozen=True)
class Spec:
    range: str
    version: int
    prefix: str
    min_engine: int
    networks: tuple[str, ...]
    hosts: dict[str, Host]
    text: str = ""
    base: Base | None = None
    wazuh: Wazuh | None = None
    watch: Watch = field(default_factory=Watch)

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

    @property
    def manager(self) -> str | None:
        """The host that runs the Wazuh manager, if the range has a defense."""

        return next((host.name for host in self.hosts.values() if host.kind == "defense"), None)

    @property
    def agents(self) -> list[str]:
        return [host.name for host in self.hosts.values() if host.agent]

    def watch_for(self, host: str) -> Watch:
        """What the agent on a host collects: the defense's watch for every agent, then the host's own."""

        return self.watch.merged(self.hosts[host].watch)


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


class _Loader(yaml.SafeLoader):
    """YAML as a spec is written: only true and false are booleans.

    YAML 1.1 also reads yes, no, on and off as booleans, which would turn the
    key `off` of defense.wazuh into false.
    """


_Loader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def read(text: str) -> object:
    """The YAML document of a spec, before the loader's rules."""

    try:
        return yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as error:
        raise SpecError(f"the spec is not valid YAML: {error}") from error


def load(path: Path) -> Spec:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise SpecError("the spec must be UTF-8 text") from error
    return parse(read(text), text)


def parse(data: object, text: str = "") -> Spec:
    if not isinstance(data, dict):
        raise SpecError(
            "the spec must be a mapping with the keys range, version, prefix, docker, networks and hosts"
        )
    unknown = sorted(str(key) for key in data if key not in KEYS | READ_KEYS | LATER_KEYS)
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

    base = _base(data["base"]) if "base" in data else None
    wazuh, watch = _defense(data["defense"]) if "defense" in data else (None, Watch())

    hosts_data = data["hosts"]
    if not isinstance(hosts_data, dict) or not hosts_data:
        raise SpecError("hosts must name at least one host")
    hosts = {}
    for host, settings in hosts_data.items():
        if not isinstance(host, str) or not NAME.match(host):
            raise SpecError(f"host name {host!r} must be lower-case letters, digits and single hyphens")
        hosts[host] = _host(host, settings, networks, base, wazuh)

    for network in networks:
        if not any(network in host.networks for host in hosts.values()):
            raise SpecError(f"network {network} has no host")
    _defense_hosts(hosts, wazuh)
    spec = Spec(name, 1, prefix, min_engine, tuple(networks), hosts, text, base, wazuh, watch)
    for host in hosts:
        if not any(probe.source == host and probe.must == "connect" for probe in matrix(spec)):
            raise SpecError(
                f"host {host} shares a network with no host that listens, so the seal would have no "
                "connection from it that must work, and its failed probes would prove nothing"
            )
    return spec


def _mapping(value: object, where: str, allowed: set[str], required: set[str]) -> dict:
    if not isinstance(value, dict):
        raise SpecError(f"{where} must be a mapping with the keys {', '.join(sorted(allowed))}")
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise SpecError(f"{where} has unknown keys: {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise SpecError(f"{where} lacks: {', '.join(missing)}")
    return value


def _base(value: object) -> Base:
    base = _mapping(value, "base", {"image", "apt_snapshot"}, {"image", "apt_snapshot"})
    if not isinstance(base["image"], str) or not IMAGE.match(base["image"]):
        raise SpecError("base.image must be pinned by digest, as in ubuntu:noble@sha256:<64 hex digits>")
    if not isinstance(base["apt_snapshot"], str) or not SNAPSHOT.match(base["apt_snapshot"]):
        raise SpecError(
            "base.apt_snapshot must be a moment of the Ubuntu snapshot archive, as in 20261120T000000Z "
            "(quoted, so that YAML reads it as text)"
        )
    return Base(base["image"], base["apt_snapshot"])


def _watch(value: object, where: str) -> Watch:
    watch = _mapping(value, where, {"logs", "fim_realtime"}, set())
    logs = watch.get("logs", [])
    if not isinstance(logs, list):
        raise SpecError(f"{where}.logs must be a list of {{path, format}}")
    found = []
    for log in logs:
        entry = _mapping(log, f"{where}.logs", {"path", "format"}, {"path", "format"})
        path = entry["path"]
        if not isinstance(path, str) or not WATCH_PATH.match(path) or "/../" in path + "/":
            raise SpecError(f"{where}.logs: {path!r} must be an absolute path without spaces or commas")
        if entry["format"] not in LOG_FORMATS:
            raise SpecError(f"{where}.logs: the format of {path} must be one of {', '.join(LOG_FORMATS)}")
        if path in {item.path for item in found}:
            raise SpecError(f"{where}.logs lists {path} twice")
        found.append(Log(path, entry["format"]))
    folders = watch.get("fim_realtime", [])
    if not isinstance(folders, list):
        raise SpecError(f"{where}.fim_realtime must be a list of folders")
    for folder in folders:
        if not isinstance(folder, str) or not WATCH_PATH.match(folder) or "/../" in folder + "/":
            raise SpecError(
                f"{where}.fim_realtime: {folder!r} must be an absolute path without spaces or commas"
            )
    if len(set(folders)) != len(folders):
        raise SpecError(f"{where}.fim_realtime lists a folder twice")
    return Watch(tuple(found), tuple(folders))


def _defense(value: object) -> tuple[Wazuh, Watch]:
    defense = _mapping(value, "defense", {"wazuh", "watch"}, {"wazuh"})
    wazuh = _mapping(
        defense["wazuh"],
        "defense.wazuh",
        {"manager_image", "agent_deb", "alert_level", "off"},
        {"manager_image", "agent_deb", "alert_level"},
    )
    manager_image = wazuh["manager_image"]
    if not isinstance(manager_image, str) or not IMAGE.match(manager_image):
        raise SpecError(
            "defense.wazuh.manager_image must be pinned by digest, as in "
            "wazuh/wazuh-manager:4.14.10@sha256:<64 hex digits>"
        )
    deb = _mapping(
        wazuh["agent_deb"], "defense.wazuh.agent_deb", {"version", "sha512"}, {"version", "sha512"}
    )
    version = deb["version"]
    if not isinstance(version, str) or not AGENT_VERSION.match(version):
        raise SpecError("defense.wazuh.agent_deb.version must be a package version, as in 4.14.10-1")
    if not isinstance(deb["sha512"], str) or not SHA512.match(deb["sha512"]):
        raise SpecError(
            "defense.wazuh.agent_deb.sha512 must be the package's SHA-512 checksum, 128 lower-case hex digits"
        )
    tag = IMAGE.match(manager_image).group(1)
    if tag != ":" + AGENT_VERSION.match(version).group(1):
        raise SpecError(
            f"the agent package {version} and the manager image {manager_image.split('@')[0]} differ: "
            "the manager image's tag must be the agent's version, and the seal checks the version each one reports"
        )
    level = wazuh["alert_level"]
    if not isinstance(level, int) or isinstance(level, bool) or not 0 < level <= 16:
        raise SpecError("defense.wazuh.alert_level must be a Wazuh rule level from 1 to 16")
    off = wazuh.get("off", [])
    if not isinstance(off, list) or any(item not in OFF for item in off) or len(set(off)) != len(off):
        raise SpecError(f"defense.wazuh.off may list only these agent features, once each: {', '.join(OFF)}")
    watch = _watch(defense.get("watch", {}), "defense.watch")
    return Wazuh(manager_image, version, deb["sha512"], level, tuple(off)), watch


def _defense_hosts(hosts: dict[str, Host], wazuh: Wazuh | None) -> None:
    managers = [host for host in hosts.values() if host.kind == "defense"]
    if wazuh is None:
        if managers:
            raise SpecError(f"host {managers[0].name} is of kind defense, and the spec has no defense.wazuh")
        return
    if len(managers) != 1:
        raise SpecError("a spec with defense.wazuh needs exactly one host of kind defense, the manager")
    manager = managers[0]
    missing = [port for port in MANAGER_PORTS if port not in manager.listens]
    if missing:
        raise SpecError(
            f"host {manager.name} runs the Wazuh manager and must list 1514 and 1515 in listens "
            "(agents connect on 1514 and enroll on 1515)"
        )
    if not any(host.agent for host in hosts.values()):
        raise SpecError(
            "a spec with defense.wazuh needs at least one host built from base with an agent: "
            "without one the defense watches nothing"
        )
    for host in hosts.values():
        if host.agent and not set(host.networks) & set(manager.networks):
            raise SpecError(f"host {host.name} has an agent and shares no network with the manager")


def _host(name: str, settings: object, networks: dict, base: Base | None, wazuh: Wazuh | None) -> Host:
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

    if kind == "defense":
        extra = sorted(set(settings) - {"kind", "role", "networks", "listens"})
        if extra:
            raise SpecError(
                f"host {name} runs the Wazuh manager, whose image comes from defense.wazuh.manager_image, "
                f"and takes only kind, role, networks and listens, not {', '.join(extra)}"
            )
        return Host(name, kind, role.strip(), tuple(joined), tuple(listens), None)

    if image is None and base is None:
        raise SpecError(f"host {name} has no image, so the lab builds it from base, and the spec has no base")
    built_keys = sorted({"agent", "watch", "packages", "services"} & set(settings))
    if image is not None and built_keys:
        raise SpecError(
            f"host {name} runs the pinned image unchanged, so it cannot have {', '.join(built_keys)}: "
            "leave out image to build the host from base"
        )
    agent = settings.get("agent", image is None and wazuh is not None)
    if not isinstance(agent, bool):
        raise SpecError(f"host {name}: agent must be true or false")
    if agent and wazuh is None:
        raise SpecError(f"host {name} has an agent, and the spec has no defense.wazuh")
    if "watch" in settings and not agent:
        raise SpecError(f"host {name} has watch but no agent to collect it")
    watch = _watch(settings["watch"], f"host {name}: watch") if "watch" in settings else Watch()

    packages = settings.get("packages", [])
    if not isinstance(packages, list) or not all(isinstance(p, str) and PACKAGE.match(p) for p in packages):
        raise SpecError(f"host {name}: packages must be a list of Ubuntu package names")
    if len(set(packages)) != len(packages):
        raise SpecError(f"host {name} lists a package twice")
    services = settings.get("services", [])
    if not isinstance(services, list):
        raise SpecError(f"host {name}: services must be a list")
    for service in services:
        if service not in SERVICES:
            raise SpecError(
                f"host {name}: the lab cannot start service {service!r} yet; it can start {', '.join(SERVICES)}"
            )
        if SERVICES[service] not in packages:
            raise SpecError(
                f"host {name}: service {service} needs the package {SERVICES[service]} in packages"
            )
    if len(set(services)) != len(services):
        raise SpecError(f"host {name} lists a service twice")
    return Host(
        name,
        kind,
        role.strip(),
        tuple(joined),
        tuple(listens),
        image,
        agent,
        watch,
        tuple(packages),
        tuple(services),
    )


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

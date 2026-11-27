"""Read a range's spec file, and derive from it the probes that show its segmentation.

This reads the parts that bring a range up: `range`, `version`, `prefix`,
`docker`, `networks`, `hosts` with what is planted in each, the `base` that
hosts without an image of their own are built from, the `defense` (a Wazuh
manager and the agents baked into the hosts), and the pin of Atomic Red Team
whose files the hosts carry. Of the `path` it reads only which techniques and
hosts its steps name. The `activity` is read by the module `activity`, which
also reads which accounts and addresses the path uses. The other sections (the
sentence, the executor and the rest of the path) are accepted here and read by
the parts of the lab that use them.

`rule_sets` names public rule sets, each pinned to a commit of its repository
or carried as tracked files pinned by a SHA-256 manifest. `defenses` names the
defenses that judge a run: each one the kinds of sensor it records with and
the rules it runs, which are the rules the Wazuh manager runs live (`wazuh`)
or a rule set of `rule_sets`, evaluated after the run.

What a host may have planted in it is a closed list: accounts, keys,
known_hosts, dirs, files, database, sshd, packages, services, serve and
atomics_src. It is not a general provisioning system.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

import yaml

KEYS = {"range", "version", "prefix", "docker", "networks", "hosts"}
READ_KEYS = {"base", "defense", "atomic_red_team", "path", "activity", "rule_sets", "defenses"}
LATER_KEYS = {"sentence", "executor"}
HOST_KEYS = {
    "kind",
    "role",
    "networks",
    "listens",
    "image",
    "agent",
    "watch",
    "packages",
    "services",
    "capture",
}
PLANT_KEYS = {
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
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA512 = re.compile(r"[0-9a-f]{128}\Z")
# A path Wazuh can watch: absolute, no spaces, no commas (its folder lists are comma separated)
# and nothing that would need escaping in its XML configuration.
WATCH_PATH = re.compile(r"/[A-Za-z0-9._/-]*\Z")
# Features of the Wazuh agent that a spec may switch off, each by its own setting.
OFF = ("command_monitoring", "sca", "rootcheck", "syscollector")
# Log formats whose files the delivery count has been shown to read line by line: with these, each
# line of the file is the full log of one event. (With mysql_log, Wazuh 4.14.10 delivered none of
# MariaDB 10.11's error log lines.)
LOG_FORMATS = ("syslog", "apache")
# The services a host's start script can start, the package each one needs, and the TCP ports it
# listens on. A host built from base lists in `listens` exactly the ports of its services.
SERVICES = {
    "sshd": "openssh-server",
    "nginx": "nginx",
    "php-fpm": "php-fpm",
    "mariadb": "mariadb-server",
    "cron": "cron",
    "inet-server": "python3",
}
SERVICE_PORTS = {"sshd": (22,), "nginx": (80,), "mariadb": (3306,), "inet-server": (80, 443)}
# Agents connect to the manager on 1514 and enroll on 1515.
MANAGER_PORTS = (1514, 1515)
# Accounts every host built from base has, besides those its spec plants.
SYSTEM_ACCOUNTS = ("root", "www-data")
ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
# Planted values reach a shell, SQL and PHP, so they hold only characters that need no quoting there.
PLAIN_VALUE = re.compile(r"[A-Za-z0-9._-]+\Z")
DB_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
MODE = re.compile(r"0?[0-7]{3}\Z")
SUDO_COMMAND = re.compile(r"/[A-Za-z0-9._/-]+( [A-Za-z0-9._/=-]+)*\Z")
TECHNIQUE = re.compile(r"T[0-9]{4}(\.[0-9]{3})?\Z")
ATOMIC_FILE = re.compile(r"atomic:(T[0-9]{4}(?:\.[0-9]{3})?/src/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)\Z")
REPO = re.compile(r"repo:([a-z][a-z0-9-]*)\Z")
RELATIVE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
GITHUB_REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+\Z")
KEY_TYPES = ("rsa", "ed25519")
# The folder beside the spec that holds the git repositories `repo:<name>` names.
REPOS = "repos"
# The logs every agent must collect, because the engine reads its own lines in them: the ready and
# end nonces and the syslog marks go to auth.log, the program start mark to snoopy.log.
ENGINE_LOGS = ("/var/log/auth.log", "/var/log/snoopy.log")
# The kinds of sensor a range can have, and what of the spec gives a range each one. A defense
# names the kinds it records with.
WAZUH_AGENT = "wazuh-agent"
PACKET_CAPTURE = "packet-capture"
SENSORS = {WAZUH_AGENT: "defense.wazuh", PACKET_CAPTURE: "a host with capture: packets"}
# The rules the Wazuh manager of defense.wazuh runs live, as a defense names them.
WAZUH_RULES = "wazuh"
# The kinds of rule set the lab can give a recorded run to, and the kinds of sensor whose records
# each kind reads. The live rules read what the agents send.
RULE_KINDS = {"sigma": (WAZUH_AGENT,), "suricata": (PACKET_CAPTURE,)}
LIVE_RULES = {WAZUH_RULES: (WAZUH_AGENT,)}
# A rule set's name is its detector's id in a recording, where these two ids are taken: `pinned` is
# the manager's live rules, and `lab` the rules written in this repository.
RESERVED_DETECTORS = ("pinned", "lab")
# A defense's id, as the recording format takes it, and the most defenses and rules it holds.
DEFENSE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
# Text that the recording format refuses outside the few long-form fields that explicitly allow it.
FORBIDDEN_TEXT = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]")
MAX_DEFENSES = 8
MAX_RULES = 4
MAX_NAME = 200


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
    # The level from which a Wazuh alert counts as an alert when a step is scored. It is not the
    # manager's log_alert_level: the manager keeps the stock 3, so that matches below this level
    # are still written to alerts.json and can be shown for review. It changes no image.
    alert_level: int
    off: tuple[str, ...]

    @property
    def version(self) -> str:
        """The Wazuh version, as in 4.14.10."""

        return AGENT_VERSION.match(self.agent_version).group(1)


@dataclass(frozen=True)
class Atomics:
    """The pin of Atomic Red Team, and the lock file of what the lab fetches from it."""

    repo: str
    commit: str
    lock: str


@dataclass(frozen=True)
class RuleSet:
    """A pinned public rule set.

    Repository sets use ``repo`` through ``lock``. A tracked set keeps those
    positional fields in place for compatibility and uses ``source_file``,
    ``sha256`` and ``version`` for its repository-relative manifest.
    """

    name: str
    kind: str
    repo: str = ""
    commit: str = ""
    folders: tuple[str, ...] = ()
    licence: str = ""
    lock: str = ""
    source_file: str = ""
    sha256: str = ""
    version: str = ""
    rule_paths: tuple[str, ...] = ()
    include: str = "all"
    exclude: tuple[str, ...] = ()
    pipelines: tuple[str, ...] = ()


@dataclass(frozen=True)
class Defense:
    """A named defense: the kinds of sensor it records with, and the rules it runs over their records."""

    id: str
    name: str
    sensors: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True)
class Listed:
    """Where a planted password appears in a published file: its line, read as `<account>:<password>`."""

    file: (
        str  # a path in the repository of Atomic Red Team, as in atomics/T1110.004/src/credstuffuserpass.txt
    )
    line: int


@dataclass(frozen=True)
class Account:
    name: str
    shell: str
    password: str | None = None
    sudo: tuple[str, ...] = ()
    listed: Listed | None = None


@dataclass(frozen=True)
class Key:
    """One entry of a host's `keys`: a key pair held by an account of the host, or a key it accepts.

    A key is named once with its type and the account that holds its private
    half (`private`); any entry may say where its public half is accepted
    (`authorized`, as account@host).
    """

    name: str
    type: str | None = None
    private: str | None = None  # the account of this host that holds the private key
    file: str | None = None
    authorized: tuple[str, str] | None = None  # (account, host)

    @property
    def file_name(self) -> str:
        return self.file or f"id_{self.type}"


@dataclass(frozen=True)
class KnownHosts:
    account: str
    hosts: tuple[str, ...]
    hashed: bool = False


@dataclass(frozen=True)
class Folder:
    path: str
    owner: str
    group: str
    mode: str


@dataclass(frozen=True)
class File:
    path: str
    owner: str
    group: str
    mode: str | None  # None for a git repository, a folder whose modes git sets
    text: str | None = None
    source: str | None = None  # a file beside the spec, or repo:<name>

    @property
    def repo(self) -> str | None:
        found = REPO.match(self.source or "")
        return found.group(1) if found else None

    @property
    def content(self) -> bytes | None:
        """The bytes of a file planted from text: the text, ended by a newline."""

        if self.text is None:
            return None
        return (self.text if self.text.endswith("\n") else self.text + "\n").encode()


@dataclass(frozen=True)
class Database:
    name: str
    user: str
    password: str
    grant_from: str
    bind_address: str
    log_error: str
    sql: str | None = None  # a file beside the spec, run in the database after it is made


@dataclass(frozen=True)
class Sshd:
    password_auth: bool
    permit_root: bool
    pam_nodelay: bool = False


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
    capture: str | None = None
    accounts: tuple[Account, ...] = ()
    keys: tuple[Key, ...] = ()
    known_hosts: tuple[KnownHosts, ...] = ()
    dirs: tuple[Folder, ...] = ()
    files: tuple[File, ...] = ()
    database: Database | None = None
    sshd: Sshd | None = None
    serve: tuple[tuple[str, str], ...] = ()  # (URL path, atomics file)
    atomics_src: tuple[str, ...] = ()

    @property
    def digest(self) -> str | None:
        found = IMAGE.match(self.image or "")
        return found.group(2) if found else None

    @property
    def built(self) -> bool:
        """True when the lab builds the host's image from the spec, rather than running a pinned image."""

        return self.image is None

    def account(self, name: str) -> Account | None:
        return next((account for account in self.accounts if account.name == name), None)

    @property
    def account_names(self) -> tuple[str, ...]:
        return SYSTEM_ACCOUNTS + tuple(account.name for account in self.accounts)


def home(account: str) -> str:
    return "/root" if account == "root" else "/home/" + account


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
    atomics: Atomics | None = None
    # The (technique, host) of each step of the path, in order. The rest of the path is read elsewhere.
    steps: tuple[tuple[str, str], ...] = ()
    # The folder that holds the spec, beside which its files, repositories and lock are.
    folder: Path | None = None
    # The ordinary activity beside the path (see `activity`), when the spec has one.
    activity: object = None
    # The public rule sets the spec pins, and the named defenses that judge a run, in the spec's order.
    rule_sets: tuple[RuleSet, ...] = ()
    defenses: tuple[Defense, ...] = ()

    @property
    def path_hosts(self) -> set[str]:
        """The hosts on which a step of the path runs."""

        return {host for _, host in self.steps}

    def key(self, name: str) -> tuple[str, Key]:
        """The host and the entry that hold the private half of a key."""

        for host in self.hosts.values():
            for key in host.keys:
                if key.name == name and key.private:
                    return host.name, key
        raise KeyError(name)

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
    return parse(read(text), text, Path(path).resolve().parent)


def parse(data: object, text: str = "", folder: Path | None = None) -> Spec:
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
    atomics = _atomics(data["atomic_red_team"]) if "atomic_red_team" in data else None

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
    _defense_hosts(hosts, wazuh, watch)
    steps = _steps(data.get("path"), hosts)
    spec = Spec(
        name, 1, prefix, min_engine, tuple(networks), hosts, text, base, wazuh, watch, atomics, steps, folder
    )
    if "activity" in data:
        # Imported here, since that module reads this one's types.
        from .activity import parse as parse_activity

        spec = replace(spec, activity=parse_activity(data["activity"], hosts, data.get("path"), watch))
    rule_sets = _rule_sets(data["rule_sets"], atomics) if "rule_sets" in data else ()
    defenses = _defenses(data["defenses"], rule_sets, wazuh) if "defenses" in data else ()
    capture_hosts = [host for host in hosts.values() if host.capture == "packets"]
    if any(PACKET_CAPTURE in defense.sensors for defense in defenses) and not capture_hosts:
        raise SpecError(
            f"a defense with sensor {PACKET_CAPTURE} needs at least one host with capture: packets"
        )
    if wazuh is None and any(PACKET_CAPTURE in defense.sensors for defense in defenses):
        raise SpecError(
            f"a defense with sensor {PACKET_CAPTURE} also needs defense.wazuh, because scoring starts "
            "from the manager's copied logs"
        )
    for host in capture_hosts:
        for network in host.networks:
            if not any(other.name != host.name and network in other.networks for other in hosts.values()):
                raise SpecError(
                    f"host {host.name}: capture packets needs a peer on network {network}, so capture_ready "
                    "can mark that interface"
                )
    unused = [found.name for found in rule_sets if not any(found.name in d.rules for d in defenses)]
    if unused:
        raise SpecError(
            f"rule_sets: no defense runs {', '.join(unused)}: name it under a defense's rules, or leave it out"
        )
    spec = replace(spec, rule_sets=rule_sets, defenses=defenses)
    _plants_across(spec)
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
        raise SpecError(
            "defense.wazuh.alert_level must be a Wazuh rule level from 1 to 16: the level from which an "
            "alert counts when a step is scored"
        )
    off = wazuh.get("off", [])
    if not isinstance(off, list) or any(item not in OFF for item in off) or len(set(off)) != len(off):
        raise SpecError(f"defense.wazuh.off may list only these agent features, once each: {', '.join(OFF)}")
    watch = _watch(defense.get("watch", {}), "defense.watch")
    return Wazuh(manager_image, version, deb["sha512"], level, tuple(off)), watch


def _defense_hosts(hosts: dict[str, Host], wazuh: Wazuh | None, watch: Watch) -> None:
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
        collected = {log.path for log in watch.merged(host.watch).logs}
        missing = [path for path in ENGINE_LOGS if path not in collected]
        if host.agent and missing:
            raise SpecError(
                f"the agent on host {host.name} does not collect {', '.join(missing)}: add each to "
                "defense.watch.logs (format syslog), since the engine's ready and end nonces and its "
                "marks are lines in auth.log and snoopy.log, and without them the range is never ready"
            )


def _host(name: str, settings: object, networks: dict, base: Base | None, wazuh: Wazuh | None) -> Host:
    if not isinstance(settings, dict):
        raise SpecError(f"host {name} must be a mapping")
    unknown = sorted(str(key) for key in settings if key not in HOST_KEYS | PLANT_KEYS)
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
    built_keys = sorted(({"agent", "watch", "packages", "services", "capture"} | PLANT_KEYS) & set(settings))
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
    capture = settings.get("capture")
    if capture not in (None, "packets"):
        raise SpecError(f"host {name}: capture must be packets when the host records its network traffic")
    if capture == "packets" and image is not None:
        raise SpecError(f"host {name}: capture needs a host built from base, not a pinned image")
    if capture == "packets" and "tcpdump" not in packages:
        raise SpecError(f"host {name}: capture packets needs the package tcpdump in packages")
    if image is None:
        ports = sorted({port for service in services for port in SERVICE_PORTS.get(service, ())})
        if sorted(listens) != ports:
            raise SpecError(
                f"host {name} lists {sorted(listens)} in listens, and its services listen on {ports}: "
                "the seal connects to every port a host lists, so the two must be the same"
            )
    host = Host(
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
        capture,
    )
    return _plants(host, settings)


def _list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise SpecError(f"{where} must be a list")
    return value


def _path(value: object, where: str) -> str:
    if not isinstance(value, str) or not WATCH_PATH.match(value) or "/../" in value + "/" or "/./" in value:
        raise SpecError(f"{where}: {value!r} must be an absolute path of letters, digits and . _ - /")
    return value.rstrip("/") or "/"


def _owner(host: Host, value: object, where: str, default: str = "root") -> str:
    value = default if value is None else value
    if value not in host.account_names:
        raise SpecError(
            f"{where}: {value!r} is not an account of host {host.name}; it has {', '.join(host.account_names)}"
        )
    return value


def _mode(value: object, where: str, default: str) -> str:
    value = default if value is None else value
    if not isinstance(value, str) or not MODE.match(value):
        raise SpecError(
            f'{where}: mode must be octal digits in quotes, as in "0640", so that YAML keeps them'
        )
    return value.rjust(4, "0")


def _flag(value: object, where: str, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise SpecError(f"{where} must be true or false")
    return value


def _at(value: object, where: str) -> tuple[str, str]:
    if not isinstance(value, str) or value.count("@") != 1:
        raise SpecError(f"{where} must be <account>@<host>, as in deploy@build")
    account, _, host = value.partition("@")
    if not ACCOUNT.match(account) or not NAME.match(host):
        raise SpecError(f"{where} must be <account>@<host>, as in deploy@build")
    return account, host


def _plants(host: Host, settings: dict) -> Host:
    """What is planted in one host, each key read with the rules that need only the host itself."""

    name = host.name
    packages = set(host.packages)
    accounts = []
    for entry in _list(settings.get("accounts", []), f"host {name}: accounts"):
        where = f"host {name}: accounts"
        entry = _mapping(entry, where, {"name", "shell", "password", "sudo", "listed"}, {"name", "shell"})
        account = entry["name"]
        if not isinstance(account, str) or not ACCOUNT.match(account) or account in SYSTEM_ACCOUNTS:
            raise SpecError(f"{where}: {account!r} must be a new account name, such as webadmin")
        where = f"host {name}: account {account}"
        shell = _path(entry["shell"], f"{where}: shell")
        password = entry.get("password")
        if password is not None and (not isinstance(password, str) or not PLAIN_VALUE.match(password)):
            raise SpecError(f"{where}: password must be letters, digits and . _ - only")
        sudo = _list(entry.get("sudo", []), f"{where}: sudo")
        for command in sudo:
            if not isinstance(command, str) or not SUDO_COMMAND.match(command):
                raise SpecError(
                    f"{where}: sudo lists {command!r}, and takes commands by full path, as in /usr/sbin/nginx -t"
                )
        if sudo and "sudo" not in packages:
            raise SpecError(f"{where} may run commands with sudo, so host {name} needs the package sudo")
        listed = None
        if "listed" in entry:
            found = _mapping(entry["listed"], f"{where}: listed", {"file", "line"}, {"file", "line"})
            source = found["file"]
            if not isinstance(source, str) or not ATOMIC_FILE.match(source):
                raise SpecError(
                    f"{where}: listed.file must be a published file, as in atomic:T1110.004/src/<file>"
                )
            if not isinstance(found["line"], int) or isinstance(found["line"], bool) or found["line"] < 1:
                raise SpecError(f"{where}: listed.line must be a line number")
            if password is None:
                raise SpecError(f"{where} is listed in a published file and has no password")
            listed = Listed("atomics/" + ATOMIC_FILE.match(source).group(1), found["line"])
        if account in {a.name for a in accounts}:
            raise SpecError(f"host {name} plants the account {account} twice")
        accounts.append(Account(account, shell, password, tuple(sudo), listed))
    host = _replace(host, accounts=tuple(accounts))

    sshd = None
    if "sshd" in settings:
        where = f"host {name}: sshd"
        entry = _mapping(
            settings["sshd"],
            where,
            {"password_auth", "permit_root", "pam_nodelay"},
            {"password_auth", "permit_root"},
        )
        if "sshd" not in host.services:
            raise SpecError(f"{where} sets the SSH server, and the host's services do not run sshd")
        sshd = Sshd(
            _flag(entry["password_auth"], f"{where}.password_auth"),
            _flag(entry["permit_root"], f"{where}.permit_root"),
            _flag(entry.get("pam_nodelay"), f"{where}.pam_nodelay", False),
        )

    keys = []
    for entry in _list(settings.get("keys", []), f"host {name}: keys"):
        where = f"host {name}: keys"
        entry = _mapping(entry, where, {"name", "type", "private", "file", "authorized"}, {"name"})
        key = entry["name"]
        if not isinstance(key, str) or not NAME.match(key):
            raise SpecError(f"{where}: name must be lower-case letters, digits and single hyphens")
        where = f"host {name}: key {key}"
        private = None
        if "private" in entry:
            account, holder = _at(entry["private"], f"{where}: private")
            if holder != name:
                raise SpecError(
                    f"{where}: private names {entry['private']}, and a key is held on the host that lists it"
                )
            private = _owner(host, account, f"{where}: private")
            if entry.get("type") not in KEY_TYPES:
                raise SpecError(f"{where}: type must be one of {', '.join(KEY_TYPES)}")
        elif "type" in entry or "file" in entry:
            raise SpecError(f"{where}: type and file belong with private, on the host that holds the key")
        file = entry.get("file")
        if file is not None and (not isinstance(file, str) or not ACCOUNT.match(file)):
            raise SpecError(f"{where}: file must be a file name in ~/.ssh, as in id_rsa")
        authorized = _at(entry["authorized"], f"{where}: authorized") if "authorized" in entry else None
        if private is None and authorized is None:
            raise SpecError(f"{where} needs private, authorized or both")
        keys.append(Key(key, entry.get("type"), private, file, authorized))

    known = []
    for entry in _list(settings.get("known_hosts", []), f"host {name}: known_hosts"):
        where = f"host {name}: known_hosts"
        entry = _mapping(entry, where, {"account", "hosts", "hashed"}, {"account", "hosts"})
        account = _owner(host, entry["account"], where)
        listed_hosts = _list(entry["hosts"], f"{where}: hosts")
        if not listed_hosts or not all(isinstance(h, str) and NAME.match(h) for h in listed_hosts):
            raise SpecError(f"{where}: hosts must list host names")
        known.append(
            KnownHosts(account, tuple(listed_hosts), _flag(entry.get("hashed"), f"{where}.hashed", False))
        )

    paths: set[str] = set()
    dirs = []
    for entry in _list(settings.get("dirs", []), f"host {name}: dirs"):
        where = f"host {name}: dirs"
        entry = _mapping(entry, where, {"path", "owner", "group", "mode"}, {"path"})
        path = _path(entry["path"], where)
        owner = _owner(host, entry.get("owner"), f"{where}: {path}")
        group = _owner(host, entry.get("group"), f"{where}: {path}: group", owner)
        if path in paths:
            raise SpecError(f"{where} plants {path} twice")
        paths.add(path)
        dirs.append(Folder(path, owner, group, _mode(entry.get("mode"), f"{where}: {path}", "0755")))

    files = []
    for entry in _list(settings.get("files", []), f"host {name}: files"):
        where = f"host {name}: files"
        entry = _mapping(entry, where, {"path", "owner", "group", "mode", "text", "from"}, {"path"})
        path = _path(entry["path"], where)
        where = f"host {name}: file {path}"
        if ("text" in entry) == ("from" in entry):
            raise SpecError(f"{where} needs either text or from")
        owner = _owner(host, entry.get("owner"), where)
        group = _owner(host, entry.get("group"), f"{where}: group", owner)
        text, source = entry.get("text"), entry.get("from")
        if text is not None and not isinstance(text, str):
            raise SpecError(f"{where}: text must be text")
        mode = _mode(entry.get("mode"), where, "0644")
        if source is not None:
            if not isinstance(source, str) or not (REPO.match(source) or RELATIVE.match(source)):
                raise SpecError(
                    f"{where}: from must be a file beside the spec, as in app/index.php, or a git repository, "
                    "as in repo:shop"
                )
            if REPO.match(source):
                if "mode" in entry:
                    raise SpecError(f"{where} is a git repository, whose modes git sets: it takes no mode")
                if "git" not in packages:
                    raise SpecError(f"{where} is a git repository, so host {name} needs the package git")
                mode = None
        if path in paths:
            raise SpecError(f"host {name} plants {path} twice")
        paths.add(path)
        files.append(File(path, owner, group, mode, text, source))

    database = None
    if "database" in settings:
        where = f"host {name}: database"
        entry = _mapping(
            settings["database"],
            where,
            {"name", "user", "password", "from", "bind_address", "log_error", "sql"},
            {"name", "user", "password", "from", "bind_address", "log_error"},
        )
        if "mariadb" not in host.services:
            raise SpecError(f"{where} needs the service mariadb")
        for key in ("name", "user"):
            if not isinstance(entry[key], str) or not DB_NAME.match(entry[key]):
                raise SpecError(f"{where}: {key} must be lower-case letters, digits and _")
        if not isinstance(entry["password"], str) or not PLAIN_VALUE.match(entry["password"]):
            raise SpecError(f"{where}: password must be letters, digits and . _ - only")
        if entry["from"] != "%":
            raise SpecError(
                f'{where}: from must be "%": the grant is for the user from any address in the range'
            )
        try:
            ipaddress.IPv4Address(entry["bind_address"])
        except (ValueError, TypeError) as error:
            raise SpecError(f"{where}: bind_address must be an IPv4 address, as in 0.0.0.0") from error
        sql = entry.get("sql")
        if sql is not None and (not isinstance(sql, str) or not RELATIVE.match(sql)):
            raise SpecError(f"{where}: sql must be a file beside the spec, as in app/shop.sql")
        database = Database(
            entry["name"],
            entry["user"],
            entry["password"],
            entry["from"],
            entry["bind_address"],
            _path(entry["log_error"], f"{where}: log_error"),
            sql,
        )

    serve = []
    if "serve" in settings:
        where = f"host {name}: serve"
        if not isinstance(settings["serve"], dict) or not settings["serve"]:
            raise SpecError(f"{where} must map a path of the server to a published file")
        if "inet-server" not in host.services:
            raise SpecError(f"{where} names files to serve, and the host does not run inet-server")
        for url, source in settings["serve"].items():
            url = _path(url, where)
            if not isinstance(source, str) or not ATOMIC_FILE.match(source):
                raise SpecError(
                    f"{where}: {url} must be served from a published file, as in atomic:T1105/src/atomic.sh"
                )
            serve.append((url, "atomics/" + ATOMIC_FILE.match(source).group(1)))

    techniques = _list(settings.get("atomics_src", []), f"host {name}: atomics_src")
    if not all(isinstance(t, str) and TECHNIQUE.match(t) for t in techniques) or len(set(techniques)) != len(
        techniques
    ):
        raise SpecError(f"host {name}: atomics_src must list technique ids once each, as in T1110.004")

    return _replace(
        host,
        keys=tuple(keys),
        known_hosts=tuple(known),
        dirs=tuple(dirs),
        files=tuple(files),
        database=database,
        sshd=sshd,
        serve=tuple(serve),
        atomics_src=tuple(techniques),
    )


def _replace(host: Host, **changes) -> Host:
    return replace(host, **changes)


def _plants_across(spec: Spec) -> None:
    """The rules of the plants that need more than one host: keys, known hosts and published files."""

    held: dict[str, tuple[str, Key]] = {}
    for host in spec.hosts.values():
        for key in host.keys:
            if key.private:
                if key.name in held:
                    raise SpecError(
                        f"key {key.name} is held twice: on {held[key.name][0]} and on {host.name}"
                    )
                held[key.name] = (host.name, key)
    for host in spec.hosts.values():
        for key in host.keys:
            where = f"host {host.name}: key {key.name}"
            if key.name not in held:
                raise SpecError(
                    f"{where}: no host holds the private half of {key.name} (private: <account>@<host>)"
                )
            if key.authorized is None:
                continue
            account, target = key.authorized
            if target not in spec.hosts:
                raise SpecError(f"{where}: authorized names host {target}, which hosts does not declare")
            other = spec.hosts[target]
            if "sshd" not in other.services:
                raise SpecError(f"{where}: authorized names {account}@{target}, and {target} runs no sshd")
            if account not in other.account_names or account == "www-data":
                raise SpecError(
                    f"{where}: authorized names {account}@{target}, and {target} has no such account"
                )
            holder = held[key.name][0]
            if not spec.shared(holder, target):
                raise SpecError(f"{where}: {holder}, which holds the key, shares no network with {target}")
        for known in host.known_hosts:
            for target in known.hosts:
                where = f"host {host.name}: known_hosts of {known.account}"
                if target not in spec.hosts or "sshd" not in spec.hosts[target].services:
                    raise SpecError(f"{where} names {target}, which runs no sshd and so has no host key")
                if not spec.shared(host.name, target):
                    raise SpecError(f"{where} names {target}, which shares no network with {host.name}")
        uses_atomics = host.atomics_src or host.serve or any(a.listed for a in host.accounts)
        if uses_atomics and spec.atomics is None:
            raise SpecError(f"host {host.name} carries published files, and the spec has no atomic_red_team")


def _atomics(value: object) -> Atomics:
    entry = _mapping(value, "atomic_red_team", {"repo", "commit", "lock"}, {"repo", "commit"})
    if not isinstance(entry["repo"], str) or not GITHUB_REPO.match(entry["repo"]):
        raise SpecError("atomic_red_team.repo must be a GitHub repository, as in redcanaryco/atomic-red-team")
    if not isinstance(entry["commit"], str) or not COMMIT.match(entry["commit"]):
        raise SpecError("atomic_red_team.commit must be a full commit id, 40 hex digits")
    lock = entry.get("lock", "")
    if lock and (not isinstance(lock, str) or not RELATIVE.match(lock)):
        raise SpecError("atomic_red_team.lock must be a file beside the spec, as in range-one.lock")
    return Atomics(entry["repo"], entry["commit"], lock)


def _rule_sets(value: object, atomics: Atomics | None) -> tuple[RuleSet, ...]:
    """The spec's `rule_sets`: each a name and where its files come from, pinned."""

    if not isinstance(value, dict) or not value:
        raise SpecError("rule_sets must name at least one rule set, as in sigma: {kind: sigma, ...}")
    repository_keys = {"kind", "repo", "commit", "folders", "licence", "lock"}
    selection_keys = {"rule_paths", "include", "exclude", "pipelines"}
    manifest_keys = {"kind", "source", "sha256", "version"}
    found = []
    for name, settings in value.items():
        if not isinstance(name, str) or not NAME.match(name) or len(name) > 64:
            raise SpecError(
                f"rule_sets: the name {name!r} must be lower-case letters, digits and single hyphens, "
                "from 1 to 64 characters"
            )
        if name in LIVE_RULES:
            raise SpecError(
                f"rule_sets: {name} is the name of the rules the Wazuh manager runs live, so a rule set "
                "that is fetched needs another name"
            )
        if name in RESERVED_DETECTORS:
            raise SpecError(
                f"rule_sets: a recording names a detector of its own {name}, so a rule set needs another name"
            )
        where = f"rule_sets: {name}"
        if not isinstance(settings, dict):
            raise SpecError(f"{where} must be a mapping")
        local = "source" in settings or "sha256" in settings or "version" in settings
        allowed = manifest_keys if local else repository_keys | selection_keys
        required = manifest_keys if local else repository_keys
        entry = _mapping(settings, where, allowed, required)
        if entry["kind"] not in RULE_KINDS:
            raise SpecError(
                f"{where}: kind must be one of {', '.join(RULE_KINDS)}: the kinds of rule set the lab can "
                "give a recorded run to"
            )
        if local:
            source = entry["source"]
            if (
                not isinstance(source, str)
                or not RELATIVE.match(source)
                or PurePosixPath(source).name != "SHA256SUMS"
            ):
                raise SpecError(
                    f"{where}: source must be a SHA256SUMS manifest inside the repository, relative to its root"
                )
            digest_value = entry["sha256"]
            if isinstance(digest_value, str):
                digest = digest_value
            elif (
                isinstance(digest_value, list)
                and len(digest_value) == 8
                and all(isinstance(part, str) and re.fullmatch(r"[0-9a-f]{8}", part) for part in digest_value)
            ):
                digest = "".join(digest_value)
            else:
                raise SpecError(
                    f"{where}: sha256 must be 64 lower-case hex digits, as one string or eight 8-digit chunks"
                )
            if not SHA256.match(digest):
                raise SpecError(
                    f"{where}: sha256 must be 64 lower-case hex digits, as one string or eight 8-digit chunks"
                )
            version = entry["version"]
            if (
                not isinstance(version, str)
                or not version.strip()
                or version != version.strip()
                or "\n" in version
                or len(version) > 100
            ):
                raise SpecError(f"{where}: version must be one short line")
            found.append(RuleSet(name, entry["kind"], source_file=source, sha256=digest, version=version))
            continue
        if not isinstance(entry["repo"], str) or not GITHUB_REPO.match(entry["repo"]):
            raise SpecError(f"{where}: repo must be a GitHub repository, as in SigmaHQ/sigma")
        if not isinstance(entry["commit"], str) or not COMMIT.match(entry["commit"]):
            raise SpecError(f"{where}: commit must be a full commit id, 40 hex digits")
        folders = entry["folders"]
        if (
            not isinstance(folders, list)
            or not folders
            or not all(isinstance(folder, str) and RELATIVE.match(folder) for folder in folders)
            or any(
                one == other or one.startswith(other + "/")
                for number, one in enumerate(folders)
                for place, other in enumerate(folders)
                if number != place
            )
        ):
            raise SpecError(
                f"{where}: folders must list folders of the repository, as in rules/linux/process_creation, "
                "once each and none inside another"
            )
        rule_paths = entry.get("rule_paths", [])
        if (
            not isinstance(rule_paths, list)
            or not all(
                isinstance(path, str)
                and RELATIVE.match(path.replace("*", "x"))
                and all("*" not in part or part == "*" for part in path.split("/"))
                for path in rule_paths
            )
            or len(set(rule_paths)) != len(rule_paths)
        ):
            raise SpecError(
                f"{where}: rule_paths must list relative source folders once each; a whole path part may be *"
            )
        outside_paths = sorted(
            path
            for path in rule_paths
            if not any(path == folder or path.startswith(folder + "/") for folder in folders)
        )
        if outside_paths:
            raise SpecError(
                f"{where}: rule_paths names {', '.join(outside_paths[:5])}, outside the configured folders"
            )
        include = entry.get("include", "all")
        if include not in ("all", "rules"):
            raise SpecError(f"{where}: include must be all or rules")
        exclude = entry.get("exclude", [])
        if (
            not isinstance(exclude, list)
            or not all(isinstance(path, str) and RELATIVE.match(path) for path in exclude)
            or len(set(exclude)) != len(exclude)
        ):
            raise SpecError(
                f"{where}: exclude must list repository file paths once each, with no absolute or parent path"
            )
        outside = sorted(
            path for path in exclude if not any(path.startswith(folder + "/") for folder in folders)
        )
        if outside:
            raise SpecError(
                f"{where}: exclude names {', '.join(outside[:5])}, outside the folders the rule set takes"
            )
        pipelines = entry.get("pipelines", [])
        if (
            not isinstance(pipelines, list)
            or not all(isinstance(path, str) and RELATIVE.match(path) for path in pipelines)
            or len(set(pipelines)) != len(pipelines)
        ):
            raise SpecError(
                f"{where}: pipelines must list repository file paths once each, with no absolute or parent path"
            )
        if pipelines and entry["kind"] != "sigma":
            raise SpecError(f"{where}: pipelines is only for sigma rule sets")
        outside_pipelines = sorted(
            path for path in pipelines if not any(path.startswith(folder + "/") for folder in folders)
        )
        if outside_pipelines:
            raise SpecError(
                f"{where}: pipelines names {', '.join(outside_pipelines[:5])}, outside the folders the rule set takes"
            )
        excluded_pipelines = sorted(set(pipelines) & set(exclude))
        if excluded_pipelines:
            raise SpecError(
                f"{where}: pipelines names {', '.join(excluded_pipelines[:5])}, which exclude also names"
            )
        licence = entry["licence"]
        if not isinstance(licence, str) or not RELATIVE.match(licence):
            raise SpecError(
                f"{where}: licence must be the licence file of the repository, as in LICENSE: it is "
                "fetched and kept with the rules"
            )
        if any(licence == folder or licence.startswith(folder + "/") for folder in folders):
            raise SpecError(f"{where}: licence names {licence}, which is inside one of the rule folders")
        lock = entry["lock"]
        if not isinstance(lock, str) or not RELATIVE.match(lock):
            raise SpecError(f"{where}: lock must be a file beside the spec, as in range-one.rules.lock")
        if atomics is not None and lock == atomics.lock:
            raise SpecError(
                f"{where}: lock names {lock}, the lock of atomic_red_team's files: the rule sets need a "
                "lock file of their own"
            )
        found.append(
            RuleSet(
                name,
                entry["kind"],
                entry["repo"],
                entry["commit"],
                tuple(folders),
                licence,
                lock,
                rule_paths=tuple(rule_paths),
                include=include,
                exclude=tuple(exclude),
                pipelines=tuple(pipelines),
            )
        )
    return tuple(found)


def _defenses(value: object, rule_sets: tuple[RuleSet, ...], wazuh: Wazuh | None) -> tuple[Defense, ...]:
    """The spec's `defenses`: each an id, a name, the kinds of sensor it records with and the rules it runs."""

    if not isinstance(value, list) or not 1 <= len(value) <= MAX_DEFENSES:
        raise SpecError(
            f"defenses must be a list of 1 to {MAX_DEFENSES} defenses, each with id, name, sensors and rules"
        )
    kinds = {found.name: found.kind for found in rule_sets}
    keys = {"id", "name", "sensors", "rules"}
    found: list[Defense] = []
    for entry in value:
        entry = _mapping(entry, "defenses", keys, keys)
        identifier = entry["id"]
        if not isinstance(identifier, str) or not DEFENSE_ID.match(identifier):
            raise SpecError(
                f"defenses: the id {identifier!r} must be 1 to 64 letters, digits, hyphens and underscores"
            )
        where = f"defenses: {identifier}"
        if identifier in {defense.id for defense in found}:
            raise SpecError(f"defenses lists the id {identifier} twice")
        name = entry["name"]
        if (
            not isinstance(name, str)
            or not name.strip()
            or FORBIDDEN_TEXT.search(name)
            or len(name) > MAX_NAME
        ):
            raise SpecError(f"{where}: name must say in a few plain words what the defense is, on one line")
        sensors = entry["sensors"]
        if (
            not isinstance(sensors, list)
            or not sensors
            or any(sensor not in SENSORS for sensor in sensors)
            or len(set(sensors)) != len(sensors)
        ):
            raise SpecError(
                f"{where}: sensors must list at least one kind of sensor, once each, of: {', '.join(SENSORS)}"
            )
        if WAZUH_AGENT in sensors and wazuh is None:
            raise SpecError(
                f"{where}: the sensor {WAZUH_AGENT} is the agent of {SENSORS[WAZUH_AGENT]}, and the spec has none"
            )
        rules = entry["rules"]
        if (
            not isinstance(rules, list)
            or len(rules) > MAX_RULES
            or not all(isinstance(rule, str) for rule in rules)
            or len(set(rules)) != len(rules)
        ):
            raise SpecError(f"{where}: rules must list at most {MAX_RULES} rule sets by name, once each")
        for rule in rules:
            if rule not in LIVE_RULES and rule not in kinds:
                raise SpecError(
                    f"{where}: rules names {rule!r}, which is neither {WAZUH_RULES} (the rules the Wazuh "
                    f"manager runs live) nor a rule set of rule_sets ({', '.join(kinds) or 'the spec has none'})"
                )
            reads = LIVE_RULES[rule] if rule in LIVE_RULES else RULE_KINDS[kinds[rule]]
            if not set(reads) & set(sensors):
                raise SpecError(
                    f"{where}: the rules {rule} read what the sensor {' or '.join(reads)} records, and the "
                    "defense does not list it under sensors"
                )
        found.append(Defense(identifier, name.strip(), tuple(sensors), tuple(rules)))
    named = {rule for defense in found for rule in defense.rules}
    if len(named) > MAX_DEFENSES:
        raise SpecError(
            f"defenses name {len(named)} different rule sets, and a recording holds at most {MAX_DEFENSES}"
        )
    return tuple(found)


def _steps(path: object, hosts: dict[str, Host]) -> tuple[tuple[str, str], ...]:
    """The technique and host of each step of the path. The path's own rules are read elsewhere."""

    if path is None:
        return ()
    steps = path.get("steps") if isinstance(path, dict) else None
    if not isinstance(steps, list):
        raise SpecError("path must have steps, a list")
    found = []
    for number, step in enumerate(steps, start=1):
        if not isinstance(step, dict) or not isinstance(step.get("technique"), str):
            raise SpecError(f"step {number} of the path has no technique")
        if not TECHNIQUE.match(step["technique"]):
            raise SpecError(f"step {number} of the path: {step['technique']!r} is not a technique id")
        if step.get("host") is not None and step.get("host") not in hosts:
            raise SpecError(
                f"step {step.get('id', number)} of the path runs on {step.get('host')}, which hosts does not declare"
            )
        found.append((step["technique"], step.get("host")))
    return tuple(found)


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

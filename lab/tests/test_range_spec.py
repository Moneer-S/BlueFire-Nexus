from pathlib import Path

import pytest
import yaml

from bluefire_lab.range import spec as range_spec

SEAL_CHECK = Path(__file__).parents[1] / "range" / "seal-check.yaml"
IMAGE = "nginx:1.28.0-bookworm@sha256:" + "5" * 64


def a_spec(**changes) -> dict:
    document = {
        "range": "two-nets",
        "version": 1,
        "prefix": "bluefire-lab-tn",
        "docker": {"min_engine": 28},
        "networks": {"west": {}, "east": {}},
        "hosts": {
            "left": {
                "kind": "host",
                "role": "on west",
                "networks": ["west"],
                "listens": [80],
                "image": IMAGE,
            },
            "middle": {
                "kind": "host",
                "role": "on both",
                "networks": ["west", "east"],
                "listens": [80],
                "image": IMAGE,
            },
            "right": {
                "kind": "host",
                "role": "on east",
                "networks": ["east"],
                "listens": [22],
                "image": IMAGE,
            },
        },
    }
    document.update(changes)
    return document


def with_host(name: str, **settings) -> dict:
    document = a_spec()
    document["hosts"][name] = {**document["hosts"].get(name, {}), **settings}
    return document


def test_the_seal_check_spec_loads_with_pairs_that_must_connect_and_a_pair_that_must_not() -> None:
    spec = range_spec.load(SEAL_CHECK)

    assert spec.prefix == "bluefire-lab-sc"
    assert spec.container_name("left") == "bluefire-lab-sc-left"
    assert spec.network_name("west") == "bluefire-lab-sc-west"
    assert all(host.digest == spec.hosts["left"].digest for host in spec.hosts.values())
    musts = {(probe.source, probe.target, probe.must) for probe in range_spec.matrix(spec)}
    assert ("left", "middle", "connect") in musts
    assert ("left", "right", "fail") in musts
    assert ("right", "left", "fail") in musts


def test_the_matrix_tries_every_listening_port_on_every_shared_network_and_one_port_on_every_other_address() -> (
    None
):
    probes = range_spec.matrix(range_spec.parse(a_spec()))

    assert [(p.source, p.target, p.network, p.port, p.must) for p in probes] == [
        ("left", "middle", "west", 80, "connect"),
        ("left", "right", "east", 22, "fail"),
        ("middle", "left", "west", 80, "connect"),
        ("middle", "right", "east", 22, "connect"),
        ("right", "left", "west", 80, "fail"),
        ("right", "middle", "east", 80, "connect"),
    ]


def test_a_target_that_listens_on_nothing_is_probed_on_port_22_where_it_must_fail() -> None:
    document = a_spec()
    document["hosts"]["far"] = {"kind": "host", "role": "far", "networks": ["east"], "image": IMAGE}

    probes = range_spec.matrix(range_spec.parse(document))

    assert ("left", "far", "east", 22, "fail") in [
        (p.source, p.target, p.network, p.port, p.must) for p in probes
    ]
    assert not [p for p in probes if p.target == "far" and p.must == "connect"]


def test_a_spec_with_the_sections_that_later_parts_read_is_not_refused() -> None:
    document = a_spec(
        sentence="a sentence",
        atomic_red_team={"repo": "redcanaryco/atomic-red-team", "commit": "a0e3f9bc"},
        executor={"reference": "redcanaryco/invoke-atomicredteam", "commit": "8af478bb"},
        base={"image": IMAGE, "apt_snapshot": "20261120T000000Z"},
        activity={"seed": 1, "jobs": []},
        path={"steps": []},
    )
    document["hosts"]["middle"].pop("image")
    document["hosts"]["middle"].update(
        accounts=[{"name": "ops"}],
        keys=[],
        known_hosts=[],
        dirs=[],
        files=[],
        database={},
        sshd={},
        serve={},
        atomics_src=[],
    )

    spec = range_spec.parse(document)

    assert spec.hosts["middle"].image is None
    assert spec.hosts["middle"].built


WAZUH_CHECK = Path(__file__).parents[1] / "range" / "wazuh-check.yaml"


def wazuh_check(change=None) -> dict:
    document = range_spec.read(WAZUH_CHECK.read_text())
    if change:
        change(document)
    return document


def test_the_wazuh_check_spec_has_a_manager_and_one_agent_host_that_shares_its_network() -> None:
    spec = range_spec.load(WAZUH_CHECK)

    assert spec.prefix == "bluefire-lab-wz"
    assert spec.manager == "manager"
    assert spec.agents == ["web"]
    assert spec.wazuh.version == "4.14.10"
    # The bare word off is a key, not the boolean YAML 1.1 would read.
    assert spec.wazuh.off == ("command_monitoring", "sca", "rootcheck", "syscollector")
    assert [log.path for log in spec.watch_for("web").logs] == [
        "/var/log/auth.log",
        "/var/log/snoopy.log",
        "/var/log/dpkg.log",
    ]
    assert ("web", "manager", "connect") in {(p.source, p.target, p.must) for p in range_spec.matrix(spec)}


def test_only_hosts_built_from_base_get_an_agent_unless_they_say_otherwise() -> None:
    def add(document: dict) -> None:
        document["hosts"]["db"] = {**document["hosts"]["web"], "role": "no agent", "agent": False}
        document["hosts"]["bare"] = {"kind": "host", "role": "pinned", "networks": ["mgmt"], "image": IMAGE}

    spec = range_spec.parse(wazuh_check(add))

    assert spec.agents == ["web"]
    assert not spec.hosts["bare"].built


def drop(*path: str):
    def change(document: dict) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return change


def put(value, *path: str):
    def change(document: dict) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (drop("base"), "host web has no image, so the lab builds it from base, and the spec has no base"),
        (put("ubuntu:noble", "base", "image"), "base.image must be pinned by digest"),
        (put(20261120, "base", "apt_snapshot"), "base.apt_snapshot must be a moment of the Ubuntu snapshot"),
        (put("x", "base", "mirror"), "base has unknown keys: mirror"),
        (drop("defense", "wazuh", "agent_deb"), "defense.wazuh lacks: agent_deb"),
        (
            put("wazuh/wazuh-manager:4.14.10", "defense", "wazuh", "manager_image"),
            "defense.wazuh.manager_image must be pinned by digest",
        ),
        (
            put("4.14.9-1", "defense", "wazuh", "agent_deb", "version"),
            "the agent package 4.14.9-1 and the manager",
        ),
        (
            put("abc", "defense", "wazuh", "agent_deb", "sha512"),
            "agent_deb.sha512 must be the package's SHA-512",
        ),
        (put(20, "defense", "wazuh", "alert_level"), "alert_level must be a Wazuh rule level from 1 to 16"),
        (
            put(["vulnerability"], "defense", "wazuh", "off"),
            "defense.wazuh.off may list only these agent features",
        ),
        (
            put([{"path": "var/log/auth.log", "format": "syslog"}], "defense", "watch", "logs"),
            "must be an absolute path without spaces or commas",
        ),
        (
            put([{"path": "/var/log/x.log", "format": "eventchannel"}], "defense", "watch", "logs"),
            "the format of /var/log/x.log must be one of syslog",
        ),
        (
            put(False, "hosts", "web", "agent"),
            "a spec with defense.wazuh needs at least one host built from base with an agent",
        ),
        (
            put(["/etc,/home"], "defense", "watch", "fim_realtime"),
            "must be an absolute path without spaces or commas",
        ),
        (
            put(["/tmp", "/tmp"], "defense", "watch", "fim_realtime"),
            "defense.watch.fim_realtime lists a folder twice",
        ),
        (
            put([{"path": "/var/log/snoopy.log", "format": "syslog"}], "defense", "watch", "logs"),
            "the agent on host web does not collect /var/log/auth.log: add each to defense.watch.logs",
        ),
        (
            put([], "defense", "watch", "logs"),
            "does not collect /var/log/auth.log, /var/log/snoopy.log",
        ),
        (put([1514], "hosts", "manager", "listens"), "must list 1514 and 1515 in listens"),
        (put(IMAGE, "hosts", "manager", "image"), "host manager runs the Wazuh manager"),
        (
            put(["nginx"], "hosts", "web", "services"),
            "the lab cannot start service 'nginx' yet; it can start sshd",
        ),
        (put([], "hosts", "web", "packages"), "service sshd needs the package openssh-server in packages"),
        (
            put(["Not A Package"], "hosts", "web", "packages"),
            "packages must be a list of Ubuntu package names",
        ),
        (put("yes", "hosts", "web", "agent"), "host web: agent must be true or false"),
        (put(IMAGE, "hosts", "web", "image"), "host web runs the pinned image unchanged, so it cannot have"),
        (drop("defense"), "host manager is of kind defense, and the spec has no defense.wazuh"),
    ],
)
def test_the_loader_refuses_a_defense_or_a_built_host_with_the_reason(change, message: str) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        range_spec.parse(wazuh_check(change))

    assert message in str(refused.value)


def test_an_agent_on_a_network_without_the_manager_is_refused() -> None:
    def apart(document: dict) -> None:
        document["networks"]["inside"] = {}
        document["hosts"]["db"] = {**document["hosts"]["web"], "role": "apart", "networks": ["inside"]}
        document["hosts"]["db2"] = {**document["hosts"]["web"], "role": "beside db", "networks": ["inside"]}

    with pytest.raises(
        range_spec.SpecError, match="host db has an agent and shares no network with the manager"
    ):
        range_spec.parse(wazuh_check(apart))


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (a_spec(colour="blue"), "unknown key at the top of the spec: colour"),
        ({k: v for k, v in a_spec().items() if k != "networks"}, "the spec lacks: networks"),
        (a_spec(version=2), "version must be 1"),
        (a_spec(prefix="range-tn"), "prefix must start with bluefire-lab-"),
        (a_spec(docker={"min_engine": 27}), "docker.min_engine must be 28 or later"),
        (a_spec(docker={"min_engine": 28, "rootless": True}), "docker must be {min_engine"),
        (
            a_spec(networks={"west": {"internal": False}, "east": {}}),
            "network west has settings, and networks take none",
        ),
        (a_spec(networks={"west": {}, "east": {}, "north": {}}), "network north has no host"),
        (
            with_host("left", networks=["south"]),
            "host left joins network south, which networks does not declare",
        ),
        (with_host("left", networks=["west", "west"]), "host left lists a network twice"),
        (with_host("left", networks=[["west"]]), "host left: networks must list network names"),
        (with_host("left", networks=[{"west": 1}]), "host left: networks must list network names"),
        (with_host("left", image="nginx:1.28.0-bookworm"), "host left: image must be pinned by digest"),
        (with_host("left", privileged=True), "host left has unknown keys: privileged"),
        (
            with_host("left", kind="router"),
            "host left: kind must be one of attacker, internet, host, defense",
        ),
        (with_host("left", role=""), "host left: role must say in words what the host is"),
        (with_host("left", listens=["80"]), "host left: listens must be a list of TCP ports"),
        (with_host("left", listens=[70000]), "host left: listens must be a list of TCP ports"),
        (with_host("middle", listens=[]), "host left shares a network with no host that listens"),
    ],
)
def test_the_loader_refuses_with_the_reason(document: dict, message: str) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        range_spec.parse(document)

    assert message in str(refused.value)


def test_a_file_that_is_not_yaml_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("hosts: [unclosed\n")

    with pytest.raises(range_spec.SpecError, match="not valid YAML"):
        range_spec.load(broken)


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    latin = tmp_path / "latin.yaml"
    latin.write_bytes("range: caf\xe9\n".encode("latin-1"))

    with pytest.raises(range_spec.SpecError, match="must be UTF-8 text"):
        range_spec.load(latin)


def test_the_spec_text_travels_with_it_for_the_manifest(tmp_path: Path) -> None:
    path = tmp_path / "range.yaml"
    path.write_text(yaml.safe_dump(a_spec()))

    spec = range_spec.load(path)

    assert spec.text == path.read_text()
    assert len(spec.sha256) == 64

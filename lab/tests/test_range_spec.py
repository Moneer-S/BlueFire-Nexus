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
        defense={"wazuh": {"alert_level": 12}},
        activity={"seed": 1, "jobs": []},
        path={"steps": []},
    )
    document["hosts"]["middle"].pop("image")
    document["hosts"]["middle"].update(
        packages=["nginx"],
        services=["nginx"],
        accounts=[{"name": "ops"}],
        keys=[],
        known_hosts=[],
        dirs=[],
        files=[],
        database={},
        sshd={},
        serve={},
        atomics_src=[],
        agent=False,
        watch={},
    )

    spec = range_spec.parse(document)

    assert spec.hosts["middle"].image is None


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

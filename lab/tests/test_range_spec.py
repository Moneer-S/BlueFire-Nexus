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
        executor={"reference": "redcanaryco/invoke-atomicredteam", "commit": "8af478bb"},
        path={"steps": [], "goal": {"plain": "a goal"}},
    )

    spec = range_spec.parse(document)

    assert sorted(spec.hosts) == ["left", "middle", "right"]
    assert spec.steps == ()


SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"


def small(change=None) -> dict:
    document = range_spec.read(SMALL.read_text())
    if change:
        change(document)
    return document


def test_the_small_spec_has_a_manager_and_two_agent_hosts_that_share_its_network() -> None:
    spec = range_spec.load(SMALL)

    assert spec.prefix == "bluefire-lab-sm"
    assert spec.manager == "manager"
    assert spec.agents == ["web", "db"]
    assert spec.wazuh.version == "4.14.10"
    # The bare word off is a key, not the boolean YAML 1.1 would read.
    assert spec.wazuh.off == ("command_monitoring", "sca", "rootcheck", "syscollector")
    assert [log.path for log in spec.watch_for("web").logs] == [
        "/var/log/auth.log",
        "/var/log/snoopy.log",
        "/var/log/dpkg.log",
    ]
    assert ("web", "manager", "connect") in {(p.source, p.target, p.must) for p in range_spec.matrix(spec)}


def test_the_plants_of_the_small_spec_are_read_as_written() -> None:
    web = range_spec.load(SMALL).hosts["web"]

    assert web.account("admin").password == "admin"  # pragma: allowlist secret
    assert web.account("admin").sudo == ("/usr/bin/id",)
    assert web.account("admin").listed.file == "atomics/T1110.004/src/credstuffuserpass.txt"
    assert web.account("app").password is None
    key = web.keys[0]
    assert (key.name, key.type, key.private, key.file_name, key.authorized) == (
        "deploy",
        "rsa",
        "admin",
        "id_rsa",
        ("app", "web"),
    )
    assert [(d.path, d.owner, d.group, d.mode) for d in web.dirs] == [("/srv/drop", "app", "app", "0750")]
    assert [(f.path, f.owner, f.group, f.mode) for f in web.files] == [
        ("/etc/app/secret.env", "root", "app", "0640"),
        ("/srv/app/page.txt", "root", "root", "0644"),
    ]
    assert web.sshd == range_spec.Sshd(password_auth=True, permit_root=False, pam_nodelay=True)


def test_only_hosts_built_from_base_get_an_agent_unless_they_say_otherwise() -> None:
    def add(document: dict) -> None:
        document["hosts"]["db2"] = {**document["hosts"]["db"], "role": "no agent", "agent": False}
        document["hosts"]["bare"] = {"kind": "host", "role": "pinned", "networks": ["mgmt"], "image": IMAGE}

    spec = range_spec.parse(small(add))

    assert spec.agents == ["web", "db"]
    assert not spec.hosts["bare"].built


def test_range_one_loads_with_seven_hosts_on_three_networks() -> None:
    spec = range_spec.load(RANGE_ONE)

    assert list(spec.hosts) == ["attacker", "inet", "client", "web", "db", "build", "manager"]
    assert spec.networks == ("edge", "inside", "mgmt")
    assert spec.agents == ["web", "db", "build"]
    assert spec.path_hosts == {"attacker", "web"}
    assert spec.atomics.commit == "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"  # pragma: allowlist secret
    assert spec.hosts["web"].capture == "packets"
    assert "tcpdump" in spec.hosts["web"].packages


def test_the_matrix_of_range_one_connects_every_pair_that_shares_a_network_and_fails_every_other() -> None:
    probes = range_spec.matrix(range_spec.load(RANGE_ONE))
    connect: dict[tuple[str, str], set[tuple[str, int]]] = {}
    fail: dict[tuple[str, str], set[tuple[str, int]]] = {}
    for probe in probes:
        found = connect if probe.must == "connect" else fail
        found.setdefault((probe.source, probe.target), set()).add((probe.network, probe.port))

    outside, inside = {"attacker", "inet", "client"}, {"build", "db", "manager"}
    assert set(fail) == {(a, b) for a in outside for b in inside} | {(b, a) for a in outside for b in inside}
    # A pair that shares no network is tried on the target's first port, at each of its addresses.
    assert fail[("attacker", "db")] == {("inside", 3306), ("mgmt", 3306)}
    assert fail[("db", "attacker")] == {("edge", 22)}
    assert fail[("client", "manager")] == {("mgmt", 1514)}
    # A pair that shares networks is tried on every port the target listens on, on each shared network.
    assert connect[("attacker", "web")] == {("edge", 22), ("edge", 80)}
    assert connect[("client", "inet")] == {("edge", 80), ("edge", 443)}
    assert connect[("web", "db")] == {("inside", 3306), ("mgmt", 3306)}
    assert connect[("web", "build")] == {("inside", 22), ("mgmt", 22)}
    assert connect[("db", "manager")] == {("mgmt", 1514), ("mgmt", 1515)}
    assert connect[("manager", "web")] == {("mgmt", 22), ("mgmt", 80)}
    assert connect[("web", "inet")] == {("edge", 80), ("edge", 443)}
    # Nothing connects to a host that listens on nothing.
    assert not [pair for pair in connect if pair[1] in ("attacker", "client")]
    assert len(probes) == sum(len(v) for v in connect.values()) + sum(len(v) for v in fail.values())


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
            lambda d: [d["hosts"][h].update(agent=False) for h in ("web", "db")],
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
            put(["telnetd"], "hosts", "web", "services"),
            "the lab cannot start service 'telnetd' yet; it can start sshd, nginx, php-fpm, mariadb, cron, inet-server",
        ),
        (put([], "hosts", "web", "packages"), "service sshd needs the package openssh-server in packages"),
        (
            put(["Not A Package"], "hosts", "web", "packages"),
            "packages must be a list of Ubuntu package names",
        ),
        (
            put("traffic", "hosts", "web", "capture"),
            "host web: capture must be packets when the host records its network traffic",
        ),
        (
            put("packets", "hosts", "web", "capture"),
            "host web: capture packets needs the package tcpdump in packages",
        ),
        (put("yes", "hosts", "web", "agent"), "host web: agent must be true or false"),
        (put(IMAGE, "hosts", "web", "image"), "host web runs the pinned image unchanged, so it cannot have"),
        (drop("defense"), "host manager is of kind defense, and the spec has no defense.wazuh"),
    ],
)
def test_the_loader_refuses_a_defense_or_a_built_host_with_the_reason(change, message: str) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        range_spec.parse(small(change))

    assert message in str(refused.value)


def test_an_agent_on_a_network_without_the_manager_is_refused() -> None:
    def apart(document: dict) -> None:
        document["networks"]["inside"] = {}
        document["hosts"]["far"] = {**document["hosts"]["db"], "role": "apart", "networks": ["inside"]}
        document["hosts"]["far2"] = {**document["hosts"]["db"], "role": "beside far", "networks": ["inside"]}

    with pytest.raises(
        range_spec.SpecError, match="host far has an agent and shares no network with the manager"
    ):
        range_spec.parse(small(apart))


def change_web(key: str, value):
    """A change to one key of the small spec's web host."""

    return put(value, "hosts", "web", key)


def change_entry(key: str, index: int, **values):
    def change(document: dict) -> None:
        document["hosts"]["web"][key][index].update(values)

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        # accounts
        (change_entry("accounts", 1, name="root"), "host web: accounts: 'root' must be a new account name"),
        (
            change_entry("accounts", 0, password="two words"),  # pragma: allowlist secret
            "account admin: password must be letters, digits",
        ),
        (change_entry("accounts", 0, sudo=["id"]), "sudo lists 'id', and takes commands by full path"),
        (
            change_web("packages", ["openssh-server", "openssh-client", "php-mysql"]),
            "host web: account admin may run commands with sudo, so host web needs the package sudo",
        ),
        (
            change_entry("accounts", 1, listed={"file": "atomic:T1110.004/src/x.txt", "line": 1}),
            "account app is listed in a published file and has no password",
        ),  # fmt: skip
        (
            change_entry("accounts", 0, listed={"file": "/etc/passwd", "line": 1}),
            "listed.file must be a published file",
        ),
        # keys
        (change_entry("keys", 0, type="dsa"), "host web: key deploy: type must be one of rsa, ed25519"),
        (change_entry("keys", 0, private="admin@db"), "a key is held on the host that lists it"),
        (change_entry("keys", 0, authorized="app@inet"), "authorized names app@inet, and inet runs no sshd"),
        (
            change_entry("keys", 0, authorized="nobody@web"),
            "authorized names nobody@web, and web has no such account",
        ),
        (change_entry("keys", 0, authorized="app at web"), "authorized must be <account>@<host>"),
        (
            lambda d: d["hosts"]["db"].update(keys=[{"name": "lost", "authorized": "app@web"}]),
            "host db: key lost: no host holds the private half of lost",
        ),
        # known_hosts
        (change_entry("known_hosts", 0, hosts=["db"]), "known_hosts of admin names db, which runs no sshd"),
        (change_entry("known_hosts", 0, account="nobody"), "'nobody' is not an account of host web"),
        # dirs
        (change_entry("dirs", 0, mode=750), 'mode must be octal digits in quotes, as in "0640"'),
        (change_entry("dirs", 0, path="srv/drop"), "must be an absolute path of letters"),
        (change_entry("dirs", 0, path="/srv/../etc"), "must be an absolute path of letters"),
        (change_entry("dirs", 0, owner="nobody"), "'nobody' is not an account of host web"),
        # files
        (
            change_entry("files", 0, **{"from": "page.txt"}),
            "file /etc/app/secret.env needs either text or from",
        ),
        (change_entry("files", 1, **{"from": "../page.txt"}), "from must be a file beside the spec"),
        (
            change_entry("files", 1, **{"from": "repo:site"}),
            "is a git repository, so host web needs the package git",
        ),
        (change_entry("files", 1, path="/srv/drop"), "host web plants /srv/drop twice"),
        # database
        (
            lambda d: d["hosts"]["web"].update(database=d["hosts"]["db"]["database"]),
            "host web: database needs the service mariadb",
        ),
        (lambda d: d["hosts"]["db"]["database"].update({"from": "web"}), 'from must be "%"'),
        (
            lambda d: d["hosts"]["db"]["database"].update(password="it's"),
            "database: password must be letters",
        ),
        (
            lambda d: d["hosts"]["db"]["database"].update(bind_address="any"),
            "bind_address must be an IPv4 address",
        ),
        (lambda d: d["hosts"]["db"]["database"].pop("log_error"), "host db: database lacks: log_error"),
        # sshd
        (
            lambda d: d["hosts"]["db"].update(sshd={"password_auth": False, "permit_root": False}),
            "host db: sshd sets the SSH server, and the host's services do not run sshd",
        ),
        (
            change_web("sshd", {"password_auth": "yes", "permit_root": False}),  # pragma: allowlist secret
            "sshd.password_auth must be true or false",
        ),
        # serve
        (change_web("serve", {"/x": "atomic:T1105/src/atomic.sh"}), "the host does not run inet-server"),
        (
            lambda d: d["hosts"]["inet"].update(serve={"/x": "https://example.com/x"}),
            "/x must be served from a published file",
        ),
        # atomics_src
        (change_web("atomics_src", ["1110"]), "atomics_src must list technique ids once each"),
        (drop("atomic_red_team"), "host web carries published files, and the spec has no atomic_red_team"),
        (put("a0e3f9bc", "atomic_red_team", "commit"), "atomic_red_team.commit must be a full commit id"),
        # what a host lists against what its services listen on
        (
            change_web("listens", [22, 80]),
            "host web lists [22, 80] in listens, and its services listen on [22]",
        ),
        (change_web("shell", "/bin/sh"), "host web has unknown keys: shell"),
    ],
)
def test_the_loader_refuses_a_plant_with_the_reason(change, message: str) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        range_spec.parse(small(change), folder=SMALL.parent)

    assert message in str(refused.value)


def defended(change=None) -> dict:
    """The small spec with a public rule set and two named defenses, as range one's spec names its own."""

    document = small()
    document["rule_sets"] = {
        "made-up": {
            "kind": "sigma",
            "repo": "example/rules",
            "commit": "b" * 40,
            "folders": ["rules/linux/process_creation", "rules/web"],
            "licence": "LICENSE",
            "lock": "made-up.lock",
        }
    }
    document["defenses"] = [
        {
            "id": "wazuh-stock",
            "name": "Wazuh with its stock rules",
            "sensors": ["wazuh-agent"],
            "rules": ["wazuh"],
        },
        {
            "id": "made_up",
            "name": "Rules made up for the tests",
            "sensors": ["wazuh-agent"],
            "rules": ["made-up"],
        },
    ]
    if change:
        change(document)
    return document


def manifest_defended(change=None) -> dict:
    """The small spec with a tracked Suricata manifest and the packet capture it reads."""

    document = small()
    document["rule_sets"] = {
        "published": {
            "kind": "suricata",
            "source": "lab/rules/published/SHA256SUMS",
            "sha256": "a" * 64,
            "version": "7",
        }
    }
    document["defenses"] = [
        {
            "id": "packets",
            "name": "Packets with published rules",
            "sensors": ["packet-capture"],
            "rules": ["published"],
        }
    ]
    document["hosts"]["web"]["packages"].append("tcpdump")
    document["hosts"]["web"]["capture"] = "packets"
    if change:
        change(document)
    return document


def test_a_spec_names_its_rule_sets_and_its_defenses_in_order() -> None:
    spec = range_spec.parse(defended())

    assert spec.rule_sets == (
        range_spec.RuleSet(
            "made-up",
            "sigma",
            "example/rules",
            "b" * 40,
            ("rules/linux/process_creation", "rules/web"),
            "LICENSE",
            "made-up.lock",
        ),
    )
    # The first defense is the baseline; a defense that only records runs no rules.
    assert spec.defenses == (
        range_spec.Defense("wazuh-stock", "Wazuh with its stock rules", ("wazuh-agent",), ("wazuh",)),
        range_spec.Defense("made_up", "Rules made up for the tests", ("wazuh-agent",), ("made-up",)),
    )
    only_records = defended(
        lambda d: d["defenses"].append(
            {"id": "records", "name": "x", "sensors": ["wazuh-agent"], "rules": []}
        )
    )
    assert range_spec.parse(only_records).defenses[2].rules == ()
    assert range_spec.parse(small()).defenses == () and range_spec.parse(small()).rule_sets == ()


def test_a_tracked_manifest_rule_set_keeps_the_repository_sets_positional_fields() -> None:
    found = range_spec.parse(manifest_defended()).rule_sets[0]

    assert found == range_spec.RuleSet(
        "published",
        "suricata",
        source_file="lab/rules/published/SHA256SUMS",
        sha256="a" * 64,
        version="7",
    )


def test_a_tracked_manifest_sha256_can_be_written_as_eight_short_chunks() -> None:
    chunks = ["01234567", "89abcdef"] * 4
    document = manifest_defended(lambda d: d["rule_sets"]["published"].update(sha256=chunks))

    assert range_spec.parse(document).rule_sets[0].sha256 == "".join(chunks)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"source": "lab/rules/published.tar.gz"}, "source must be a SHA256SUMS manifest"),
        ({"source": "../SHA256SUMS"}, "source must be a SHA256SUMS manifest"),
        ({"sha256": "A" * 64}, "sha256 must be 64 lower-case hex digits"),
        ({"sha256": "a" * 63}, "sha256 must be 64 lower-case hex digits"),
        ({"sha256": ["01234567"] * 7}, "sha256 must be 64 lower-case hex digits"),
        ({"sha256": ["01234567"] * 7 + ["ABCDEFGH"]}, "sha256 must be 64 lower-case hex digits"),
        ({"version": "two\nlines"}, "version must be one short line"),
        ({"version": 7}, "version must be one short line"),
    ],
)
def test_a_tracked_manifest_pin_is_strict(values: dict, message: str) -> None:
    document = manifest_defended(lambda d: d["rule_sets"]["published"].update(values))

    with pytest.raises(range_spec.SpecError, match=message):
        range_spec.parse(document)


def change_set(**values):
    def change(document: dict) -> None:
        document["rule_sets"]["made-up"].update(values)

    return change


def change_defense(index: int, **values):
    def change(document: dict) -> None:
        document["defenses"][index].update(values)

    return change


def rename_set(name):
    def change(document: dict) -> None:
        document["rule_sets"] = {name: document["rule_sets"]["made-up"]}
        document["defenses"][1]["rules"] = [name]

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        # rule_sets
        (put({}, "rule_sets"), "rule_sets must name at least one rule set"),
        (put(["made-up"], "rule_sets"), "rule_sets must name at least one rule set"),
        (rename_set("Made Up"), "rule_sets: the name 'Made Up' must be lower-case letters"),
        (rename_set("a" * 65), "from 1 to 64 characters"),
        (rename_set("wazuh"), "rule_sets: wazuh is the name of the rules the Wazuh manager runs live"),
        (rename_set("pinned"), "rule_sets: a recording names a detector of its own pinned"),
        (rename_set("lab"), "rule_sets: a recording names a detector of its own lab"),
        (drop("rule_sets", "made-up", "commit"), "rule_sets: made-up lacks: commit"),
        (change_set(url="https://example.com/rules.zip"), "rule_sets: made-up has unknown keys: url"),
        (change_set(repo="https://github.com/example/rules"), "repo must be a GitHub repository"),
        (change_set(commit="552f3fee"), "rule_sets: made-up: commit must be a full commit id"),
        (change_set(folders=[]), "folders must list folders of the repository"),
        (change_set(folders=["/rules/linux"]), "folders must list folders of the repository"),
        (change_set(folders=["rules", "rules/linux"]), "once each and none inside another"),
        (change_set(folders=["rules/linux", "rules/linux"]), "once each and none inside another"),
        (change_set(licence="../LICENSE"), "licence must be the licence file of the repository"),
        (change_set(licence="rules/web/LICENSE"), "licence names rules/web/LICENSE, which is inside"),
        (change_set(lock="locks/../made-up.lock"), "lock must be a file beside the spec"),
        (change_set(lock="small.lock"), "lock names small.lock, the lock of atomic_red_team's files"),
        (
            lambda d: d["defenses"].pop(1),
            "rule_sets: no defense runs made-up: name it under a defense's rules, or leave it out",
        ),
        (drop("defenses"), "rule_sets: no defense runs made-up"),
        # defenses
        (put([], "defenses"), "defenses must be a list of 1 to 8 defenses"),
        (put({"wazuh-stock": {}}, "defenses"), "defenses must be a list of 1 to 8 defenses"),
        (change_defense(1, id="two words"), "defenses: the id 'two words' must be 1 to 64 letters"),
        (change_defense(1, id="wazuh-stock"), "defenses lists the id wazuh-stock twice"),
        (change_defense(1, name=""), "defenses: made_up: name must say in a few plain words"),
        (change_defense(1, name="made\tup"), "name must say in a few plain words"),
        (change_defense(1, responses=["block"]), "defenses has unknown keys: responses"),
        (drop("defenses", 1, "rules"), "defenses lacks: rules"),
        (
            change_defense(1, sensors=["pcap"]),
            "defenses: made_up: sensors must list at least one kind of sensor, once each, of: "
            "wazuh-agent, packet-capture",
        ),
        (change_defense(1, sensors=[]), "sensors must list at least one kind of sensor"),
        (
            change_defense(0, rules=["suricata"]),
            "defenses: wazuh-stock: rules names 'suricata', which is neither wazuh (the rules the Wazuh "
            "manager runs live) nor a rule set of rule_sets (made-up)",
        ),
        (
            change_defense(0, rules=["wazuh", "wazuh"]),
            "rules must list at most 4 rule sets by name, once each",
        ),
        (change_defense(0, rules="wazuh"), "rules must list at most 4 rule sets by name, once each"),
    ],
)
def test_the_loader_refuses_a_rule_set_or_a_defense_with_the_reason(change, message: str) -> None:
    with pytest.raises(range_spec.SpecError) as refused:
        range_spec.parse(defended(change))

    assert message in str(refused.value)


def test_a_defense_that_names_the_agents_needs_a_spec_with_wazuh() -> None:
    document = a_spec(
        defenses=[{"id": "wazuh-stock", "name": "Wazuh", "sensors": ["wazuh-agent"], "rules": ["wazuh"]}]
    )

    with pytest.raises(
        range_spec.SpecError,
        match="the sensor wazuh-agent is the agent of defense.wazuh, and the spec has none",
    ):
        range_spec.parse(document)


def test_a_packet_capture_defense_needs_a_host_that_captures_packets() -> None:
    document = a_spec(
        defenses=[
            {
                "id": "packets",
                "name": "Recorded packets",
                "sensors": ["packet-capture"],
                "rules": [],
            }
        ]
    )

    with pytest.raises(
        range_spec.SpecError,
        match="a defense with sensor packet-capture needs at least one host with capture: packets",
    ):
        range_spec.parse(document)


def test_a_packet_capture_defense_needs_the_manager_logs_that_scoring_starts_from() -> None:
    document = a_spec(
        base={"image": IMAGE, "apt_snapshot": "20261120T000000Z"},
        defenses=[
            {
                "id": "packets",
                "name": "Recorded packets",
                "sensors": ["packet-capture"],
                "rules": [],
            }
        ],
    )
    middle = document["hosts"]["middle"]
    middle.pop("image")
    middle.update(capture="packets", packages=["tcpdump"], listens=[])

    with pytest.raises(
        range_spec.SpecError,
        match=(
            "a defense with sensor packet-capture also needs defense.wazuh, because scoring starts "
            "from the manager's copied logs"
        ),
    ):
        range_spec.parse(document)


def test_every_network_interface_of_a_capture_host_needs_a_peer() -> None:
    document = small()
    document["networks"]["alone"] = {}
    document["hosts"]["web"]["networks"].append("alone")
    document["hosts"]["web"]["packages"].append("tcpdump")
    document["hosts"]["web"]["capture"] = "packets"

    with pytest.raises(
        range_spec.SpecError,
        match="host web: capture packets needs a peer on network alone, so capture_ready can mark that interface",
    ):
        range_spec.parse(document)


def test_a_step_of_the_path_on_a_host_the_spec_does_not_declare_is_refused() -> None:
    document = small(put({"steps": [{"id": "s01", "technique": "T1082", "host": "nowhere"}]}, "path"))

    with pytest.raises(range_spec.SpecError, match="step s01 of the path runs on nowhere"):
        range_spec.parse(document)


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

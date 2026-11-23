"""The checks that what range one plants is in place: what each one runs where, and how it is judged."""

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from bluefire_lab.range import atomics, engine, plants
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
ADDRESSES = {"client": {"edge": "10.9.0.4"}, "web": {"edge": "10.9.0.5"}}


def range_one() -> range_spec.Spec:
    return range_spec.load(RANGE_ONE)


def all_checks() -> list[plants.Check]:
    spec = range_one()
    locked = atomics.read_lock((RANGE_ONE.parent / "range-one.lock").read_text(), spec)
    return plants.checks(spec, locked, ADDRESSES)


def named(name: str, subject: str) -> plants.Check:
    return next(c for c in all_checks() if c.name == name and c.subject == subject)


def test_the_deploy_key_logs_in_to_build_and_may_read_the_signing_secret_and_nothing_else_checked() -> None:
    login = named("plant: key login", "key deploy: webadmin@web to deploy@build")

    (command,) = login.commands
    assert (command.host, command.user) == ("web", "webadmin")
    # No -i: the path's ssh uses the key under the name ssh tries by itself.
    assert "ssh -o BatchMode=yes -o ConnectTimeout=10 deploy@build " in command.script
    assert login.expected == ["key webadmin 600", "deploy", "readable /etc/buildbot/signing.env"]
    for secret in ("/etc/shadow", "/etc/gshadow", "/etc/ssh/ssh_host_ed25519_key"):
        assert secret in command.script


def test_a_key_held_on_one_host_and_accepted_on_another_is_tried_from_its_holder() -> None:
    login = named("plant: key login", "key ops: ops@client to ops@web")

    (command,) = login.commands
    assert (command.host, command.user) == ("client", "ops")
    assert login.expected[:2] == ["key ops 600", "ops"]
    assert "readable /var/www/app/config.php" in login.expected
    assert "readable /etc/shadow" not in login.expected


@pytest.mark.skipif(not (shutil.which("perl") and shutil.which("openssl")), reason="needs perl and openssl")
def test_webadmins_password_check_tells_its_own_hash_from_another_passwords() -> None:
    account = named("plant: account", "host web: webadmin")
    compare = next(line for line in account.commands[0].script.splitlines() if line.startswith("perl "))

    def judged(password: str) -> str:
        # A hash of the kind the C library's crypt() reads, made here instead of read from /etc/shadow.
        made = subprocess.run(
            ["openssl", "passwd", "-6", password], capture_output=True, text=True, check=True
        )
        script = f"hash={shlex.quote(made.stdout.strip())}\n{compare}"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout

    assert account.expected[-1] == "password matches"
    assert judged("webadmin") == "password matches\n"
    assert judged("webadmin2") == "password differs\n"


def test_ops_uses_its_sudo_rule_once_without_a_password() -> None:
    account = named("plant: account", "host web: ops")

    use = account.commands[-1]
    assert (use.host, use.user) == ("web", "ops")
    assert use.script.startswith("sudo -n /usr/sbin/nginx -t ")
    assert account.expected[-2:] == ["sudo NOPASSWD: /usr/sbin/nginx -t", "sudo exit 0"]
    assert account.judge([(0, "x"), (0, "sudo exit 1\n")])[1] is False


def test_webadmins_password_logs_in_over_ssh_once_from_client_not_from_the_attacker() -> None:
    login = named("plant: password login", "ops@client to webadmin@web")

    (command,) = login.commands
    assert (command.host, command.user) == ("client", "ops")
    assert "-o PubkeyAuthentication=no" in command.script
    assert "-o StrictHostKeyChecking=yes" in command.script
    assert login.expected == ["webadmin"]
    assert [c.subject for c in all_checks() if c.name == "plant: password login"] == [login.subject]


def test_the_shop_page_passes_only_with_status_200_no_database_error_and_an_item() -> None:
    (page,) = plants.pages(range_one(), range_one().hosts["web"])

    def passes(output: str, code: int = 0) -> bool:
        return page.judge([(code, output)])[1]

    assert passes("status 200\ndatabase errors 0\nitems 3\n")
    assert not passes("status 503\ndatabase errors 0\nitems 3\n")
    assert not passes("status 200\ndatabase errors 1\nitems 3\n")
    assert not passes("status 200\ndatabase errors 0\nitems 0\n")
    assert not passes("status 200\ndatabase errors 0\nitems 3\n", code=7)


def test_the_database_passes_only_with_its_user_its_grant_and_its_settings() -> None:
    spec = range_one()
    grants = plants.database(spec, spec.hosts["db"])[0]
    usage = "GRANT USAGE ON *.* TO `shop`@`%` IDENTIFIED BY PASSWORD '*0000'"
    grant = "GRANT ALL PRIVILEGES ON `shop`.* TO `shop`@`%`"

    def passes(*lines: str) -> bool:
        return grants.judge([(0, "\n".join(lines) + "\n")])[1]

    assert passes("shop@%", usage, grant, "0.0.0.0\t/var/log/mysql/error.log")
    assert not passes("shop@%", usage, "0.0.0.0\t/var/log/mysql/error.log")
    assert not passes(
        "shop@%", usage, "GRANT SELECT ON `shop`.* TO `shop`@`%`", "0.0.0.0\t/var/log/mysql/error.log"
    )
    assert not passes("shop@%", usage, grant, "127.0.0.1\t/var/log/mysql/error.log")
    assert not passes("shop@localhost", usage, grant, "0.0.0.0\t/var/log/mysql/error.log")


PLANTS_FAILED = {
    "passed": False,
    "checks": [{"check": "plant: upload", "subject": "host inet", "pass": False}],
}


def test_a_sealed_run_whose_plants_are_not_in_place_ends_with_exit_1_and_names_the_check() -> None:
    sealed = (engine.EXIT_OK, "sealed", None)

    assert engine.outcome(sealed, True, True, {"passed": True, "checks": []}) == sealed
    assert engine.outcome(sealed, True, True, PLANTS_FAILED) == (
        engine.EXIT_REFUSED,
        "plants not in place",
        "plant checks failed: plant: upload (host inet)",
    )


def test_failed_plants_do_not_hide_a_teardown_or_an_event_watch_that_failed_after_them() -> None:
    sealed = (engine.EXIT_OK, "sealed", None)

    watch = engine.outcome(sealed, True, False, PLANTS_FAILED)
    left = engine.outcome(sealed, False, True, PLANTS_FAILED)

    assert watch[:2] == (engine.EXIT_INVALID, "invalid")
    assert left[:2] == (engine.EXIT_REFUSED, "engine error")
    assert engine.outcome((engine.EXIT_SEAL, "seal failed", "x"), True, True, PLANTS_FAILED)[:2] == (
        engine.EXIT_SEAL,
        "seal failed",
    )


def test_the_database_password_in_config_php_connects_from_web_as_its_owner() -> None:
    connect = named("plant: database password in a file", "host web: /var/www/app/config.php")

    (command,) = connect.commands
    assert (command.host, command.user) == ("web", "www-data")
    assert connect.expected == ["connected as shop@%"]


def test_web_pages_and_the_stand_in_internet_are_checked_from_client_never_from_a_host_of_the_path() -> None:
    from_hosts = {
        c.commands[0].host
        for c in all_checks()
        if c.name in ("plant: shop page", "plant: served file", "plant: upload")
    }

    assert from_hosts == {"client"}


def test_the_served_file_must_have_its_locked_sha256_and_its_line_in_the_access_log() -> None:
    served = named("plant: served file", "host inet: /atomics/T1105/src/atomic.sh to client")

    locked = atomics.read_lock((RANGE_ONE.parent / "range-one.lock").read_text(), range_one())
    assert served.expected == [locked["atomics/T1105/src/atomic.sh"], "1"]
    assert "grep -c '^10.9.0.4 GET /atomics/T1105/src/atomic.sh 200 '" in served.commands[1].script


def test_the_upload_is_stored_indexed_and_then_removed_so_that_the_paths_upload_is_the_first() -> None:
    upload = named("plant: upload", "host inet: upload from client")

    assert upload.expected[0] == "stored 1"
    assert upload.expected[1].startswith("1 10.9.0.4 ")
    assert upload.commands[1].script.endswith("rm -f /srv/uploads/1.bin /srv/uploads/index.tsv")


def test_carried_files_are_compared_in_the_order_of_their_paths_whatever_their_hashes() -> None:
    spec = range_one()
    attacker = spec.hosts["attacker"]
    folder = f"atomics/{attacker.atomics_src[0]}/src"
    # The first path has the larger hash: sorting by the whole line would swap the two.
    locked = {f"{folder}/a.txt": "f" * 64, f"{folder}/b.txt": "0" * 64}

    (carried,) = plants.carried(spec, attacker, locked)
    listed_by_path = "".join(
        f"{digest}  {path.removeprefix('atomics/')}\n" for path, digest in sorted(locked.items())
    )

    assert carried.judge([(0, listed_by_path)])[1] is True


def test_a_check_fails_when_a_command_fails_even_with_the_expected_output() -> None:
    judge = plants.lines_judge(["deploy"])

    assert judge([(0, "deploy\n")]) == (["deploy"], True)
    assert judge([(255, "deploy\n")])[1] is False
    assert judge([(0, "deploy\nreadable /etc/shadow\n")])[1] is False


def test_the_ready_gate_compares_each_known_hosts_entry_with_its_hosts_key() -> None:
    checks = [c for c in plants.ready_checks(range_one()) if c.name == "ready: known host key"]
    known = checks[1]

    assert [c.subject for c in checks] == ["host client: ops knows web", "host web: webadmin knows build"]
    assert [c.host for c in known.commands] == ["build", "web"]
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStandIn"
    assert known.judge([(0, key + "\n"), (0, key + "\n")])[1] is True
    assert known.judge([(0, key + "\n"), (0, "ssh-ed25519 AAAAother\n")])[1] is False
    assert known.judge([(0, "\n"), (0, "\n")])[1] is False


def test_the_ready_gate_fetches_the_stand_in_internet_from_web_and_client_over_http_and_https() -> None:
    fetches = [
        c for c in plants.ready_checks(range_one()) if c.name == "ready: pages of the stand-in internet"
    ]

    assert [c.subject for c in fetches] == ["host client to inet", "host web to inet"]
    assert all(c.expected == ["http 200", "https 200"] for c in fetches)


def test_the_weaknesses_range_one_plants_are_listed_for_the_manifest() -> None:
    found = plants.weaknesses(range_one())

    assert found == [
        "web: the account webadmin has the password that line 475 of the published list "
        "atomics/T1110.004/src/credstuffuserpass.txt gives it",
        "web: the SSH server accepts passwords",
        "web: pam_unix has nodelay, so a failed password is answered without a pause",
        "web: webadmin holds the rsa key deploy without a passphrase, and deploy@build accepts it",
        "web: /var/www/app/config.php holds the password of db's database user shop, mode 0644",
        "web: /tmp/stage is a folder owned by webadmin, mode 0700",
        "build: /etc/buildbot/signing.env is readable by the group deploy",
    ]


def test_the_engine_runs_each_command_as_its_account_and_records_the_judgement(tmp_path: Path) -> None:
    run = engine.Run(range_one(), "range-one.yaml", tmp_path, None, 0)
    run.containers = {host: host[0] * 64 for host in run.spec.hosts}
    ran = []

    def execute(identifier, script, timeout, tag="", user="root") -> subprocess.CompletedProcess:
        ran.append((identifier[0], user, tag))
        return subprocess.CompletedProcess([], 0, "deploy\n", "")

    run.execute = execute
    check = plants.check("plant: x", "a subject", [plants.Command("web", "webadmin", "id -un")], ["deploy"])
    failing = plants.check("plant: y", "another", [plants.Command("build", "root", "true")], ["other"])

    results = run.run_checks([check, failing], "engine:plant")

    assert ran == [("w", "webadmin", "engine:plant"), ("b", "root", "engine:plant")]
    assert [(r["check"], r["pass"], r["observed"]) for r in results] == [
        ("plant: x", True, ["deploy"]),
        ("plant: y", False, ["deploy"]),
    ]

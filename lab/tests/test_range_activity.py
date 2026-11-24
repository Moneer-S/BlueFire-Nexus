"""The ordinary activity of a range: what its loader refuses, its schedule, what it bakes in, and its counts."""

import copy
import json
import math
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from bluefire_lab.range import activity, build, engine
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
FIXTURES = Path(__file__).parent / "fixtures" / "range" / "activity"


def document() -> dict:
    return range_spec.read(RANGE_ONE.read_text())


def loaded(changed: dict | None = None) -> range_spec.Spec:
    data = changed if changed is not None else document()
    return range_spec.parse(data, "", RANGE_ONE.parent)


def with_job(**job) -> dict:
    data = document()
    data["activity"]["jobs"] = [job]
    return data


def refused(data: dict) -> str:
    with pytest.raises(range_spec.SpecError) as error:
        loaded(data)
    return str(error.value)


CRON = {"name": "tidy", "host": "web", "account": "www-data", "every": 60, "do": "cron", "run": "true"}


def test_range_one_has_five_jobs_on_the_hosts_and_accounts_the_path_does_not_use() -> None:
    jobs = loaded().activity.jobs

    assert [(j.name, j.host, j.account, j.do) for j in jobs] == [
        ("browse", "client", "ops", "http"),
        ("admin", "client", "ops", "ssh"),
        ("cache", "web", "www-data", "cron"),
        ("build", "build", "ci", "cron"),
        ("backup", "db", "root", "cron"),
    ]
    assert [j.acts_on for j in jobs] == ["web", "web", "web", "build", "db"]


@pytest.mark.parametrize(
    ("job", "reason"),
    [
        ({**CRON, "account": "webadmin"}, "uses the account webadmin on web, which the path uses"),
        # deploy is named only in a step's arguments (domain: deploy@build).
        (
            {**CRON, "host": "build", "account": "deploy"},
            "uses the account deploy on build, which the path uses",
        ),
        (
            {
                "name": "peek",
                "host": "client",
                "account": "ops",
                "every": 60,
                "do": "ssh",
                "target": "webadmin@web",
                "run": "true",
            },
            "uses the account webadmin on web, which the path uses",
        ),
        ({**CRON, "host": "attacker", "account": "root"}, "whose address the path comes from"),
        (
            {
                "name": "look",
                "host": "client",
                "account": "ops",
                "every": 5,
                "do": "http",
                "target": "attacker",
                "paths": ["/"],
            },
            "reaches attacker, whose address the path comes from",
        ),
        ({**CRON, "do": "ftp"}, "do must be one of http, ssh, cron"),
        ({**CRON, "account": "nobody"}, "'nobody' is not an account of host web"),
        ({**CRON, "every": 90}, "every must be whole minutes"),
        ({**CRON, "every": [120, 60]}, "120 is more than 60"),
        ({**CRON, "host": "client", "account": "ops"}, "host client does not run cron"),
        ({**CRON, "host": "manager"}, "not built from base"),
        ({**CRON, "run": "true\nfalse"}, "run must be a command on one line"),
        ({**CRON, "paths": ["/"]}, "a job that does cron takes no paths"),
        ({**CRON, "writes": ["tmp/x"]}, "writes must list absolute paths"),
        (
            {
                "name": "look",
                "host": "inet",
                "account": "root",
                "every": 5,
                "do": "http",
                "target": "web",
                "paths": ["/"],
            },
            "host inet needs the package curl",
        ),
        (
            {
                "name": "look",
                "host": "client",
                "account": "ops",
                "every": 5,
                "do": "http",
                "target": "inet",
                "paths": ["/"],
            },
            "target inet runs no nginx",
        ),
        (
            {
                "name": "look",
                "host": "client",
                "account": "ops",
                "every": 5,
                "do": "http",
                "target": "web",
                "paths": ["no-slash"],
            },
            "paths must list paths of the web server",
        ),
    ],
)
def test_the_loader_refuses_a_job_that_cannot_run_or_could_be_taken_for_the_path(
    job: dict, reason: str
) -> None:
    assert reason in refused(with_job(**job))


def test_a_job_whose_runs_no_agent_would_see_is_refused() -> None:
    data = with_job(**CRON)
    data["hosts"]["web"]["agent"] = False
    del data["hosts"]["web"]["watch"]

    assert "acts on web, which has no agent" in refused(data)


def test_an_account_the_path_uses_is_refused_by_its_name_on_any_host() -> None:
    # deploy is the path's account on build; here db has an account of that name too.
    data = with_job(**{**CRON, "host": "db", "account": "deploy"})
    data["hosts"]["db"]["accounts"] = [{"name": "deploy", "shell": "/bin/bash"}]

    assert "uses the account deploy on db, which the path uses" in refused(data)


def test_an_ssh_job_needs_a_known_hosts_entry_for_its_target() -> None:
    data = with_job(
        name="peek", host="client", account="ops", every=60, do="ssh", target="ops@web", run="true"
    )
    del data["hosts"]["client"]["known_hosts"]

    assert "ops on client has no known_hosts entry for web" in refused(data)


def test_an_http_job_whose_access_log_no_agent_collects_is_refused() -> None:
    data = with_job(name="look", host="client", account="ops", every=5, do="http", target="web", paths=["/"])
    logs = data["hosts"]["web"]["watch"]["logs"]
    data["hosts"]["web"]["watch"]["logs"] = [
        log for log in logs if log["path"] != "/var/log/nginx/access.log"
    ]

    assert "/var/log/nginx/access.log on web, which no agent collects" in refused(data)


def test_an_ssh_job_needs_a_key_the_target_accepts() -> None:
    data = with_job(
        name="peek", host="client", account="ops", every=60, do="ssh", target="ops@web", run="true"
    )
    data["hosts"]["web"]["keys"] = [k for k in data["hosts"]["web"]["keys"] if k["name"] != "ops"]

    assert "ops on client holds no key that ops@web accepts" in refused(data)


def test_an_ssh_job_logs_in_with_the_accepted_key_only_whatever_its_file_is_called() -> None:
    data = with_job(
        name="peek", host="client", account="ops", every=60, do="ssh", target="ops@web", run="true"
    )
    (key,) = data["hosts"]["client"]["keys"]
    key["file"] = "ops-key"
    loop = activity.loop_script(loaded(data).activity, "client")

    (once,) = [line for line in loop.splitlines() if line.startswith("  once() {")]
    file = f"{range_spec.home('ops')}/.ssh/ops-key"
    assert f" -o IdentitiesOnly=yes -i {file} ops@web " in once


def test_two_jobs_of_one_name_are_refused() -> None:
    data = document()
    data["activity"]["jobs"] = [CRON, {**CRON, "host": "db", "account": "root"}]

    assert "lists the job tidy twice" in refused(data)


LOOK = {"name": "look", "host": "client", "account": "ops", "every": 5, "do": "http", "target": "web"}
PEEK = {"name": "peek", "host": "client", "account": "ops", "every": 60, "do": "ssh", "run": "true"}


@pytest.mark.parametrize(
    ("jobs", "reason"),
    [
        (
            [{**LOOK, "paths": ["/", "/cart"]}, {**LOOK, "name": "shop", "paths": ["/cart"]}],
            "jobs look and shop both fetch /cart of web from client",
        ),
        (
            [{**PEEK, "target": "ops@web"}, {**PEEK, "name": "check", "target": "ops@web"}],
            "jobs peek and check both log in to web from client",
        ),
        (
            [{**CRON, "writes": ["/tmp/shop-*"]}, {**CRON, "name": "sweep", "writes": ["/tmp/*.json"]}],
            "jobs tidy and sweep both write files of /tmp/shop-* and /tmp/*.json on web",
        ),
    ],
)
def test_two_jobs_whose_lines_cannot_be_told_apart_are_refused(jobs: list, reason: str) -> None:
    data = document()
    data["activity"]["jobs"] = jobs

    assert reason in refused(data)


def counted_on_the_excerpts(jobs: list) -> dict:
    """Range one's activity with `jobs` in place of its own, counted on the trimmed logs of a run."""

    record = json.loads((FIXTURES / "window.json").read_text())
    data = document()
    data["activity"]["jobs"] = jobs
    logs = {
        ("web", "/var/log/nginx/access.log"): excerpt("web-nginx-access.txt"),
        ("web", "/var/log/auth.log"): excerpt("web-auth.txt"),
        ("web", "/var/log/snoopy.log"): excerpt("web-snoopy.txt"),
        ("db", "/var/log/snoopy.log"): excerpt("db-snoopy.txt"),
    }
    events = [json.loads(line) for line in excerpt("archive.ndjson")]
    return activity.count(
        loaded(data).activity, logs, events, record["addresses"], record["go"], record["stop"]
    )


def test_two_http_jobs_to_one_server_are_counted_by_their_own_paths() -> None:
    # In the trimmed window client fetched /, /?item=1, /?item=2, /?item=3, /cart, /missing and / again.
    pages = {**LOOK, "name": "pages", "paths": ["/", "/?item=1", "/?item=2", "/?item=3"]}
    errors = {**LOOK, "name": "errors", "paths": ["/cart", "/missing"]}
    other = {**LOOK, "name": "other", "paths": ["/other-only"]}

    counted = counted_on_the_excerpts([other, pages, errors])

    assert {name: entry["runs"] for name, entry in counted.items()} == {"other": 0, "pages": 5, "errors": 2}
    assert {name: entry["archived runs"] for name, entry in counted.items()} == {
        "other": 0,
        "pages": 5,
        "errors": 2,
    }
    assert counted["other"]["archive events"] == 0
    summary = activity.summary({"range": "range-one", "activity": {"jobs": counted, "schedule": {}}})
    assert summary.startswith("### Ordinary activity of range-one: NOT every job ran")


def test_two_cron_jobs_of_one_account_are_counted_by_their_tags() -> None:
    jobs = document()["activity"]["jobs"]
    cache = next(job for job in jobs if job["name"] == "cache")

    counted = counted_on_the_excerpts([{**cache, "name": "again", "writes": []}, cache])

    assert counted["cache"]["runs"] == 1
    assert counted["again"]["runs"] == 0
    assert counted["again"]["archive events"] == 0


def test_a_job_that_runs_as_the_account_an_ssh_job_logs_in_as_is_refused() -> None:
    # admin logs in to ops@web. A cron job on web as ops would leave PAM, sudo and cron lines that
    # name ops and no job, so they could not be told from admin's.
    jobs = document()["activity"]["jobs"]
    admin = next(job for job in jobs if job["name"] == "admin")
    data = document()
    data["activity"]["jobs"] = [admin, {**CRON, "account": "ops"}]

    assert "jobs admin and tidy both act as ops on web" in refused(data)

    # The same cron job as another account of web is told apart by that account, and loads.
    data["activity"]["jobs"] = [admin, CRON]
    assert [job.name for job in loaded(data).activity.jobs] == ["admin", "tidy"]


def test_the_same_seed_gives_the_same_waits_and_another_seed_others() -> None:
    first = loaded().activity
    again = loaded().activity
    data = document()
    data["activity"]["seed"] = 2
    other = loaded(data).activity

    for job in first.jobs:
        assert activity.waits(first, job) == activity.waits(again, job)
    browse, admin = first.jobs[0], first.jobs[1]
    assert activity.waits(first, browse) != activity.waits(other, other.jobs[0])
    assert activity.waits(first, admin) != activity.waits(other, other.jobs[1])


def test_every_wait_is_inside_its_range_and_the_waits_cover_an_hour() -> None:
    spec = loaded().activity

    for job in spec.jobs:
        waits = activity.waits(spec, job)
        low, high = job.every
        assert all(low <= wait <= high for wait in waits), job.name
        assert sum(waits) >= activity.HORIZON
        if job.do == "cron":
            assert all(wait % 60 == 0 for wait in waits)
    browse = activity.waits(spec, spec.jobs[0])
    assert len(set(browse)) == 11  # every whole second from 5 to 15 is drawn in an hour


def small_activity() -> range_spec.Spec:
    data = document()
    data["activity"] = {
        "seed": 7,
        "warmup_seconds": 0,
        "tail_seconds": 0,
        "jobs": [
            {
                "name": "look",
                "host": "client",
                "account": "ops",
                "every": [2, 3],
                "do": "http",
                "target": "web",
                "paths": ["/", "/?item=1"],
            },
            {
                "name": "tidy",
                "host": "web",
                "account": "www-data",
                "every": [60, 120],
                "do": "cron",
                "run": "php /var/www/app/cron.php",
                "writes": ["/tmp/shop-cache-*.json"],
            },
        ],
    }
    return loaded(data)


def test_a_cron_job_is_gated_on_the_go_tagged_and_run_as_its_account() -> None:
    spec = small_activity()
    files = activity.files(spec.activity, "web")

    entry = files["files/web/cron-tidy"].decode().splitlines()
    assert "BLUEFIRE_TAG=job:tidy" in entry
    assert (
        entry[-1]
        == "* * * * * www-data test -e /run/bluefire/go || exit 0; exec /usr/local/lib/bluefire/job-tidy"
    )
    script = files["files/web/job-tidy"].decode().splitlines()
    commands = [line for line in script if not line.startswith("#")]
    assert commands[0] == "test -e /run/bluefire/go || exit 0"
    assert commands[1] == "export BLUEFIRE_TAG=job:tidy"
    assert commands[-1] == "/bin/bash -c 'php /var/www/app/cron.php' > /run/bluefire/job-tidy/output 2>&1"
    lines = activity.dockerfile_lines(spec.activity, "web")
    assert "COPY --chmod=0644 files/web/cron-tidy /etc/cron.d/bluefire-tidy" in lines
    assert "install -d -o www-data -g www-data -m 0700 /run/bluefire/job-tidy" in build.start_script(
        spec, "web"
    )


def test_the_loop_script_runs_each_job_as_its_account_once_the_go_is_there() -> None:
    spec = small_activity()
    loop = activity.files(spec.activity, "client")["files/client/activity"].decode()

    assert "  export BLUEFIRE_TAG=job:look" in loop.splitlines()
    assert "  test -e /run/bluefire/go || { nap 1; continue; }" in loop.splitlines()
    assert "paths=(/ '/?item=1')" in loop
    start = build.start_script(spec, "client").splitlines()
    assert "su -s /bin/bash -c '/usr/local/lib/bluefire/activity look' ops > /dev/null 2>&1 &" in start
    assert start[-1] == "exec sleep infinity"
    # A host without a loop job gets no loop script.
    assert "files/web/activity" not in activity.files(spec.activity, "web")


def minute() -> int:
    return int(
        subprocess.run(["bash", "-c", "echo $((EPOCHSECONDS / 60))"], capture_output=True, text=True).stdout
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_a_cron_jobs_script_runs_once_when_due_and_waits_its_minutes(tmp_path: Path) -> None:
    spec = small_activity()
    job = spec.activity.jobs[1]
    script = activity.cron_script(spec.activity, job)
    # The same script with its paths moved into a folder of the test, and the job's run made harmless.
    script = script.replace(activity.GO, str(tmp_path / "go")).replace(activity.STATE, str(tmp_path))
    script = script.replace("'php /var/www/app/cron.php'", "'echo ran'")
    (tmp_path / "job-tidy").mkdir()
    path = tmp_path / "job"
    path.write_text(script)

    def started() -> str:
        subprocess.run(["bash", str(path)], check=True)
        state = tmp_path / "job-tidy" / "state"
        return state.read_text() if state.exists() else ""

    assert started() == ""  # no go: nothing runs
    assert not (tmp_path / "job-tidy" / "output").exists()
    (tmp_path / "go").touch()
    before = minute()
    first = started()
    after = minute()
    assert (tmp_path / "job-tidy" / "output").read_text() == "ran\n"
    runs, due = (int(value) for value in first.split())
    assert runs == 1
    assert due - activity.waits(spec.activity, job)[0] // 60 in (before, after)
    if minute() < due:
        assert started() == first  # not due again before its wait is over


def excerpt(name: str) -> list[str]:
    return (FIXTURES / name).read_text().splitlines()


def test_runs_and_archive_events_are_counted_per_job_from_a_runs_trimmed_logs() -> None:
    # A run of range one, trimmed to each host's go and 70 s after it, which stands in for its stop:
    # browse's first seven pages, admin's first login, and the first runs of cache and backup. The
    # expected counts were made by plain filters apart from the lab's code. build is left out.
    record = json.loads((FIXTURES / "window.json").read_text())
    spec = loaded().activity
    logs = {
        ("web", "/var/log/nginx/access.log"): excerpt("web-nginx-access.txt"),
        ("web", "/var/log/auth.log"): excerpt("web-auth.txt"),
        ("web", "/var/log/snoopy.log"): excerpt("web-snoopy.txt"),
        ("db", "/var/log/snoopy.log"): excerpt("db-snoopy.txt"),
    }
    events = [json.loads(line) for line in excerpt("archive.ndjson")]

    counted = activity.count(spec, logs, events, record["addresses"], record["go"], record["stop"])

    assert {name: entry["runs"] for name, entry in counted.items()} == record["runs"]
    assert {name: entry["archived runs"] for name, entry in counted.items()} == record["archived runs"]
    assert {name: entry["archive events by source"] for name, entry in counted.items()} == record["sources"]
    sessions = {
        name: entry["cron sessions of the account"]
        for name, entry in counted.items()
        if "cron sessions of the account" in entry
    }
    assert sessions == record["cron sessions of the account"]


def test_cron_sessions_and_a_minutes_start_of_the_script_are_not_taken_for_a_run_that_was_seen() -> None:
    # Root's stock /etc/crontab on db opens the same session lines as backup's entry, and cron starts
    # backup's script each minute, also when backup is not due.
    spec = loaded().activity
    stamp = "2026-11-23T23:17:01.000000+00:00"
    session = {
        "agent": {"name": "db"},
        "location": "/var/log/auth.log",
        "full_log": f"{stamp} db CRON[700]: pam_unix(cron:session): session opened for user root",
        "predecoder": {"timestamp": stamp},
    }
    script = {
        "agent": {"name": "db"},
        "location": "/var/log/snoopy.log",
        "full_log": f"{stamp} db snoopy[702]: [login:root ssh:((undefined)) sid:702 uid:0 euid:0 cwd:/root "
        "tag:job:backup]: /usr/local/lib/bluefire/job-backup",
        "predecoder": {"timestamp": stamp},
        "data": {"tag": "job:backup", "command": "/usr/local/lib/bluefire/job-backup"},
    }
    go, stop = {"db": 1795475000.0}, {"db": 1795480000.0}  # 23:03:20 to 00:26:40, around the lines

    counted = activity.count(spec, {("db", "/var/log/snoopy.log"): []}, [session, script], {}, go, stop)

    assert counted["backup"]["cron sessions of the account"] == 1
    assert counted["backup"]["archive events by source"] == {"snoopy, by tag": 1}
    assert counted["backup"]["archived runs"] == 0
    summary = activity.summary({"range": "range-one", "activity": {"jobs": counted, "schedule": {}}})
    assert summary.startswith("### Ordinary activity of range-one: NOT every job ran")


def a_page(written: str, received: str) -> dict:
    """An archived nginx line of a page client fetched at `written`, which the manager received at `received`."""

    return {
        "timestamp": f"2026-11-24T09:18:{received}+0000",
        "agent": {"name": "web"},
        "full_log": f'172.18.0.3 - - [24/Nov/2026:09:18:{written} +0000] "GET / HTTP/1.1" 200 251 "-" "curl/8.5.0"',
        "data": {"protocol": "GET", "srcip": "172.18.0.3", "id": "200", "url": "/"},
        "location": "/var/log/nginx/access.log",
    }


def test_a_line_is_sorted_to_a_job_by_its_own_time_not_by_when_the_manager_received_it() -> None:
    # The engine's plant check fetched a page 1.9 s before the go, and the manager received the line
    # after the go. browse's first page in the second of the go counts, as `runs` counts it.
    spec = loaded().activity
    go = {host: 1795511935.880936 for host in spec.hosts}  # 2026-11-24T09:18:55.88
    plant_check, first_page = a_page("54", "56.314"), a_page("55", "56.402")

    found = activity.attribute(spec, [plant_check, first_page], {"client": ["172.18.0.3"]}, go, {})

    assert found == {1: ("browse", "/var/log/nginx/access.log, by address")}


def test_the_go_starts_a_new_second_so_that_nothing_the_engine_did_before_it_shares_its_second(
    tmp_path: Path,
) -> None:
    run = engine.Run(loaded(), "range-one.yaml", tmp_path, None, 0)
    run.containers = {host: host[0] * 64 for host in run.spec.hosts}
    # The containers share the clock of the machine the engine runs on.
    run.execute = lambda identifier, script, timeout, tag="": subprocess.CompletedProcess(
        [], 0, f"{time.time():.6f}", ""
    )

    before = time.time()
    run.activity_go()

    go = run.manifest["activity"]["go"]
    assert set(go) == set(run.spec.activity.hosts)
    assert math.floor(min(go.values())) > math.floor(before)
    assert min(go.values()) - before < 1.5


def test_a_job_on_a_host_where_the_go_was_never_written_is_not_counted() -> None:
    spec = loaded().activity

    counted = activity.count(spec, {}, [], {}, {"client": 1.0}, {})

    assert counted["browse"]["runs"] is None
    assert counted["browse"]["not counted"] == "/var/log/nginx/access.log was not copied out of web"
    assert counted["cache"]["runs"] is None
    assert counted["cache"]["not counted"] == "the engine did not write the go on its host"


def test_the_summary_says_when_a_job_did_not_run() -> None:
    manifest = {
        "range": "range-one",
        "activity": {
            "minutes": 2.5,
            "schedule": {"backup": {"every": [300, 300]}},
            "jobs": {
                "backup": {
                    "host": "db",
                    "account": "root",
                    "do": "cron",
                    "runs": 0,
                    "runs counted from": "db: /var/log/snoopy.log",
                    "archived runs": 0,
                    "archive events": 4,
                    "archive events by source": {"snoopy, by tag": 4},
                    "cron sessions of the account": 8,
                },
            },
        },
    }

    text = activity.summary(copy.deepcopy(manifest))

    assert text.startswith(
        "### Ordinary activity of range-one: NOT every job ran and had a run reach the archive"
    )
    assert (
        "| backup | db | root | cron | 300 | 0 | db: /var/log/snoopy.log | 0 | 4 | snoopy, by tag 4 | 8 |"
        in text
    )

"""The ordinary activity of a range: the work of a small shop's people and machines, beside the path.

A spec's `activity` lists jobs. Each runs on a host of the range as one of its
accounts, every so many seconds: `http` fetches pages from a web server, `ssh`
logs in to another host with a planted key and runs a command there, and
`cron` runs a command on its own host. They are the other half of the measure:
an alert on them is a false alert, and they write to the same logs and folders
as the path's steps.

The jobs are baked into the images: a cron entry and a script for each cron
job, and one loop script, on the host they run from, for the http and ssh
jobs, whose waits are counted in seconds. A job's script and its command start
only after the engine writes /run/bluefire/go on its host, and every program
they start carries BLUEFIRE_TAG=job:<name>. Cron still opens a session for a
cron job's account each minute before the go and after the stop, and the
entry's gate then ends it: two lines in auth.log, outside the activity's
minutes. The waits between runs are drawn from the spec's seed, so the same
spec gives the same schedule.

After the run, each job's runs are counted from the logs of the host it acts
on (snoopy's line of a cron job's command, nginx's access log lines of the
job's paths for http, sshd's logins for ssh), again from those lines in the
manager's archive, and its events in the archive by tag, address, path,
account and folder. Only the logs of watched hosts are read, so every job acts
on a host with an agent, and the loader refuses two jobs whose lines could not
be told apart.
"""

from __future__ import annotations

import hashlib
import math
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from functools import cache

from . import wazuh
from .spec import ACCOUNT, NAME, Host, SpecError, Watch, home

KINDS = ("http", "ssh", "cron")
GO = "/run/bluefire/go"
STATE = "/run/bluefire"
LIB = "/usr/local/lib/bluefire"
LOOP = f"{LIB}/activity"
AUTH_LOG = "/var/log/auth.log"
SNOOPY_LOG = "/var/log/snoopy.log"
NGINX_ACCESS = "/var/log/nginx/access.log"
# How far ahead the schedule is drawn, in seconds; a job that runs longer starts its waits again.
HORIZON = 3600
# The longest wait, warm-up or tail a spec may ask for.
LONGEST = 3600
# Events of a job are counted from the engine's go to its stop, and this many seconds after the stop.
GRACE = 5
# The files of the engine's marks start with this name. They are the engine's, in whatever folder.
ENGINE_MARK = "bluefire-mark-"
URL_PATH = re.compile(r"/[A-Za-z0-9._~/?=&%-]*\Z")
WRITES = re.compile(r"/[A-Za-z0-9._*/-]*\Z")
AT_HOST = re.compile(r"\b([a-z_][a-z0-9_-]*)@([a-z][a-z0-9-]*)\b")
SNOOPY = re.compile(r"(\S+) \S+ snoopy\[[0-9]+\]: \[.* tag:(\S*)\]: (.*)\Z")
NGINX = re.compile(r"(\S+) \S+ \S+ \[([^\]]+)\] ")
# The request of an nginx line, in the access log and in the error log alike: its path is group 1.
REQUEST = re.compile(r'"[A-Z]+ (\S+) HTTP/[0-9.]+"')


@dataclass(frozen=True)
class Job:
    name: str
    host: str
    account: str
    every: tuple[int, int]  # the shortest and the longest wait, in seconds
    do: str
    target: str | None = None  # the host an http or ssh job reaches
    target_account: str | None = None  # the account an ssh job logs in as
    paths: tuple[str, ...] = ()
    run: str | None = None
    writes: tuple[str, ...] = ()  # the files it writes on the host it acts on, as patterns
    identity: str | None = None  # the private key file an ssh job logs in with, one its target accepts

    @property
    def tag(self) -> str:
        return f"job:{self.name}"

    @property
    def acts_on(self) -> str:
        """The host whose logs show the job: the one it reaches, or its own."""

        return self.target or self.host

    @property
    def command(self) -> str:
        """The program start of a cron job's run, as snoopy logs it."""

        return f"/bin/bash -c {self.run}"


@dataclass(frozen=True)
class Activity:
    seed: int
    warmup_seconds: int
    tail_seconds: int
    jobs: tuple[Job, ...]

    @property
    def hosts(self) -> list[str]:
        """The hosts where a job runs, in the order of the jobs."""

        return list(dict.fromkeys(job.host for job in self.jobs))

    def on(self, host: str) -> list[Job]:
        return [job for job in self.jobs if job.host == host]


# The spec section


def _seconds(value: object, where: str, low: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= LONGEST:
        raise SpecError(f"{where} must be a whole number of seconds from {low} to {LONGEST}")
    return value


def path_uses(path: object, hosts: dict[str, Host]) -> tuple[set[tuple[str, str]], set[str]]:
    """The (host, account) pairs the path uses, and the hosts whose address it comes from.

    The accounts are each step's own and any account@host its arguments name;
    the addresses are those of the path's start and of every host of kind attacker.
    """

    accounts: set[tuple[str, str]] = set()
    sources = {name for name, host in hosts.items() if host.kind == "attacker"}
    if not isinstance(path, dict):
        return accounts, sources
    start = path.get("start")
    if isinstance(start, dict) and isinstance(start.get("host"), str):
        sources.add(start["host"])
    for step in path.get("steps") or []:
        if not isinstance(step, dict):
            continue
        if isinstance(step.get("host"), str) and isinstance(step.get("account"), str):
            accounts.add((step["host"], step["account"]))
        args = step.get("args")
        for value in args.values() if isinstance(args, dict) else []:
            accounts |= {(host, account) for account, host in AT_HOST.findall(str(value)) if host in hosts}
    return accounts, sources


def parse(value: object, hosts: dict[str, Host], path: object = None, watch: Watch | None = None) -> Activity:
    """The spec's `activity`, with the rules that tie its jobs to the hosts and keep them apart from the path.

    `path` is the spec's path section as read, and `watch` what every agent collects.
    """

    watch = watch or Watch()
    if not isinstance(value, dict):
        raise SpecError(
            "activity must be a mapping with the keys seed, warmup_seconds, tail_seconds and jobs"
        )
    keys = {"seed", "warmup_seconds", "tail_seconds", "jobs"}
    unknown = sorted(str(key) for key in value if key not in keys)
    if unknown:
        raise SpecError(f"activity has unknown keys: {', '.join(unknown)}")
    missing = sorted(keys - set(value))
    if missing:
        raise SpecError(f"activity lacks: {', '.join(missing)}")
    seed = value["seed"]
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise SpecError("activity.seed must be a whole number: the waits between runs are drawn from it")
    warmup = _seconds(value["warmup_seconds"], "activity.warmup_seconds")
    tail = _seconds(value["tail_seconds"], "activity.tail_seconds")
    if not isinstance(value["jobs"], list) or not value["jobs"]:
        raise SpecError("activity.jobs must list at least one job")
    accounts, sources = path_uses(path, hosts)
    jobs: list[Job] = []
    for entry in value["jobs"]:
        job = _job(entry, hosts, accounts, sources, watch)
        if job.name in {j.name for j in jobs}:
            raise SpecError(f"activity lists the job {job.name} twice")
        jobs.append(job)
    _apart(jobs)
    return Activity(seed, warmup, tail, tuple(jobs))


def _apart(jobs: list[Job]) -> None:
    """Refuse two jobs whose lines in the logs they are counted from cannot be told apart.

    A cron job's lines carry its own tag. An http job's requests are told
    apart by the host they come from, the server and the path; an ssh job's
    lines in sshd's and snoopy's logs only by the host it comes from and the
    one it logs in to, and PAM's and sudo's lines of its session only by the
    account it logs in as; a file integrity event by the files a job writes.
    """

    for number, first in enumerate(jobs):
        for second in jobs[number + 1 :]:
            both = f"activity: jobs {first.name} and {second.name}"
            if first.acts_on == second.acts_on:
                for mine in first.writes:
                    theirs = [w for w in second.writes if _overlap(mine, w)]
                    if theirs:
                        raise SpecError(
                            f"{both} both write files of {mine} and "
                            f"{theirs[0]} on {first.acts_on}: a file integrity event is counted for a job by "
                            "the files it writes, so two jobs on one host may not write the same files"
                        )
            if first.do == second.do and (first.host, first.target) == (second.host, second.target):
                if first.do == "http":
                    shared = [path for path in first.paths if path in second.paths]
                    if shared:
                        raise SpecError(
                            f"{both} both fetch {shared[0]} of {first.target} from {first.host}: a request "
                            "is counted for a job by the host it comes from and its path, so two such jobs "
                            "may not share a path"
                        )
                elif first.do == "ssh":
                    raise SpecError(
                        f"{both} both log in to {first.target} from {first.host}: sshd's lines name the "
                        "host a login comes from, not the job, so only one ssh job may go from one host to "
                        "another"
                    )
            account = _acts_as(first)
            if (
                first.acts_on == second.acts_on
                and "ssh" in (first.do, second.do)
                and account is not None
                and account == _acts_as(second)
            ):
                raise SpecError(
                    f"{both} both act as {account} on {first.acts_on}: PAM's, sudo's and cron's lines name "
                    "the account, not the job, so the account an ssh job logs in as may not be another "
                    "job's account on that host"
                )


def _acts_as(job: Job) -> str | None:
    """The account that the lines of a job's sessions name on the host it acts on.

    An ssh job's is the account it logs in as, a cron job's its own. An http
    job opens no session there.
    """

    if job.do == "ssh":
        return job.target_account
    return job.account if job.do == "cron" else None


def _job(entry: object, hosts: dict[str, Host], accounts: set, sources: set[str], watch: Watch) -> Job:
    if not isinstance(entry, dict):
        raise SpecError("each job of activity.jobs must be a mapping")
    name = entry.get("name")
    if not isinstance(name, str) or not NAME.match(name):
        raise SpecError("a job's name must be lower-case letters, digits and single hyphens")
    where = f"activity: job {name}"
    allowed = {"name", "host", "account", "every", "do", "target", "paths", "run", "writes"}
    unknown = sorted(str(key) for key in entry if key not in allowed)
    if unknown:
        raise SpecError(f"{where} has unknown keys: {', '.join(unknown)}")
    missing = sorted({"host", "account", "every", "do"} - set(entry))
    if missing:
        raise SpecError(f"{where} lacks: {', '.join(missing)}")
    do = entry["do"]
    if do not in KINDS:
        raise SpecError(f"{where}: do must be one of {', '.join(KINDS)}")
    wanted = {"http": {"target", "paths"}, "ssh": {"target", "run"}, "cron": {"run"}}[do]
    for key in sorted({"target", "paths", "run"} - wanted):
        if key in entry:
            raise SpecError(f"{where}: a job that does {do} takes no {key}")
    for key in sorted(wanted - set(entry)):
        raise SpecError(f"{where}: a job that does {do} needs {key}")

    host = entry["host"]
    if host not in hosts:
        raise SpecError(f"{where} runs on {host}, which hosts does not declare")
    settings = hosts[host]
    if host in sources:
        raise SpecError(
            f"{where} runs on {host}, whose address the path comes from: the score tells the path from "
            "ordinary activity by address, so no job may use it"
        )
    if not settings.built or settings.kind == "defense":
        raise SpecError(f"{where} runs on {host}, which is not built from base, so it cannot carry the job")
    account = entry["account"]
    if not isinstance(account, str) or account not in settings.account_names:
        raise SpecError(
            f"{where}: {account!r} is not an account of host {host}; it has {', '.join(settings.account_names)}"
        )
    _not_the_paths(where, host, account, accounts)
    every = _every(entry["every"], where, do)

    target = target_account = identity = None
    paths: tuple[str, ...] = ()
    run = entry.get("run")
    if run is not None and (not isinstance(run, str) or not run.strip() or "\n" in run):
        raise SpecError(f"{where}: run must be a command on one line")
    if do == "cron":
        if "cron" not in settings.services:
            raise SpecError(f"{where} is a cron job, and host {host} does not run cron")
        acts_on = settings
    else:
        if do == "http":
            target = entry["target"]
            if not isinstance(target, str) or target not in hosts:
                raise SpecError(f"{where}: target must be a host of the spec")
            _not_a_source(where, target, sources)
            if "curl" not in settings.packages:
                raise SpecError(f"{where} fetches pages with curl, so host {host} needs the package curl")
            if "nginx" not in hosts[target].services:
                raise SpecError(f"{where}: target {target} runs no nginx")
            if NGINX_ACCESS not in {log.path for log in watch.merged(hosts[target].watch).logs}:
                raise SpecError(
                    f"{where}: its runs are counted from {NGINX_ACCESS} on {target}, which no agent collects"
                )
            paths = tuple(entry["paths"]) if isinstance(entry["paths"], list) else ()
            if not paths or not all(isinstance(p, str) and URL_PATH.match(p) for p in paths):
                raise SpecError(f"{where}: paths must list paths of the web server, as in /?item=1")
        else:
            if not isinstance(entry["target"], str) or entry["target"].count("@") != 1:
                raise SpecError(f"{where}: target must be <account>@<host>, as in ops@web")
            target_account, _, target = entry["target"].partition("@")
            if not ACCOUNT.match(target_account) or target not in hosts:
                raise SpecError(f"{where}: target must be <account>@<host> of a host of the spec")
            _not_a_source(where, target, sources)
            _not_the_paths(where, target, target_account, accounts)
            other = hosts[target]
            if "sshd" not in other.services or target_account not in other.account_names:
                raise SpecError(
                    f"{where}: {entry['target']} is not an account that host {target} logs in over SSH"
                )
            if "openssh-client" not in settings.packages:
                raise SpecError(f"{where} logs in with ssh, so host {host} needs the package openssh-client")
            if not any(account == known.account and target in known.hosts for known in settings.known_hosts):
                raise SpecError(f"{where}: {account} on {host} has no known_hosts entry for {target}")
            accepted = {
                key.name
                for other_host in hosts.values()
                for key in other_host.keys
                if key.authorized == (target_account, target)
            }
            files = [
                key.file_name for key in settings.keys if key.private == account and key.name in accepted
            ]
            if not files:
                raise SpecError(
                    f"{where}: {account} on {host} holds no key that {target_account}@{target} accepts"
                )
            identity = f"{home(account)}/.ssh/{files[0]}"
        if not set(settings.networks) & set(hosts[target].networks):
            raise SpecError(f"{where}: {host} shares no network with {target}")
        acts_on = hosts[target]
    if not acts_on.agent:
        raise SpecError(
            f"{where} acts on {acts_on.name}, which has no agent: a job's runs and events are counted from "
            "the logs of the watched host it acts on"
        )
    writes = entry.get("writes", [])
    if not isinstance(writes, list) or not all(isinstance(w, str) and WRITES.match(w) for w in writes):
        raise SpecError(
            f"{where}: writes must list absolute paths, with * for any part, as in /tmp/cache-*.json"
        )
    return Job(name, host, account, every, do, target, target_account, paths, run, tuple(writes), identity)


@cache
def _overlap(first: str, second: str) -> bool:
    """Whether a path matches both patterns, where * stands for any text, as in `writes`."""

    if not first or not second:
        return first.strip("*") == second.strip("*") == ""
    if first[0] == "*":
        return _overlap(first[1:], second) or _overlap(first, second[1:])
    if second[0] == "*":
        return _overlap(first, second[1:]) or _overlap(first[1:], second)
    return first[0] == second[0] and _overlap(first[1:], second[1:])


def _not_a_source(where: str, target: str, sources: set[str]) -> None:
    if target in sources:
        raise SpecError(f"{where} reaches {target}, whose address the path comes from")


def _not_the_paths(where: str, host: str, account: str, accounts: set[tuple[str, str]]) -> None:
    """Refuse an account the path uses: on that host, or, other than root, by its name on any host."""

    names = {name for _, name in accounts if name != "root"}
    if (host, account) in accounts or account in names:
        raise SpecError(
            f"{where} uses the account {account} on {host}, which the path uses: the score tells the "
            "path from ordinary activity by account, so no job may use it"
        )


def _every(value: object, where: str, do: str) -> tuple[int, int]:
    if isinstance(value, list) and len(value) == 2:
        low, high = value
    else:
        low = high = value
    for number in (low, high):
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= LONGEST:
            raise SpecError(
                f"{where}: every must be a number of seconds from 1 to {LONGEST}, or [shortest, longest]"
            )
    if low > high:
        raise SpecError(f"{where}: every is [shortest, longest], and {low} is more than {high}")
    if do == "cron" and (low % 60 or high % 60):
        raise SpecError(f"{where}: cron starts a job at most once a minute, so every must be whole minutes")
    return low, high


# The schedule


def draw(seed: int, job: Job, number: int) -> int:
    """The wait after a job's run `number`, in seconds: the same seed gives the same wait.

    A cron job waits whole minutes, since cron starts it once a minute.
    """

    unit = 60 if job.do == "cron" else 1
    low, high = job.every[0] // unit, job.every[1] // unit
    digest = hashlib.sha256(f"{seed}:{job.name}:{number}".encode()).digest()
    return (low + int.from_bytes(digest[:8], "big") % (high - low + 1)) * unit


def waits(activity: Activity, job: Job) -> list[int]:
    """A job's waits for the first hour, in seconds. A job that runs longer starts them again."""

    found: list[int] = []
    while sum(found) < HORIZON:
        found.append(draw(activity.seed, job, len(found)))
    return found


def schedule(activity: Activity) -> dict:
    """The schedule, for the manifest."""

    return {
        job.name: {
            "host": job.host,
            "account": job.account,
            "do": job.do,
            "target": f"{job.target_account}@{job.target}" if job.target_account else job.target,
            "every": list(job.every),
            "tag": job.tag,
            "first run": "when cron next starts it after the go"
            if job.do == "cron"
            else "within a second of the go",
            "waits": waits(activity, job),
        }
        for job in activity.jobs
    }


# The files in the images


def cron_entry(job: Job) -> str:
    return (
        f"# Job {job.name} of the range's ordinary activity, rendered by bluefire-lab from the spec.\n"
        "# Cron starts its script every minute; the script runs the job only after the engine's go,\n"
        "# and then each time its next wait is over.\n"
        "SHELL=/bin/sh\n"
        f"BLUEFIRE_TAG={job.tag}\n"
        f"* * * * * {job.account} test -e {GO} || exit 0; exec {LIB}/job-{job.name}\n"
    )


def cron_script(activity: Activity, job: Job) -> str:
    minutes = " ".join(str(wait // 60) for wait in waits(activity, job))
    state = f"{STATE}/job-{job.name}"
    return f"""\
#!/bin/bash
# Job {job.name} of the range's ordinary activity, rendered by bluefire-lab from the spec:
# as {job.account}, every {_every_words(job)}, it runs: {job.run}
# It runs only after the engine has written {GO}. The waits, in minutes, are drawn
# from the spec's seed. Until the job is due the script starts no program, so a minute
# when it is not due leaves nothing in snoopy's log but cron's start of the script.
test -e {GO} || exit 0
export BLUEFIRE_TAG={job.tag}
waits=({minutes})
n=0
next=0
if [ -e {state}/state ]; then read -r n next < {state}/state; fi
minute=$((EPOCHSECONDS / 60))
((minute >= next)) || exit 0
printf '%s %s\\n' "$((n + 1))" "$((minute + waits[n % ${{#waits[@]}}]))" > {state}/state
/bin/bash -c {shlex.quote(job.run)} > {state}/output 2>&1
"""


def _every_words(job: Job) -> str:
    low, high = job.every
    return f"{low} s" if low == high else f"{low} to {high} s"


def _once(job: Job) -> str:
    if job.do == "http":
        return f'curl -s -o /dev/null --max-time 20 "http://{job.target}${{paths[$1 % ${{#paths[@]}}]}}"'
    remote = shlex.quote(f"export BLUEFIRE_TAG={job.tag}; {job.run}")
    # The key the loader found that the target accepts, and no other identity, whatever its file is called.
    return (
        "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes "
        f"-i {shlex.quote(job.identity or '')} {job.target_account}@{job.target} {remote} < /dev/null"
    )


def loop_script(activity: Activity, host: str) -> str | None:
    """The loop script of a host's http and ssh jobs, or None when it has none."""

    jobs = [job for job in activity.on(host) if job.do != "cron"]
    if not jobs:
        return None
    lines = [
        "#!/bin/bash",
        f"# The http and ssh jobs of the ordinary activity of {host}, whose waits are in seconds, rendered by",
        "# bluefire-lab from the range's spec. The host's start script runs `activity <job>` once for",
        f"# each job, as the job's account. A job runs only while {GO} exists: at once",
        "# when the engine writes it, then again after each wait, in seconds, drawn from the spec's seed.",
        "set -u",
        'case "${1:-}" in',
    ]
    for job in jobs:
        what = (
            f"pages of {job.target}" if job.do == "http" else f"logs in to {job.target_account}@{job.target}"
        )
        lines += [
            f"{job.name})",
            f"  # {job.do}: {what}, as {job.account}, every {_every_words(job)}.",
            f"  export BLUEFIRE_TAG={job.tag}",
            f"  waits=({' '.join(str(wait) for wait in waits(activity, job))})",
        ]
        if job.paths:
            lines.append(f"  paths=({' '.join(shlex.quote(path) for path in job.paths)})")
        lines += [f"  once() {{ {_once(job)}; }}", "  ;;"]
    lines += [
        "*)",
        '  echo "usage: activity <job>" >&2',
        "  exit 2",
        "  ;;",
        "esac",
        "# A wait that starts no program: a read with a time limit on a pipe nothing writes to.",
        "exec {pause}<> <(:)",
        'nap() { read -r -t "$1" -u "$pause" _ || true; }',
        f"state={STATE}/job-$1",
        "n=0",
        "while :; do",
        f"  test -e {GO} || {{ nap 1; continue; }}",
        '  once "$n" > "$state/output" 2>&1',
        '  printf \'%s\\n\' "$((n + 1))" > "$state/runs"',
        '  nap "${waits[n % ${#waits[@]}]}"',
        "  n=$((n + 1))",
        "done",
    ]
    return "\n".join(lines) + "\n"


def start_lines(activity: Activity | None, host: str) -> list[str]:
    """The lines of a host's start script for its jobs: each job's state folder, then each loop.

    Every account of a host built from base has a group of its own name.
    """

    jobs = activity.on(host) if activity else []
    if not jobs:
        return []
    lines = [
        "# The ordinary activity: a folder for each job's state, and the loop of each job cron does not start."
    ]
    lines += [f"install -d -o {job.account} -g {job.account} -m 0700 {STATE}/job-{job.name}" for job in jobs]
    lines += [
        f"su -s /bin/bash -c {shlex.quote(f'{LOOP} {job.name}')} {job.account} > /dev/null 2>&1 &"
        for job in jobs
        if job.do != "cron"
    ]
    return lines


def files(activity: Activity | None, host: str) -> dict[str, bytes]:
    """The files of the build context that one host's stage copies for its jobs."""

    if activity is None:
        return {}
    found = {}
    for job in activity.on(host):
        if job.do == "cron":
            found[f"files/{host}/cron-{job.name}"] = cron_entry(job).encode()
            found[f"files/{host}/job-{job.name}"] = cron_script(activity, job).encode()
    loop = loop_script(activity, host)
    if loop:
        found[f"files/{host}/activity"] = loop.encode()
    return found


def dockerfile_lines(activity: Activity | None, host: str) -> list[str]:
    """The lines of one host's stage that copy its jobs in."""

    if activity is None or not activity.on(host):
        return []
    lines = [f"# The ordinary activity's jobs on this host: {', '.join(j.name for j in activity.on(host))}."]
    for job in activity.on(host):
        if job.do == "cron":
            lines += [
                f"COPY --chmod=0755 files/{host}/job-{job.name} {LIB}/job-{job.name}",
                f"COPY --chmod=0644 files/{host}/cron-{job.name} /etc/cron.d/bluefire-{job.name}",
            ]
    if loop_script(activity, host):
        lines.append(f"COPY --chmod=0755 files/{host}/activity {LOOP}")
    return lines


# Counting what the jobs did, from the files copied out of the range


def _iso(text: str) -> float | None:
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _nginx_time(text: str) -> float | None:
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


def counted_from(job: Job) -> tuple[str, str]:
    """The host and log whose lines show each run of a job."""

    if job.do == "cron":
        return job.host, SNOOPY_LOG
    if job.do == "http":
        return job.target, NGINX_ACCESS
    return job.target, AUTH_LOG


def runs(job: Job, lines: list[str], addresses: list[str], start: float, end: float) -> int:
    """How many times a job ran between the go and the stop, by the lines of the log it is counted from.

    A cron job: snoopy's line of the run's own program start, with the job's tag.
    An http job: an access log line from the job's host for one of the job's
    paths (nginx logs whole seconds, so the go is taken down to its second). An ssh job: sshd's
    accepted key login of the target account from the job's host.
    """

    accepted = re.compile(
        rf"(\S+) \S+ sshd\[[0-9]+\]: Accepted publickey for {re.escape(job.target_account or '')} "
        rf"from (\S+) port "
    )
    if job.do == "http":
        start = math.floor(start)
    count = 0
    for line in lines:
        when = None
        if job.do == "cron":
            found = SNOOPY.match(line)
            if found and found.group(2) == job.tag and found.group(3) == job.command:
                when = _iso(found.group(1))
        elif job.do == "http":
            found = NGINX.match(line)
            if found and found.group(1) in addresses and _requested(line) in job.paths:
                when = _nginx_time(found.group(2))
        else:
            found = accepted.match(line)
            if found and found.group(2) in addresses:
                when = _iso(found.group(1))
        if when is not None and start <= when <= end:
            count += 1
    return count


def _requested(line: str) -> str | None:
    """The path an nginx line's request asks for, or None when the line names no request."""

    found = REQUEST.search(line)
    return found.group(1) if found else None


def event_time(event: dict) -> float | None:
    """When an archive event happened: rsyslog's time on the line when it has one, else the manager's."""

    stamp = (event.get("predecoder") or {}).get("timestamp")
    if stamp:
        found = _iso(stamp)
        if found is not None:
            return found
    try:
        return wazuh.timestamp(event.get("timestamp", ""))
    except ValueError:
        return None


def _names(account: str) -> re.Pattern:
    """Lines of auth.log that name an account as the one logging in, starting a session or using sudo."""

    name = re.escape(account)
    return re.compile(
        rf"(?:\bfor user {name}\b|\bfor {name} from |\bby {name}\(|sudo(?:\[[0-9]+\])?:\s+{name} : )"
    )


SUDO_OPENED = re.compile(r"pam_unix\(sudo:session\): session opened for user ")
SUDO_CLOSED = re.compile(r"pam_unix\(sudo:session\): session closed for user ")
CRON_SESSION = re.compile(r"\(cron:session\): session (?:opened|closed) for user ([a-z_][a-z0-9_-]*)\b")
# A sudo session's close names neither the account nor the address, so it is the job's when it comes this
# many seconds at most after a sudo session the job opened.
SUDO_PAIR = 2
# The source `attribute` gives a cron session line of a cron job's account.
CRON_SESSION_SOURCE = "cron session of the account"


def cron_session(job: Job, event: dict) -> bool:
    """True for cron's session line of a cron job's account on the job's host.

    Cron opens one for each entry of the account every minute, the job's own
    gate included, so the line does not tell one entry of the account from another.
    """

    session = CRON_SESSION.search(event.get("full_log") or "")
    return (
        job.do == "cron"
        and session is not None
        and session.group(1) == job.account
        and event.get("location") == AUTH_LOG
        and (event.get("agent") or {}).get("name") == job.host
    )


def source(job: Job, event: dict, addresses: list[str]) -> str | None:
    """The source by which an archive event is the job's, or None when it is not.

    Cron's session lines are not any one job's: cron opens one for every entry
    of an account each minute, the job's own before the go too, and for root's
    stock entries; `count` counts them apart.
    """

    if (event.get("agent") or {}).get("name") != job.acts_on:
        return None
    location = event.get("location") or ""
    data = event.get("data") or {}
    log = event.get("full_log") or ""
    if location == SNOOPY_LOG and data.get("tag") == job.tag:
        return "snoopy, by tag"
    if job.do == "ssh" and location == SNOOPY_LOG:
        # The remote shell itself, started before the command sets the tag: by the SSH connection it runs in.
        if (data.get("ssh") or "").split(" ")[0] in addresses:
            return "snoopy, by address"
        # sshd's own programs of the login (the motd scripts), and those that sudo starts without the
        # tag, run in a session of the target account, which the path never uses.
        if data.get("login") == job.target_account:
            return "snoopy, by account"
    if location == "syscheck":
        path = (event.get("syscheck") or {}).get("path") or ""
        if path.rsplit("/", 1)[-1].startswith(ENGINE_MARK):
            return None
        return "file integrity, by folder" if any(fnmatch(path, pattern) for pattern in job.writes) else None
    if job.do == "http" and location.startswith("/var/log/nginx/") and _requested(log) in job.paths:
        if data.get("srcip") in addresses or any(f"client: {a}," in log for a in addresses):
            return f"{location}, by address"
    if job.do == "ssh" and location == AUTH_LOG:
        if data.get("srcip") in addresses or any(f" {a} port " in log for a in addresses):
            return f"{location}, by address"
        if _names(job.target_account).search(log):
            return f"{location}, by account"
    return None


def written_before(event: dict, start: float) -> bool:
    """True for a file integrity event of a file added or changed before `start`, by the file's own time.

    A file integrity event has no time of its source, and the manager's can
    come seconds after the write: the file's modification time, to the second
    and in UTC as the containers keep it, tells a file the engine's plant
    checks made just before the go from a job's.
    """

    syscheck = event.get("syscheck") or {}
    if event.get("location") != "syscheck" or syscheck.get("event") not in ("added", "modified"):
        return False
    try:
        moment = datetime.fromisoformat(str(syscheck.get("mtime_after")))
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp() < math.floor(start)


def attribute(
    activity: Activity,
    events: list[dict],
    addresses: dict[str, list[str]],
    go: dict[str, float],
    stop: dict[str, float],
) -> dict[int, tuple[str, str]]:
    """The events that are a job's: for the index of each in `events`, the job's name and the source.

    An event is the first job's whose rules (`source`) it meets, from the go
    of the job's host to `GRACE` seconds after its stop, taken in the order of
    the events' times, and never a file written before the go (`written_before`);
    a sudo session's close is the job's that opened a sudo session just before
    it. Cron's session line of a cron job's account in
    that window gets the source `CRON_SESSION_SOURCE`.
    """

    found: dict[int, tuple[str, str]] = {}
    timed = sorted(
        (
            (when, index, event)
            for index, event in enumerate(events)
            if (when := event_time(event)) is not None
        ),
        key=lambda item: item[0],
    )
    sudo_opened: dict[str, float] = {}
    for when, index, event in timed:
        log = event.get("full_log") or ""
        for job in activity.jobs:
            start, end = go.get(job.host), stop.get(job.host, math.inf)
            if start is None or not start <= when <= end + GRACE or written_before(event, start):
                continue
            how = source(job, event, addresses.get(job.host, []))
            if how is None and job.do == "ssh" and SUDO_CLOSED.search(log):
                if (event.get("agent") or {}).get("name") == job.acts_on and job.name in sudo_opened:
                    if when - sudo_opened.pop(job.name) <= SUDO_PAIR:
                        how = f"{AUTH_LOG}, by the sudo session it closes"
            if how:
                if SUDO_OPENED.search(log):
                    sudo_opened[job.name] = when
                found[index] = (job.name, how)
                break
            if cron_session(job, event):
                found[index] = (job.name, CRON_SESSION_SOURCE)
                break
    return found


def count(
    activity: Activity,
    logs: dict[tuple[str, str], list[str] | None],
    events: list[dict],
    addresses: dict[str, list[str]],
    go: dict[str, float],
    stop: dict[str, float],
) -> dict:
    """Each job's runs and its events in the archive, between the go and the stop of its host.

    `logs` holds the copied lines of each (host, log) that `counted_from`
    names, `addresses` each host's addresses in the range. The events are
    sorted to jobs by `attribute`. "archived runs" counts the runs again, from
    the lines of the same log that reached the archive: the proof that a run
    itself was seen. Cron's session lines of a cron job's account are counted
    apart, since they do not tell one entry of the account from another.
    """

    found = {}
    timed = sorted(
        ((when, event) for event in events if (when := event_time(event)) is not None),
        key=lambda pair: pair[0],
    )
    for job in activity.jobs:
        start, end = go.get(job.host), stop.get(job.host, math.inf)
        host, log = counted_from(job)
        lines = logs.get((host, log))
        entry: dict = {
            "host": job.host,
            "account": job.account,
            "do": job.do,
            "runs": None,
            "runs counted from": f"{host}: {log}",
            "archived runs": None,
            "archive events": 0,
            "archive events by source": {},
        }
        if job.do == "cron":
            entry["cron sessions of the account"] = 0
        if start is None:
            entry["not counted"] = "the engine did not write the go on its host"
        elif lines is None:
            entry["not counted"] = f"{log} was not copied out of {host}"
        else:
            own = addresses.get(job.host, [])
            entry["runs"] = runs(job, lines, own, start, end)
            archived = [
                event.get("full_log") or ""
                for _, event in timed
                if (event.get("agent") or {}).get("name") == host and event.get("location") == log
            ]
            entry["archived runs"] = runs(job, archived, own, start, end)
        found[job.name] = entry
    for name, how in attribute(activity, events, addresses, go, stop).values():
        entry = found[name]
        if how == CRON_SESSION_SOURCE:
            entry["cron sessions of the account"] += 1
            continue
        entry["archive events"] += 1
        entry["archive events by source"][how] = entry["archive events by source"].get(how, 0) + 1
    return found


def started(go: dict[str, float]) -> str | None:
    if not go:
        return None
    return datetime.fromtimestamp(min(go.values()), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def minutes(go: dict[str, float], stop: dict[str, float]) -> float | None:
    """The minutes from the first go to the last stop."""

    if not go or not stop:
        return None
    return round((max(stop.values()) - min(go.values())) / 60, 2)


def summary(manifest: dict) -> str:
    """The ordinary activity of a run as Markdown, for a CI job's summary."""

    record = manifest.get("activity") or {}
    jobs = record.get("jobs") or {}
    seen = bool(jobs) and all(
        (j.get("runs") or 0) >= 1 and (j.get("archived runs") or 0) >= 1 for j in jobs.values()
    )
    title = (
        "every job ran and a run of each reached the archive"
        if seen
        else "NOT every job ran and had a run reach the archive"
    )
    if not jobs:
        title = "not counted"
    lines = [f"### Ordinary activity of {manifest.get('range')}: {title}", ""]
    lines += [
        f"From the first go to the last stop: {record.get('minutes')} minutes, started "
        f"{record.get('started')}, warm-up {record.get('warmup_seconds')} s, tail {record.get('tail_seconds')} s, "
        f"seed {record.get('seed')}.",
        "",
    ]
    schedule_ = record.get("schedule") or {}
    if jobs:
        lines += [
            "| Job | Host | Account | Does | Every (s) | Runs | Runs counted from | Archived runs | Archive events "
            "| By source | Cron sessions of the account |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for name, entry in jobs.items():
            plan = schedule_.get(name) or {}
            low, high = (plan.get("every") or [None, None])[:2]
            every = f"{low}" if low == high else f"{low} to {high}"
            does = entry["do"] + (f" to {plan['target']}" if plan.get("target") else "")
            runs_ = entry["runs"] if entry["runs"] is not None else f"not counted: {entry.get('not counted')}"
            sources = ", ".join(f"{k} {v}" for k, v in entry["archive events by source"].items())
            sessions = entry.get("cron sessions of the account", "")
            lines.append(
                f"| {name} | {entry['host']} | {entry['account']} | {does} | {every} | {runs_} | "
                f"{entry['runs counted from']} | {entry.get('archived runs')} | {entry['archive events']} | "
                f"{sources} | {sessions} |"
            )
        lines += [
            "",
            "Archived runs are the runs again, from the lines of the same log that reached the manager's "
            "archive. Cron opens a session for every cron entry of an account each minute, before the go "
            "and after the stop too, so its session lines are counted apart and not as any one job's.",
        ]
        lines.append("")
    return "\n".join(lines)

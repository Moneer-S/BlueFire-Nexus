"""Render the images of a range from its spec: one multi-stage Dockerfile and a bake file.

The build context holds the Dockerfile, `bake.json` and the few files the
images copy in. Every image is tagged `<prefix>-<host>:<hash>`, where the hash
is the SHA-256 of the build context (without `bake.json`, which holds the
tags), first 16 hex digits: the same spec gives the same tags, and a changed
spec, or a change in what the lab renders from it, gives new ones. A host with
an image pinned in the spec is not built.

Stages:

- `ubuntu`: the pinned base image, with the certificate store (ca-certificates
  and the openssl it needs) from the live archive of the build day, and then
  every other package from the pinned APT snapshot. The live packages are not
  part of the tag's hash.
- `fetch`: downloads the pinned Wazuh agent package and checks its SHA-512.
  Nothing of this stage but the package reaches another one.
- `base`: rsyslog, procps, iproute2, snoopy and the Wazuh agent. The agent's
  stock ossec.conf is kept beside the one the range runs, as ossec.conf.stock.
- `keys`: makes every SSH key the spec plants: an ed25519 host key for each
  host that runs sshd, and each named key pair. They are lab keys with no
  value outside the range. It also writes each account's authorized_keys and
  known_hosts, which the hosts copy. The keys are made when the stage is
  first built and then kept by the build cache, the GitHub Actions cache of
  CI included: ranges built from the same keys stage share them. inet's
  certificate is kept the same way.
- `conf`: runs `ossec.py` (the lab's edits of the stock ossec.conf) with the
  Python inside the pinned manager image, for the manager and every agent.
- `host-<name>`: one per host built from base, with its packages, then what
  the spec plants in it (accounts, sshd settings, keys, known hosts, folders,
  files, the database, served files, the published `src` folders it carries),
  the jobs of the ordinary activity that run on it (see `activity`), its
  ossec.conf, its start script and, last, snoopy in /etc/ld.so.preload.
  No step runs published text: the published files are copied in as data.
- `host-<manager>`: the pinned manager image, with the lab's configuration
  under /wazuh-config-mount/, which the image's own start copies into
  /var/ossec, and the stock ossec.conf kept as ossec.conf.stock.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import activity, atomics, inet_server, ossec
from .spec import REPOS, Host, Spec, SpecError, home

DOCKERFILE = "Dockerfile"
BAKE = "bake.json"
LABEL_RANGE = "bluefire.lab.range"
SNOOPY_LIBRARY = "/lib/x86_64-linux-gnu/libsnoopy.so"
MANAGER_PYTHON = "/var/ossec/framework/python/bin/python3"
STOCK = "/var/ossec/etc/ossec.conf.stock"
OSSEC_CONF = "/var/ossec/etc/ossec.conf"

# The syslog daemon of a host: the local socket only (a container has no kernel log), and
# rsyslog's default file format, whose timestamps are RFC 3339 to the microsecond.
RSYSLOG_CONF = """\
# The syslog daemon of a range host: the local socket only, since a container
# has no kernel log. Lines keep rsyslog's default file format, which starts
# with an RFC 3339 timestamp to the microsecond.
module(load="imuxsock")

# Program starts logged by snoopy go to a file of their own.
if $programname == "snoopy" then {
    action(type="omfile" file="/var/log/snoopy.log")
    stop
}

auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          /var/log/syslog
"""

# snoopy logs every program start made through the C library's exec calls. The tag is the
# BLUEFIRE_TAG of the process, which the lab sets on everything it runs. snoopy 2.5.1 has no data
# source of its own for the SSH connection, so the line takes it from SSH_CONNECTION. `exe` is the
# file the exec call names, which the command line does not hold: a shell that finds `grep` on its
# search path starts /usr/bin/grep with the command line `grep ...`.
SNOOPY_INI = """\
; snoopy on a range host: one line to syslog for every program start.
[snoopy]
message_format = "[login:%{login} ssh:(%{env:SSH_CONNECTION}) sid:%{sid} uid:%{uid} euid:%{euid} cwd:%{cwd} exe:%{filename} tag:%{env:BLUEFIRE_TAG}]: %{cmdline}"
output = devlog
syslog_ident = snoopy
syslog_facility = AUTHPRIV
syslog_level = INFO
"""

# The lab's one decoder: it reads the fields of a snoopy line. A decoder raises no alert.
SNOOPY_DECODER = """\
<!-- A decoder of the lab's own, for the program starts that snoopy logs on
     the range's hosts. It reads the fields of the line and raises no alert.

     A snoopy line, after the syslog header:
     [login:root ssh:((undefined)) sid:1 uid:0 euid:0 cwd:/ exe:/usr/bin/uname tag:engine:mark]: uname -r
-->
<decoder name="bluefire-snoopy">
  <program_name>^snoopy$</program_name>
</decoder>

<decoder name="bluefire-snoopy-fields">
  <parent>bluefire-snoopy</parent>
  <regex type="pcre2">^\\[login:(\\S*) ssh:\\((.*?)\\) sid:(\\S*) uid:(\\S*) euid:(\\S*) cwd:(.*?) exe:(.*?) tag:(\\S*)\\]: (.*)$</regex>
  <order>login, ssh, sid, uid, euid, cwd, exe, tag, command</order>
</decoder>
"""

LOCAL_INTERNAL_OPTIONS = """\
# Read new agent keys every second instead of every ten, so that the first
# connection of a freshly enrolled agent is accepted at once.
remoted.keyupdate_interval=1
"""

FILEBEAT_DOWN = (
    "# While this file exists, s6 does not start the image's Filebeat: the range has no indexer.\n"
)

# The image's API listens on every address by default. The range uses no API, and the hosts that
# share mgmt with the manager must not reach it, so it listens on loopback only.
WAZUH_API = """\
# The Wazuh API of a range's manager, rendered by bluefire-lab: loopback only.
host: ['127.0.0.1']
"""
WAZUH_API_FILE = "/var/ossec/api/configuration/api.yaml"

# The manager's files other than ossec.conf, and what each one changes.
MANAGER_FILES = (
    {
        "label": ossec.LAB,
        "file": "/var/ossec/etc/decoders/bluefire_snoopy.xml",
        "change": "the lab's decoder for snoopy's lines; it reads fields and raises no alert",
    },
    {
        "label": ossec.STARTUP,
        "file": "/var/ossec/etc/local_internal_options.conf",
        "change": "remoted.keyupdate_interval=1: a newly enrolled agent's key is read within a second",
    },
    {
        "label": ossec.REMOVED,
        "file": "/etc/services.d/filebeat/down",
        "change": "Filebeat, which forwards alerts to an indexer, does not start: the range has no indexer",
    },
    {
        "label": ossec.REMOVED,
        "file": WAZUH_API_FILE,
        "change": "the Wazuh API listens on 127.0.0.1 only: the range uses no API, and no other host reaches it",
    },
)


# The shop's web server: nginx serves this folder and hands PHP pages to php-fpm, whose socket is
# the one of Ubuntu noble's PHP 8.3.
NGINX_ROOT = "/var/www/app"
NGINX_SITE = f"""\
# The range's web site, rendered by bluefire-lab: the folder {NGINX_ROOT}, with its
# PHP pages run by php-fpm.
server {{
    listen 80 default_server;
    root {NGINX_ROOT};
    index index.php;
    location / {{
        try_files $uri $uri/ =404;
    }}
    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }}
}}
"""
# The stand-in internet's server and what it reads and writes.
INET_SERVER = "/usr/local/sbin/inet-server"
INET_TREE = "/srv/www"
INET_UPLOADS = "/srv/uploads"
INET_LOG = "/var/log/inet/access.log"
INET_CERT = "/etc/inet/cert.pem"
INET_KEY = "/etc/inet/key.pem"
# A packet capture asked for by a host stays inside that host until collection. One file is written
# for each of its range interfaces. The Wazuh manager's ports are the defense's own channel, not the
# shop traffic the packet sensor records.
CAPTURE_DIR = "/var/log/bluefire/packets"
CAPTURE_RUN = "/run/bluefire/packets"
CAPTURE_ARMED_SUFFIX = ".armed"
CAPTURE_STATUS_SUFFIX = ".status"
CAPTURE_FILTER = "not (port 1514 or port 1515)"
HOST_KEY = "/etc/ssh/ssh_host_ed25519_key"
COMMIT_FILE = f"{atomics.ATOMICS_PATH}/COMMIT"
LICENSE_IN_CONTEXT = f"atomics/{atomics.LICENSE}"
# A fixed date for the commit of a planted repository, so that the same spec gives the same commit.
REPO_DATE = "2026-11-20T00:00:00Z"
RSA_BITS = 3072


@dataclass(frozen=True)
class Rendered:
    folder: Path
    digest: str
    tags: dict[str, str]


def start_script(spec: Spec, host: str) -> str:
    """The entrypoint of a host built from base: capture, services, its agent, then sleep."""

    settings = spec.hosts[host]
    services = settings.services
    lines = [
        "#!/bin/sh",
        "# Starts this range host without an init system: the syslog daemon first, so",
        "# that nothing the others log is lost, then the host's services and its agent.",
        "set -eu",
        "mkdir -p /run/bluefire",
        "rsyslogd",
    ]
    if settings.capture == "packets":
        lines += [
            f"install -d -m 0750 -o tcpdump -g tcpdump {CAPTURE_DIR}",
            f"install -d -m 0755 {CAPTURE_RUN}",
            "for path in /sys/class/net/*; do",
            '  iface=${path##*/}; [ "$iface" = lo ] && continue',
            f'  armed_file="{CAPTURE_RUN}/$iface{CAPTURE_ARMED_SUFFIX}"',
            f'  pid_file="{CAPTURE_RUN}/$iface.pid"',
            f'  status_file="{CAPTURE_RUN}/$iface{CAPTURE_STATUS_SUFFIX}"',
            '  rm -f "$armed_file" "$armed_file.partial" "$pid_file" "$pid_file.partial" '
            '"$status_file" "$status_file.partial"',
            "  (",
            "    child=",
            "    stopping=0",
            '    forward_term() { stopping=1; [ -z "$child" ] || kill -TERM "$child" 2>/dev/null || :; }',
            '    forward_int() { stopping=1; [ -z "$child" ] || kill -INT "$child" 2>/dev/null || :; }',
            "    trap forward_term TERM",
            "    trap forward_int INT",
            '    if [ "$stopping" -ne 0 ]; then',
            '      printf "125\\n" > "$status_file.partial"',
            '      mv "$status_file.partial" "$status_file"',
            "      exit 125",
            "    fi",
            f'    tcpdump -i "$iface" -p -nn -s 0 -U -Z tcpdump -w "{CAPTURE_DIR}/$iface.pcap" '
            f"'{CAPTURE_FILTER}' 2> \"{CAPTURE_DIR}/$iface.log\" &",
            "    child=$!",
            '    if [ "$stopping" -ne 0 ]; then',
            '      kill -TERM "$child" 2>/dev/null || :',
            "      set +e",
            '      wait "$child"',
            '      printf "125\\n" > "$status_file.partial"',
            '      mv "$status_file.partial" "$status_file"',
            "      exit 125",
            "    fi",
            '    if ! printf "%s\\n" "$child" > "$armed_file.partial" '
            '|| ! mv "$armed_file.partial" "$armed_file"; then',
            '      kill -TERM "$child" 2>/dev/null || :',
            "      set +e",
            '      wait "$child"',
            '      printf "125\\n" > "$status_file.partial"',
            '      mv "$status_file.partial" "$status_file"',
            "      exit 125",
            "    fi",
            "    set +e",
            '    wait "$child"',
            "    code=$?",
            '    if [ "$code" -ge 128 ]; then',
            '      wait "$child"',
            "      waited=$?",
            '      [ "$waited" -eq 127 ] || code=$waited',
            "    fi",
            "    set -e",
            "    trap - TERM INT",
            '    printf "%s\\n" "$code" > "$status_file.partial"',
            '    mv "$status_file.partial" "$status_file"',
            '    exit "$code"',
            "  ) &",
            "  pid=$!",
            '  printf "%s\\n" "$pid" > "$pid_file.partial"',
            '  mv "$pid_file.partial" "$pid_file"',
            "  tries=0",
            f'  while [ ! -s "{CAPTURE_DIR}/$iface.pcap" ] || [ ! -s "$armed_file" ]; do',
            '    [ ! -e "$status_file" ] || exit 1',
            '    kill -0 "$pid"',
            '    tries=$((tries + 1)); [ "$tries" -lt 100 ] || exit 1',
            "    sleep 0.1",
            "  done",
            '  [ -s "$armed_file" ] && [ ! -e "$status_file" ] || exit 1',
            "done",
        ]
    if "sshd" in services:
        lines += [
            "mkdir -p /run/sshd",
            f"[ -e {HOST_KEY} ] || ssh-keygen -A",
            "/usr/sbin/sshd",
        ]
    if "mariadb" in services:
        lines.append("install -d -o mysql -g mysql /run/mysqld")
        # The server itself, not mysqld_safe: Ubuntu's settings for mysqld_safe send the server's log to
        # syslog, and the spec names a log file.
        lines.append("mysqld --user=mysql > /dev/null 2>&1 &")
    if "php-fpm" in services:
        lines += ["mkdir -p /run/php", 'for fpm in /usr/sbin/php-fpm[0-9]*; do "$fpm"; done']
    if "nginx" in services:
        lines.append("nginx")
    if "cron" in services:
        lines.append("cron")
    if "inet-server" in services:
        lines.append(
            f"nohup python3 {INET_SERVER} {INET_TREE} {INET_UPLOADS} {INET_LOG} {INET_CERT} {INET_KEY} "
            "> /var/log/inet/server.log 2>&1 &"
        )
    if settings.agent:
        # The agent reads a log only if it exists when the agent starts: one that nothing wrote yet, such
        # as auth.log on a host without an SSH server, is made empty first.
        logs = " ".join(log.path for log in spec.watch_for(host).logs)
        lines += [
            f'for log in {logs}; do [ -e "$log" ] || : > "$log"; done',
            "/var/ossec/bin/wazuh-control start",
        ]
    lines += activity.start_lines(spec.activity, host)
    lines.append("exec sleep infinity")
    return "\n".join(lines) + "\n"


def sshd_hosts(spec: Spec) -> list[str]:
    return [host.name for host in spec.hosts.values() if "sshd" in host.services]


def authorized(spec: Spec) -> dict[tuple[str, str], list[str]]:
    """The keys each account accepts, by (host, account), in the order the spec names them."""

    found: dict[tuple[str, str], list[str]] = {}
    for host in spec.hosts.values():
        for key in host.keys:
            if key.authorized:
                account, target = key.authorized
                found.setdefault((target, account), []).append(key.name)
    return found


def keys_script(spec: Spec) -> str:
    """The script of the `keys` stage: every key the spec plants, and the files made from them."""

    lines = [
        "#!/bin/sh",
        "# Makes the range's SSH keys. They are lab keys with no value outside the range,",
        "# made when this stage is first built and then kept by the build cache.",
        "set -eu",
        "umask 077",
        "mkdir -p /keys/host /keys/key /keys/authorized /keys/known_hosts",
    ]
    for name in sshd_hosts(spec):
        lines.append(f"ssh-keygen -q -t ed25519 -N '' -C 'host key of {name}' -f /keys/host/{name}")
    for host in spec.hosts.values():
        for key in host.keys:
            if key.private:
                bits = f" -b {RSA_BITS}" if key.type == "rsa" else ""
                lines.append(
                    f"ssh-keygen -q -t {key.type}{bits} -N '' -C '{key.private}@{host.name}' -f /keys/key/{key.name}"
                )
    for (target, account), names in authorized(spec).items():
        lines.append(f"mkdir -p /keys/authorized/{target}")
        lines += [f"cat /keys/key/{name}.pub >> /keys/authorized/{target}/{account}" for name in names]
    for host in spec.hosts.values():
        for known in host.known_hosts:
            file = f"/keys/known_hosts/{host.name}/{known.account}"
            lines.append(f"mkdir -p /keys/known_hosts/{host.name}")
            lines += [
                f"printf '%s %s\\n' {target} \"$(cut -d' ' -f1,2 /keys/host/{target}.pub)\" >> {file}"
                for target in known.hosts
            ]
            if known.hashed:
                lines.append(f"ssh-keygen -q -H -f {file} > /dev/null && rm -f {file}.old")
    return "\n".join(lines) + "\n"


def sshd_conf(host: Host) -> str:
    def yes(value: bool) -> str:
        return "yes" if value else "no"

    return (
        "# The SSH server of this range host, rendered by bluefire-lab from its spec.\n"
        f"PasswordAuthentication {yes(host.sshd.password_auth)}\n"
        f"PermitRootLogin {yes(host.sshd.permit_root)}\n"
        "KbdInteractiveAuthentication no\n"
        "UsePAM yes\n"
        f"HostKey {HOST_KEY}\n"
    )


def database_files(spec: Spec, host: Host) -> dict[str, bytes]:
    """The server settings and the build-time script that makes the database, its user and its tables."""

    db = host.database
    settings = (
        "# The database server of this range host, rendered by bluefire-lab from its spec.\n"
        "[mysqld]\n"
        f"bind-address = {db.bind_address}\n"
        f"log_error = {db.log_error}\n"
    )
    sql = (
        f"CREATE DATABASE `{db.name}`;\n"
        f"CREATE USER '{db.user}'@'{db.grant_from}' IDENTIFIED BY '{db.password}';\n"
        f"GRANT ALL PRIVILEGES ON `{db.name}`.* TO '{db.user}'@'{db.grant_from}';\n"
        f"USE `{db.name}`;\n"
    )
    if db.sql:
        sql += beside(spec, db.sql).decode()
    script = """\
#!/bin/sh
# Makes the database while the image is built: starts the server without a
# network, runs the SQL, and stops the server again.
set -eu
install -d -o mysql -g mysql /run/mysqld
mysqld --user=mysql --skip-networking --log-error=/tmp/db-init/server.log &
tries=0
until mariadb-admin ping > /dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 60 ]; then cat /tmp/db-init/server.log; exit 1; fi
  sleep 1
done
mariadb < /tmp/db-init/db-init.sql
mariadb-admin shutdown
wait
"""
    return {"mariadb.cnf": settings.encode(), "db-init.sql": sql.encode(), "db-init.sh": script.encode()}


def in_folder(spec: Spec, relative: str) -> Path:
    """The path of `relative` in the spec's folder, refused when it or a folder on the way is a link.

    What the build copies into an image is only ever what lies in the spec's
    folder: a link there could point anywhere the user can read.
    """

    if spec.folder is None:
        raise SpecError(f"the spec names {relative}, and was not read from a file")
    path = spec.folder
    for part in PurePosixPath(relative).parts:
        path = path / part
        if path.is_symlink():
            raise SpecError(
                f"the spec names {relative}, and {path.relative_to(spec.folder).as_posix()} beside it is a link: "
                "a file the spec names must be a regular file inside the spec's folder"
            )
    if not path.resolve().is_relative_to(spec.folder.resolve()):
        raise SpecError(f"the spec names {relative}, which is not inside the spec's folder")
    return path


def beside(spec: Spec, relative: str) -> bytes:
    """A file the spec names by its path beside the spec: a regular file inside the spec's folder."""

    path = in_folder(spec, relative)
    if not path.is_file():
        raise SpecError(f"the spec names {relative}, and there is no such file beside it")
    return path.read_bytes()


def repo_files(spec: Spec, name: str) -> dict[str, bytes]:
    """The files of a git repository beside the spec: folders and regular files only, no link."""

    folder = in_folder(spec, f"{REPOS}/{name}") if spec.folder else None
    if folder is None or not folder.is_dir():
        raise SpecError(f"the spec names repo:{name}, and there is no folder {REPOS}/{name} beside it")
    found = {}
    for path in sorted(folder.rglob("*")):
        relative = path.relative_to(folder).as_posix()
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise SpecError(
                f"{REPOS}/{name}/{relative} beside the spec is a link or not a regular file: "
                "a repository the spec names holds folders and regular files only"
            )
        if path.is_file():
            found[relative] = path.read_bytes()
    if not found:
        raise SpecError(f"the folder {REPOS}/{name} beside the spec holds no file")
    return found


def plant_lines(spec: Spec, host: Host) -> list[str]:
    """The lines of a host's stage that plant what the spec names, after its packages."""

    name = host.name
    lines: list[str] = []
    if host.accounts:
        commands = []
        for account in host.accounts:
            commands.append(f"useradd --create-home --shell {account.shell} {account.name}")
            if account.password is not None:
                commands.append(f"echo {shlex.quote(account.name + ':' + account.password)} | chpasswd")
            else:
                # No password, and not locked: a key can still log the account in.
                commands.append(f"usermod -p '*' {account.name}")
        lines += ["# Accounts.", _run(*commands)]
        sudoers = [account for account in host.accounts if account.sudo]
        for account in sudoers:
            lines.append(
                f"COPY --chmod=0440 files/{name}/sudoers-{account.name} /etc/sudoers.d/{account.name}"
            )
        if sudoers:
            lines.append("RUN visudo -cq")
    if host.sshd:
        lines += [
            "# The SSH server: its settings, and the host key made in the keys stage.",
            "RUN rm -f /etc/ssh/ssh_host_*",
            f"COPY --from=keys --chmod=0600 /keys/host/{name} {HOST_KEY}",
            f"COPY --from=keys --chmod=0644 /keys/host/{name}.pub {HOST_KEY}.pub",
            f"COPY files/{name}/sshd.conf /etc/ssh/sshd_config.d/50-range.conf",
            "RUN mkdir -p /run/sshd && /usr/sbin/sshd -t",
        ]
        if host.sshd.pam_nodelay:
            lines += [
                "# pam_unix without its delay after a failed password.",
                _run(
                    "sed -i -E '/^auth[[:space:]].*pam_unix[.]so/ s/$/ nodelay/' /etc/pam.d/common-auth",
                    "grep -Eq '^auth[[:space:]].*pam_unix[.]so.* nodelay$' /etc/pam.d/common-auth",
                ),
            ]
    elif "sshd" in host.services:
        lines += [
            "RUN rm -f /etc/ssh/ssh_host_*",
            f"COPY --from=keys --chmod=0600 /keys/host/{name} {HOST_KEY}",
            f"COPY --from=keys --chmod=0644 /keys/host/{name}.pub {HOST_KEY}.pub",
        ]
    ssh_accounts = []
    copies = []
    for key in host.keys:
        if key.private:
            owner = f"{key.private}:{key.private}"
            folder = f"{home(key.private)}/.ssh"
            ssh_accounts.append(key.private)
            copies += [
                f"COPY --from=keys --chown={owner} --chmod=0600 /keys/key/{key.name} {folder}/{key.file_name}",
                f"COPY --from=keys --chown={owner} --chmod=0644 /keys/key/{key.name}.pub {folder}/{key.file_name}.pub",
            ]
    for target, account in authorized(spec):
        if target == name:
            ssh_accounts.append(account)
            copies.append(
                f"COPY --from=keys --chown={account}:{account} --chmod=0600 /keys/authorized/{name}/{account} "
                f"{home(account)}/.ssh/authorized_keys"
            )
    for known in host.known_hosts:
        ssh_accounts.append(known.account)
        copies.append(
            f"COPY --from=keys --chown={known.account}:{known.account} --chmod=0644 "
            f"/keys/known_hosts/{name}/{known.account} {home(known.account)}/.ssh/known_hosts"
        )
    if copies:
        folders = [
            f"install -d -m 0700 -o {account} -g {account} {home(account)}/.ssh"
            for account in dict.fromkeys(ssh_accounts)
        ]
        lines += [
            "# SSH keys, accepted keys and known hosts, made in the keys stage.",
            _run(*folders),
            *copies,
        ]
    if host.dirs:
        lines += [
            "# Folders.",
            _run(*[f"install -d -o {d.owner} -g {d.group} -m {d.mode} {d.path}" for d in host.dirs]),
        ]
    # A COPY with --chmod gives the folders it makes the file's mode, so the folders of the planted
    # and served files are made first, as root with mode 0755 where they do not exist yet.
    parents = [str(Path(f.path).parent) for f in host.files if not f.repo]
    parents += [str(Path(INET_TREE + url).parent) for url, _ in host.serve]
    if parents:
        lines.append("RUN mkdir -p " + " ".join(dict.fromkeys(parents)))
    for number, file in enumerate(host.files, start=1):
        if file.repo:
            lines += [
                f"# The git repository {file.repo}, made from the files beside the spec, one commit.",
                f"COPY {REPOS}/{file.repo} /tmp/repo-{file.repo}",
                _run(
                    f"git init -q -b main /tmp/repo-{file.repo}",
                    f"git -C /tmp/repo-{file.repo} add -A",
                    f"GIT_AUTHOR_DATE={REPO_DATE} GIT_COMMITTER_DATE={REPO_DATE} git -C /tmp/repo-{file.repo} "
                    f"-c user.name={file.owner} -c user.email={file.owner}@{name} commit -q -m 'The {file.repo} sources'",
                    f"git clone -q --bare /tmp/repo-{file.repo} {file.path}",
                    f"rm -rf /tmp/repo-{file.repo}",
                    f"chown -R {file.owner}:{file.group} {file.path}",
                ),
            ]
        else:
            lines.append(
                f"COPY --chown={file.owner}:{file.group} --chmod={file.mode} files/{name}/plant-{number} {file.path}"
            )
    if host.database:
        lines += [
            "# The database: server settings, then the database made by a script that starts the server,",
            "# runs the SQL and stops it.",
            f"COPY files/{name}/mariadb.cnf /etc/mysql/mariadb.conf.d/60-range.cnf",
            f"COPY files/{name}/db-init.sh files/{name}/db-init.sql /tmp/db-init/",
            "RUN sh /tmp/db-init/db-init.sh && rm -rf /tmp/db-init",
            "# The server's log file, which the server, run as mysql, can write and the agent can read from its start.",
            _run(
                f"install -d -o mysql -g adm -m 0750 {str(Path(host.database.log_error).parent)}",
                f"touch {host.database.log_error}",
                f"chown mysql:adm {host.database.log_error}",
                f"chmod 0640 {host.database.log_error}",
            ),
        ]
    if "nginx" in host.services:
        lines += [f"COPY files/{name}/nginx-site.conf /etc/nginx/sites-available/default", "RUN nginx -t"]
    if "inet-server" in host.services:
        lines += [
            "# The stand-in internet's server, with a certificate made here.",
            f"COPY --chmod=0755 files/inet-server {INET_SERVER}",
            _run(
                f"install -d /etc/inet {INET_TREE} {INET_UPLOADS} /var/log/inet",
                f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN={name} "
                f"-addext subjectAltName=DNS:{name} -keyout {INET_KEY} -out {INET_CERT} 2> /dev/null",
            ),
        ]
        for url, source in host.serve:
            lines.append(f"COPY --chmod=0444 {source} {INET_TREE}{url}")
    if host.atomics_src:
        lines.append(f"# Published files, as data, at the commit in {COMMIT_FILE}.")
        lines += [
            f"COPY atomics/{technique}/src {atomics.ATOMICS_PATH}/{technique}/src"
            for technique in host.atomics_src
        ]
        lines.append(f"COPY --chmod=0444 files/COMMIT {COMMIT_FILE}")
    if host.atomics_src or host.serve:
        lines.append(f"COPY --chmod=0444 {LICENSE_IN_CONTEXT} {atomics.ATOMICS_PATH}/{atomics.LICENSE}")
    return lines


def host_files(spec: Spec, host: Host) -> dict[str, bytes]:
    """The files of the build context that one host's stage copies."""

    name = host.name
    found = {f"files/range-start-{name}": start_script(spec, name).encode()}
    for account in host.accounts:
        if account.sudo:
            rule = f"{account.name} ALL=(root) NOPASSWD: {', '.join(account.sudo)}\n"
            found[f"files/{name}/sudoers-{account.name}"] = rule.encode()
    if host.sshd:
        found[f"files/{name}/sshd.conf"] = sshd_conf(host).encode()
    for number, file in enumerate(host.files, start=1):
        if file.repo:
            for relative, content in repo_files(spec, file.repo).items():
                found[f"{REPOS}/{file.repo}/{relative}"] = content
        else:
            found[f"files/{name}/plant-{number}"] = (
                file.content if file.text is not None else beside(spec, file.source)
            )
    if host.database:
        found.update({f"files/{name}/{k}": v for k, v in database_files(spec, host).items()})
    if "nginx" in host.services:
        found[f"files/{name}/nginx-site.conf"] = NGINX_SITE.encode()
    if "inet-server" in host.services:
        found["files/inet-server"] = Path(inet_server.__file__).read_bytes()
    if host.atomics_src:
        found["files/COMMIT"] = (spec.atomics.commit + "\n").encode()
    found.update(activity.files(spec.activity, name))
    return found


def conf_settings(spec: Spec) -> dict:
    """What `ossec.py` needs to edit the stock files: the manager's host and each agent's settings."""

    agents = {}
    for host in spec.agents:
        watch = spec.watch_for(host)
        agents[host] = {
            "name": host,
            "manager": spec.manager,
            "logs": [{"path": log.path, "format": log.format} for log in watch.logs],
            "fim_realtime": list(watch.fim_realtime),
            "off": list(spec.wazuh.off),
        }
    return {"manager": spec.manager, "agents": agents}


def _run(*commands: str) -> str:
    return "RUN " + " \\\n && ".join(commands)


APT_INSTALL = "apt-get update && apt-get install -y --no-install-recommends "
APT_CLEAN = "rm -rf /var/lib/apt/lists/*"
# apt's setting for a server that answers with an error now and then: each download is tried
# again up to eight times, with apt's growing wait between the tries.
APT_RETRIES = 'Acquire::Retries "8";'


def dockerfile(spec: Spec) -> str:
    built = [host for host in spec.hosts.values() if host.built and host.kind != "defense"]
    wazuh = spec.wazuh
    parts = [
        f"# Images of the range {spec.range}, rendered by bluefire-lab from its spec. Do not edit:",
        "# render again from the spec.",
    ]
    if built:
        parts += [
            "",
            f"FROM {spec.base.image} AS ubuntu",
            "ARG DEBIAN_FRONTEND=noninteractive",
            "# Packages come from the Ubuntu archive as it was at the snapshot. The snapshot service is",
            "# reached over HTTPS, so the certificate store (ca-certificates and openssl) comes first, from",
            "# the archive of the day: the only packages that do not come from the snapshot. A download",
            "# that fails is tried again with a growing wait, so that a short outage of either service",
            "# does not fail the build.",
            _run(
                f"echo '{APT_RETRIES}' > /etc/apt/apt.conf.d/80retries",
                APT_INSTALL + "ca-certificates",
                APT_CLEAN,
                f"echo 'APT::Snapshot \"{spec.base.apt_snapshot}\";' > /etc/apt/apt.conf.d/50snapshot",
            ),
        ]
        base_packages = "rsyslog procps iproute2 snoopy"
        if wazuh:
            major = wazuh.version.split(".")[0]
            url = (
                f"https://packages.wazuh.com/{major}.x/apt/pool/main/w/wazuh-agent/"
                f"wazuh-agent_{wazuh.agent_version}_amd64.deb"
            )
            parts += [
                "",
                "FROM ubuntu AS fetch",
                "ARG DEBIAN_FRONTEND=noninteractive",
                _run(APT_INSTALL + "curl", APT_CLEAN),
                "# The Wazuh agent package, checked against the SHA-512 the spec pins.",
                _run(
                    f"curl -fsSL --retry 5 --retry-all-errors --proto '=https' -o /wazuh-agent.deb {url}",
                    f'echo "{wazuh.agent_sha512}  /wazuh-agent.deb" | sha512sum -c -',
                ),
            ]
            base_packages += " /tmp/wazuh-agent.deb"
        parts += [
            "",
            "FROM ubuntu AS base",
            "ARG DEBIAN_FRONTEND=noninteractive",
        ]
        install = [APT_INSTALL + base_packages, APT_CLEAN, "rm -f /etc/ld.so.preload"]
        if wazuh:
            install.append(f"cp -p {OSSEC_CONF} {STOCK}")
            parts.append(
                "RUN --mount=type=bind,from=fetch,source=/wazuh-agent.deb,target=/tmp/wazuh-agent.deb \\\n    "
                + " \\\n && ".join(install)
            )
        else:
            parts.append(_run(*install))
        parts += [
            "COPY files/rsyslog.conf /etc/rsyslog.conf",
            "COPY files/snoopy.ini /etc/snoopy.ini",
        ]
    if any(host.keys or host.known_hosts or "sshd" in host.services for host in built):
        parts += [
            "",
            "# The range's SSH keys: lab keys with no value outside the range, made when this stage",
            "# is first built and then kept by the build cache.",
            "FROM ubuntu AS keys",
            "ARG DEBIAN_FRONTEND=noninteractive",
            _run(APT_INSTALL + "openssh-client", APT_CLEAN),
            "COPY files/keys.sh /keys.sh",
            "RUN sh /keys.sh",
        ]
    if wazuh:
        parts += [
            "",
            "# The lab's edits of the stock ossec.conf files, run with the Python the manager image has.",
            f"FROM {wazuh.manager_image} AS conf",
            "COPY --from=base " + STOCK + " /stock/agent.conf",
            "COPY files/ossec.py files/ossec-settings.json /conf/",
            f"RUN {MANAGER_PYTHON} /conf/ossec.py /conf/ossec-settings.json {OSSEC_CONF} /stock/agent.conf /out",
        ]
    for host in built:
        parts += ["", f"FROM base AS host-{host.name}", "ARG DEBIAN_FRONTEND=noninteractive"]
        if host.packages:
            parts.append(_run(APT_INSTALL + " ".join(host.packages), APT_CLEAN))
            parts += [
                "# A login must not fail because a container may not set the audit login id.",
                "RUN sed -i -E 's/^(session[[:space:]]+)required([[:space:]]+pam_loginuid[.]so)/\\1optional\\2/' "
                "/etc/pam.d/*",
            ]
        parts += plant_lines(spec, host)
        parts += activity.dockerfile_lines(spec.activity, host.name)
        if host.agent:
            parts.append(
                f"COPY --from=conf --chown=root:wazuh --chmod=0660 /out/{host.name}/ossec.conf {OSSEC_CONF}"
            )
        parts.append(f"COPY --chmod=0755 files/range-start-{host.name} /usr/local/sbin/range-start")
        if host.agent:
            parts += [
                "# Last, so that the build's own commands are not logged: snoopy loads into every program",
                "# that starts in this host.",
                f"RUN echo {SNOOPY_LIBRARY} > /etc/ld.so.preload",
            ]
        parts += [f'LABEL {LABEL_RANGE}="{spec.range}"', 'ENTRYPOINT ["/usr/local/sbin/range-start"]']
    if wazuh:
        parts += [
            "",
            "# The manager: the pinned image, with the lab's configuration where the image's own start",
            "# copies it into /var/ossec. Its entrypoint stays the image's /init.",
            f"FROM {wazuh.manager_image} AS host-{spec.manager}",
            f"RUN cp -p {OSSEC_CONF} {STOCK}",
            f"COPY --from=conf /out/{spec.manager}/ossec.conf /wazuh-config-mount/etc/ossec.conf",
            "COPY files/local_internal_options.conf /wazuh-config-mount/etc/local_internal_options.conf",
            "COPY files/bluefire_snoopy.xml /wazuh-config-mount/etc/decoders/bluefire_snoopy.xml",
            "COPY files/filebeat-down /etc/services.d/filebeat/down",
            "COPY files/wazuh-api.yaml /wazuh-config-mount/api/configuration/api.yaml",
            f'LABEL {LABEL_RANGE}="{spec.range}"',
        ]
    return "\n".join(parts) + "\n"


def files(spec: Spec, fetched: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """The build context, without bake.json: relative path to content.

    `fetched` holds the published files the spec needs, by their path in the
    repository of Atomic Red Team (see `atomics.fetch`); they are part of the
    context at that path.
    """

    found = {DOCKERFILE: dockerfile(spec).encode()}
    built = [host for host in spec.hosts.values() if host.built and host.kind != "defense"]
    if built:
        found["files/rsyslog.conf"] = RSYSLOG_CONF.encode()
        found["files/snoopy.ini"] = SNOOPY_INI.encode()
    if "FROM ubuntu AS keys" in found[DOCKERFILE].decode():
        found["files/keys.sh"] = keys_script(spec).encode()
    for host in built:
        found.update(host_files(spec, host))
    needed = atomics.single_files(spec) + atomics.src_folders(spec) if spec.atomics else []
    if needed and fetched is None:
        raise SpecError("the spec's hosts carry published files, and none were fetched")
    for relative, content in (fetched or {}).items():
        found[LICENSE_IN_CONTEXT if relative == atomics.LICENSE else relative] = content
    if spec.wazuh:
        found["files/ossec.py"] = Path(ossec.__file__).read_bytes()
        found["files/ossec-settings.json"] = (json.dumps(conf_settings(spec), indent=2) + "\n").encode()
        found["files/local_internal_options.conf"] = LOCAL_INTERNAL_OPTIONS.encode()
        found["files/bluefire_snoopy.xml"] = SNOOPY_DECODER.encode()
        found["files/filebeat-down"] = FILEBEAT_DOWN.encode()
        found["files/wazuh-api.yaml"] = WAZUH_API.encode()
    return found


def context_hash(context: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in sorted(context):
        digest.update(path.encode() + b"\0" + str(len(context[path])).encode() + b"\0" + context[path])
    return digest.hexdigest()[:16]


def tags(spec: Spec, digest: str) -> dict[str, str]:
    return {host.name: f"{spec.prefix}-{host.name}:{digest}" for host in spec.hosts.values() if host.built}


def bake(spec: Spec, tagged: dict[str, str]) -> dict:
    """The bake file: one target per built host. Paths are relative to the build folder."""

    targets = {
        host: {"context": ".", "dockerfile": DOCKERFILE, "target": f"host-{host}", "tags": [tag]}
        for host, tag in tagged.items()
    }
    return {"group": {"default": {"targets": list(targets)}}, "target": targets}


def render(spec: Spec, out: Path, get: atomics.Fetch = atomics.http_get) -> Rendered:
    """Fetch and check the published files, and write the build context and the bake file into `out`.

    Every file and folder is written with a fixed mode (0644, 0755), since a
    COPY keeps the modes of the context.
    """

    out = Path(out)
    fetched = (
        atomics.fetch(spec, get)
        if spec.atomics and (atomics.single_files(spec) or atomics.src_folders(spec))
        else {}
    )
    context = files(spec, fetched)
    digest = context_hash(context)
    tagged = tags(spec, digest)
    out.mkdir(parents=True, exist_ok=True)
    for relative, content in context.items():
        path = out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o644)
        for folder in path.relative_to(out).parents:
            if folder != Path("."):
                (out / folder).chmod(0o755)
    (out / BAKE).write_text(json.dumps(bake(spec, tagged), indent=2) + "\n", encoding="utf-8")
    return Rendered(out, digest, tagged)

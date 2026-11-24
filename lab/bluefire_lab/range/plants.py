"""Checks that what a spec plants is in place on the running range, the way the path will need it.

Each check is one or more commands of the engine's own, run in the range's
containers with the tag `engine:plant` (or `engine:ready` for the ready gate's
checks), and a judgement of their output. A check uses what is planted once,
the way it is meant to be used: one login with a planted key or a planted
password, one query with a planted password, one use of a sudo rule, one page
fetch, one upload of a few bytes. None runs a published test or anything of
one, and none guesses anything.

This module derives the checks from the spec and judges their output; running
the commands is the job of `engine`.
"""

from __future__ import annotations

import hashlib
import shlex
from collections.abc import Callable
from dataclasses import dataclass

from . import atomics, build
from .spec import Host, Spec, home

SECRETS = ("/etc/shadow", "/etc/gshadow", build.HOST_KEY)


@dataclass(frozen=True)
class Command:
    host: str
    user: str
    script: str


Outputs = list[tuple[int, str]]  # the exit code and the output of each command, in order


def lines_judge(expected: list[str]) -> Callable[[Outputs], tuple[object, bool]]:
    """Every command exits 0, and their output lines, together, are exactly `expected`."""

    def judge(outputs: Outputs) -> tuple[object, bool]:
        lines = [line for _, out in outputs for line in out.splitlines()]
        codes = [code for code, _ in outputs]
        observed = lines if all(code == 0 for code in codes) else {"exit codes": codes, "output": lines}
        return observed, observed == expected

    return judge


@dataclass(frozen=True)
class Check:
    name: str
    subject: str
    commands: tuple[Command, ...]
    expected: object
    judge: Callable[[Outputs], tuple[object, bool]]


def check(name: str, subject: str, commands: list[Command], expected: list[str]) -> Check:
    return Check(name, subject, tuple(commands), expected, lines_judge(expected))


def readable(account: str, owner: str, group: str, mode: str) -> bool:
    """Whether an account may read a planted file, by its owner, group and mode (its own group only)."""

    bits = int(mode, 8)
    if account == "root":
        return True
    return bool((owner == account and bits & 0o400) or (group == account and bits & 0o040) or bits & 0o004)


def candidates(target: Host) -> list[tuple[str, str, str, str]]:
    """The files whose reading a login to a host is checked against: what is planted there, and its secrets."""

    found = [(f.path, f.owner, f.group, f.mode) for f in target.files if not f.repo]
    found += [(path, "root", "shadow" if "shadow" in path else "root", "0640" if "shadow" in path else "0600")
              for path in SECRETS]  # fmt: skip
    return found


def accounts(spec: Spec, host: Host) -> list[Check]:
    found = []
    for account in host.accounts:
        script = [
            f"getent passwd {account.name} | cut -d: -f1,6,7 | sed 's/^/passwd /'",
            f"stat -c 'home owner %U' {home(account.name)}",
            f"hash=$(getent shadow {account.name} | cut -d: -f2)",
        ]
        expected = [
            f"passwd {account.name}:{home(account.name)}:{account.shell}",
            f"home owner {account.name}",
        ]
        if account.password is not None:
            # The password is checked against its hash with the C library's crypt(), as PAM does.
            script.append(
                'perl -e \'print crypt($ARGV[0], $ARGV[1]) eq $ARGV[1] ? "password matches\\n" : "password differs\\n"\' '
                f'{shlex.quote(account.password)} "$hash"'
            )
            expected.append("password matches")
        else:
            script.append("printf 'password field %s\\n' \"$hash\"")
            expected.append("password field *")
        if account.sudo:
            script.append(f"sudo -n -l -U {account.name} | grep -o 'NOPASSWD: .*' | sed 's/^/sudo /'")
            expected.append(f"sudo NOPASSWD: {', '.join(account.sudo)}")
        commands = [Command(host.name, "root", "\n".join(script))]
        # Each planted sudo rule used once, as the account, without a password.
        for rule in account.sudo:
            commands.append(
                Command(host.name, account.name, f'sudo -n {rule} > /dev/null 2>&1; echo "sudo exit $?"')
            )
            expected.append("sudo exit 0")
        found.append(check("plant: account", f"host {host.name}: {account.name}", commands, expected))
    return found


def password_logins(spec: Spec, host: Host) -> list[Check]:
    """One SSH login with each planted password, through PAM's auth stack as the path's first step needs
    it: from a host that knows this host's key and runs no step of the path, with the password given by
    an askpass script."""

    if host.sshd is None or not host.sshd.password_auth:
        return []
    knowing = [
        (other, known.account)
        for other in spec.hosts.values()
        if other.kind == "host" and other.name not in spec.path_hosts
        for known in other.known_hosts
        if host.name in known.hosts
    ]
    if not knowing:
        return []
    source, as_account = knowing[0]
    found = []
    for account in host.accounts:
        if account.password is None:
            continue
        askpass = f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(account.password)}\n"
        script = "\n".join(
            [
                "askpass=$(mktemp)",
                f"printf '%s' {shlex.quote(askpass)} > \"$askpass\"",
                'chmod 700 "$askpass"',
                'SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force ssh -o BatchMode=no -o PubkeyAuthentication=no '
                "-o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=yes "
                f"-o ConnectTimeout=10 {account.name}@{host.name} id -un < /dev/null",
                "code=$?",
                'rm -f "$askpass"',
                'exit "$code"',
            ]
        )
        found.append(
            check(
                "plant: password login",
                f"{as_account}@{source.name} to {account.name}@{host.name}",
                [Command(source.name, as_account, script)],
                [account.name],
            )
        )
    return found


def sshd(host: Host) -> list[Check]:
    if host.sshd is None:
        return []
    keys = "passwordauthentication|permitrootlogin|usepam|hostkey|kbdinteractiveauthentication"
    script = (
        f"/usr/sbin/sshd -T | grep -E '^({keys}) ' | sort\n"
        "printf 'pam_unix nodelay %s\\n' \"$(grep -Ec '^auth[[:space:]].*pam_unix[.]so.* nodelay$' /etc/pam.d/common-auth)\""
    )
    expected = sorted(
        [
            f"hostkey {build.HOST_KEY}",
            "kbdinteractiveauthentication no",
            f"passwordauthentication {'yes' if host.sshd.password_auth else 'no'}",
            f"permitrootlogin {'yes' if host.sshd.permit_root else 'no'}",
            "usepam yes",
        ]
    ) + [f"pam_unix nodelay {1 if host.sshd.pam_nodelay else 0}"]
    return [check("plant: sshd", f"host {host.name}", [Command(host.name, "root", script)], expected)]


def git_blob(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git's own id


def contents(spec: Spec, host: Host) -> list[Check]:
    """Folders and files with their owner, group, mode and content; a repository with its files."""

    script, expected = [], []
    for folder in host.dirs:
        script.append(f"stat -c 'dir %n %U %G %a' {folder.path}")
        expected.append(f"dir {folder.path} {folder.owner} {folder.group} {int(folder.mode, 8):o}")
    for file in host.files:
        if file.repo:
            script += [
                f"stat -c 'repo %n %U' {file.path}",
                f"git -c safe.directory='*' --git-dir={file.path} ls-tree -r HEAD",
            ]
            expected.append(f"repo {file.path} {file.owner}")
            expected += [
                f"100644 blob {git_blob(content)}\t{relative}"
                for relative, content in sorted(build.repo_files(spec, file.repo).items())
            ]
        else:
            content = file.content if file.text is not None else build.beside(spec, file.source)
            script += [f"stat -c 'file %n %U %G %a' {file.path}", f"sha256sum {file.path}"]
            expected += [
                f"file {file.path} {file.owner} {file.group} {int(file.mode, 8):o}",
                f"{hashlib.sha256(content).hexdigest()}  {file.path}",
            ]
    if not script:
        return []
    return [
        check("plant: files", f"host {host.name}", [Command(host.name, "root", "\n".join(script))], expected)
    ]


def database(spec: Spec, host: Host) -> list[Check]:
    db = host.database
    if db is None:
        return []
    sql = (
        f"SELECT CONCAT(user, '@', host) FROM mysql.user WHERE user = '{db.user}'; "
        f"SHOW GRANTS FOR '{db.user}'@'{db.grant_from}'; SELECT @@bind_address, @@log_error"
    )
    grant = f"GRANT ALL PRIVILEGES ON `{db.name}`.* TO `{db.user}`@`{db.grant_from}`"

    def judge(outputs: Outputs) -> tuple[object, bool]:
        code, out = outputs[0]
        lines = [line for line in out.splitlines() if not line.startswith("GRANT USAGE")]
        return lines, code == 0 and lines == [
            f"{db.user}@{db.grant_from}",
            grant,
            f"{db.bind_address}\t{db.log_error}",
        ]

    found = [
        Check(
            "plant: database",
            f"host {host.name}: {db.name}",
            (Command(host.name, "root", f"mariadb -N -B -e {shlex.quote(sql)}"),),
            [f"{db.user}@{db.grant_from}", grant, f"{db.bind_address}\t{db.log_error}"],
            judge,
        )
    ]
    # A PHP configuration that holds the planted password: its values connect, from its host, as its owner.
    for other in spec.hosts.values():
        for file in other.files:
            if (
                file.text
                and db.password in file.text
                and "$db_password" in file.text
                and "php-mysql" in other.packages
            ):
                php = (
                    f"include '{file.path}'; mysqli_report(MYSQLI_REPORT_OFF); "
                    f"$c = @new mysqli($db_host, $db_user, $db_password, '{db.name}'); "
                    'if ($c->connect_errno) { echo "error ", $c->connect_error, "\\n"; exit(1); } '
                    'echo "connected as ", $c->query("SELECT CURRENT_USER()")->fetch_row()[0], "\\n";'
                )
                found.append(
                    check(
                        "plant: database password in a file",
                        f"host {other.name}: {file.path}",
                        [Command(other.name, file.owner, f"php -r {shlex.quote(php)}")],
                        [f"connected as {db.user}@{db.grant_from}"],
                    )
                )
    return found


def clients(spec: Spec, server: Host) -> list[Host]:
    """The hosts from which a server's pages are checked: of kind host, with curl, sharing a network with it,
    and running no step of the path, so that no check leaves a line a step's check looks for."""

    return [
        host
        for host in spec.hosts.values()
        if host.kind == "host"
        and host.name != server.name
        and "curl" in host.packages
        and spec.shared(host.name, server.name)
        and host.name not in spec.path_hosts
    ]


def pages(spec: Spec, host: Host) -> list[Check]:
    if "nginx" not in host.services:
        return []

    def judge(outputs: Outputs) -> tuple[object, bool]:
        code, out = outputs[0]
        lines = out.splitlines()
        items = next((int(line.split()[1]) for line in lines if line.startswith("items ")), 0)
        return lines, code == 0 and "status 200" in lines and "database errors 0" in lines and items > 0

    script = (
        f"page=$(curl -s -w '\\nstatus %{{http_code}}' http://{host.name}/)\n"
        "printf '%s\\n' \"$page\" | grep '^status '\n"
        "printf 'database errors %s\\n' \"$(printf '%s\\n' \"$page\" | grep -c 'database error')\"\n"
        "printf 'items %s\\n' \"$(printf '%s\\n' \"$page\" | grep -c '<li>')\""
    )
    return [
        Check(
            "plant: shop page",
            f"host {client.name} to {host.name}",
            (Command(client.name, "root", script),),
            "status 200, no database error, at least one item",
            judge,
        )
        for client in clients(spec, host)
    ]


def keys(spec: Spec, entry_host: Host) -> list[Check]:
    """One login for each account that a host's key entries say accepts a key: from the key's holder."""

    found = []
    for entry in entry_host.keys:
        if not entry.authorized:
            continue
        holder, key = spec.key(entry.name)
        host = spec.hosts[holder]
        account, target = entry.authorized
        file = f"{home(key.private)}/.ssh/{key.file_name}"
        listed = candidates(spec.hosts[target])
        probe = (
            "id -un; for f in "
            + " ".join(path for path, *_ in listed)
            + '; do if [ -r "$f" ]; then echo "readable $f"; fi; done'
        )
        # A key under a name ssh tries by itself is used without -i, as the path's ssh will use it.
        identity = "" if key.file_name in ("id_rsa", "id_ed25519") else f" -i {file}"
        script = (
            f"stat -c 'key %U %a' {file}\n"
            f"ssh -o BatchMode=yes -o ConnectTimeout=10{identity} {account}@{target} {shlex.quote(probe)}"
        )
        expected = [f"key {key.private} 600", account]
        expected += [
            f"readable {path}" for path, owner, group, mode in listed if readable(account, owner, group, mode)
        ]
        found.append(
            check(
                "plant: key login",
                f"key {key.name}: {key.private}@{host.name} to {account}@{target}",
                [Command(host.name, key.private, script)],
                expected,
            )
        )
    return found


def served(
    spec: Spec, host: Host, locked: dict[str, str], addresses: dict[str, dict[str, str]]
) -> list[Check]:
    """Each served file, fetched once from a client, with its locked SHA-256 and its line in the access log;
    then one upload of a few bytes, stored and indexed. The upload is removed again, so that the
    path's first upload is the first one stored."""

    found = []
    if "inet-server" not in host.services:
        return found
    for client in clients(spec, host)[:1]:
        address = addresses.get(client.name, {}).get(spec.shared(client.name, host.name)[0], "")
        for url, source in host.serve:
            found.append(
                check(
                    "plant: served file",
                    f"host {host.name}: {url} to {client.name}",
                    [
                        Command(
                            client.name,
                            "root",
                            f"curl -s http://{host.name}{url} | sha256sum | cut -d' ' -f1",
                        ),
                        Command(host.name, "root", f"grep -c '^{address} GET {url} 200 ' {build.INET_LOG}"),
                    ],
                    [locked[source], "1"],
                )
            )
        body = b"bluefire-plant-upload\n"
        digest = hashlib.sha256(body).hexdigest()
        uploads = build.INET_UPLOADS
        found.append(
            check(
                "plant: upload",
                f"host {host.name}: upload from {client.name}",
                [
                    Command(
                        client.name,
                        "root",
                        f"printf 'bluefire-plant-upload\\n' | curl -sk --data-binary @- https://{host.name}/upload",
                    ),
                    Command(
                        host.name,
                        "root",
                        f"cat {uploads}/index.tsv; sha256sum {uploads}/1.bin; "
                        f"grep -c '^{address} POST /upload 200 ' {build.INET_LOG}; "
                        f"rm -f {uploads}/1.bin {uploads}/index.tsv",
                    ),
                ],
                ["stored 1", f"1 {address} {digest} {len(body)}", f"{digest}  {uploads}/1.bin", "1"],
            )
        )
    return found


def carried(spec: Spec, host: Host, locked: dict[str, str]) -> list[Check]:
    """The published src folders a host carries: every file, with its locked SHA-256."""

    if not host.atomics_src:
        return []
    folders = " ".join(f"{technique}/src" for technique in host.atomics_src)
    # Both sides in the order of the paths, byte by byte: the lock's entries here, `sort -k2` there.
    expected = [
        f"{digest}  {path.removeprefix('atomics/')}"
        for path, digest in sorted(locked.items())
        if any(path.startswith(f"atomics/{technique}/src/") for technique in host.atomics_src)
    ]
    script = f"cd {atomics.ATOMICS_PATH} && find {folders} -type f -exec sha256sum {{}} + | LC_ALL=C sort -k2"
    return [
        check("plant: published files", f"host {host.name}", [Command(host.name, "root", script)], expected)
    ]


def checks(spec: Spec, locked: dict[str, str], addresses: dict[str, dict[str, str]]) -> list[Check]:
    """Every plant check of a range, in the order the engine runs them."""

    found: list[Check] = []
    for host in spec.hosts.values():
        if not host.built or host.kind == "defense":
            continue
        found += accounts(spec, host) + sshd(host) + contents(spec, host) + database(spec, host)
    for host in spec.hosts.values():
        found += pages(spec, host)
    for host in spec.hosts.values():
        found += keys(spec, host) + password_logins(spec, host)
    for host in spec.hosts.values():
        found += served(spec, host, locked, addresses) + carried(spec, host, locked)
    return found


def weaknesses(spec: Spec) -> list[str]:
    """The weaknesses the spec plants on purpose, in words, for the manifest."""

    found = []
    for host in spec.hosts.values():
        for account in host.accounts:
            if account.listed:
                found.append(
                    f"{host.name}: the account {account.name} has the password that line {account.listed.line} "
                    f"of the published list {account.listed.file} gives it"
                )
            elif account.password is not None:
                found.append(f"{host.name}: the account {account.name} has a planted password")
        if host.sshd and host.sshd.password_auth:
            found.append(f"{host.name}: the SSH server accepts passwords")
        if host.sshd and host.sshd.pam_nodelay:
            found.append(
                f"{host.name}: pam_unix has nodelay, so a failed password is answered without a pause"
            )
        for key in host.keys:
            if key.private and key.authorized:
                found.append(
                    f"{host.name}: {key.private} holds the {key.type} key {key.name} without a passphrase, and "
                    f"{key.authorized[0]}@{key.authorized[1]} accepts it"
                )
        for file in host.files:
            for other in spec.hosts.values():
                if other.database and file.text and other.database.password in file.text:
                    found.append(
                        f"{host.name}: {file.path} holds the password of {other.name}'s database user "
                        f"{other.database.user}, mode {file.mode}"
                    )
            if not file.repo and file.group != file.owner and int(file.mode, 8) & 0o040:
                found.append(f"{host.name}: {file.path} is readable by the group {file.group}")
        for folder in host.dirs:
            found.append(
                f"{host.name}: {folder.path} is a folder owned by {folder.owner}, mode {folder.mode}"
            )
    return found


def summary(manifest: dict) -> str:
    """The plant checks of a run as Markdown, for a CI job's summary."""

    planted = manifest.get("plants") or {}
    checks = planted.get("checks") or []
    title = "not checked" if not checks else ("in place" if planted.get("passed") else "NOT in place")
    lines = [f"### Plants of {manifest.get('range')}: {title}", ""]
    ready = (manifest.get("ready") or {}).get("plants") or []
    rows = [("ready", item) for item in ready] + [("plant", item) for item in checks]
    if rows:
        lines += ["| Check | Subject | Result |", "|---|---|---|"]
        lines += [
            f"| {item['check']} | {item['subject']} | {'pass' if item['pass'] else 'FAIL'} |"
            for _, item in rows
        ]
        lines.append("")
    if manifest.get("weaknesses"):
        lines += ["Planted on purpose:", ""] + [f"- {item}" for item in manifest["weaknesses"]] + [""]
    return "\n".join(lines)


def ready_checks(spec: Spec) -> list[Check]:
    """The ready gate's checks of the plants: each known_hosts entry is the host key its host has, and each
    host with curl next to the stand-in internet fetches its pages over HTTP and HTTPS."""

    found = []
    for host in spec.hosts.values():
        for known in host.known_hosts:
            for target in known.hosts:
                file = f"{home(known.account)}/.ssh/known_hosts"

                def judge(outputs: Outputs) -> tuple[object, bool]:
                    (code_key, key), (code_entry, entry) = outputs
                    observed = {"host key": key.strip(), "known_hosts entry": entry.strip()}
                    return observed, code_key == 0 and code_entry == 0 and bool(
                        key.strip()
                    ) and key.strip() == entry.strip()

                found.append(
                    Check(
                        "ready: known host key",
                        f"host {host.name}: {known.account} knows {target}",
                        (
                            Command(target, "root", f"cut -d' ' -f1,2 {build.HOST_KEY}.pub"),
                            Command(
                                host.name,
                                "root",
                                f"ssh-keygen -F {target} -f {file} | grep -v '^#' | cut -d' ' -f2,3",
                            ),
                        ),
                        f"the entry for {target} is {target}'s {build.HOST_KEY}.pub",
                        judge,
                    )
                )
    for server in spec.hosts.values():
        if "inet-server" not in server.services:
            continue
        for host in spec.hosts.values():
            if host.kind == "host" and "curl" in host.packages and spec.shared(host.name, server.name):
                script = (
                    f"curl -s -o /dev/null -w 'http %{{http_code}}\\n' http://{server.name}/\n"
                    f"curl -sk -o /dev/null -w 'https %{{http_code}}\\n' https://{server.name}/"
                )
                found.append(
                    check(
                        "ready: pages of the stand-in internet",
                        f"host {host.name} to {server.name}",
                        [Command(host.name, "root", script)],
                        ["http 200", "https 200"],
                    )
                )
    return found

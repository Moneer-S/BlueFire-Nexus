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
- `conf`: runs `ossec.py` (the lab's edits of the stock ossec.conf) with the
  Python inside the pinned manager image, for the manager and every agent.
- `host-<name>`: one per host built from base, with its packages, its
  ossec.conf, its start script and, last, snoopy in /etc/ld.so.preload.
- `host-<manager>`: the pinned manager image, with the lab's configuration
  under /wazuh-config-mount/, which the image's own start copies into
  /var/ossec, and the stock ossec.conf kept as ossec.conf.stock.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import ossec
from .spec import Spec

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
# source of its own for the SSH connection, so the line takes it from SSH_CONNECTION.
SNOOPY_INI = """\
; snoopy on a range host: one line to syslog for every program start.
[snoopy]
message_format = "[login:%{login} ssh:(%{env:SSH_CONNECTION}) sid:%{sid} uid:%{uid} euid:%{euid} cwd:%{cwd} tag:%{env:BLUEFIRE_TAG}]: %{cmdline}"
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
     [login:root ssh:((undefined)) sid:1 uid:0 euid:0 cwd:/ tag:engine:mark]: uname -r
-->
<decoder name="bluefire-snoopy">
  <program_name>^snoopy$</program_name>
</decoder>

<decoder name="bluefire-snoopy-fields">
  <parent>bluefire-snoopy</parent>
  <regex type="pcre2">^\\[login:(\\S*) ssh:\\((.*?)\\) sid:(\\S*) uid:(\\S*) euid:(\\S*) cwd:(.*?) tag:(\\S*)\\]: (.*)$</regex>
  <order>login, ssh, sid, uid, euid, cwd, tag, command</order>
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
)


@dataclass(frozen=True)
class Rendered:
    folder: Path
    digest: str
    tags: dict[str, str]


def start_script(spec: Spec, host: str) -> str:
    """The entrypoint of a host built from base: its services, its agent, then nothing but sleep."""

    settings = spec.hosts[host]
    lines = [
        "#!/bin/sh",
        "# Starts this range host without an init system: the syslog daemon first, so",
        "# that nothing the others log is lost, then the host's services and its agent.",
        "set -eu",
        "mkdir -p /run/bluefire",
        "rsyslogd",
    ]
    if "sshd" in settings.services:
        lines += [
            "mkdir -p /run/sshd",
            "[ -e /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A",
            "/usr/sbin/sshd",
        ]
    if settings.agent:
        lines.append("/var/ossec/bin/wazuh-control start")
    lines.append("exec sleep infinity")
    return "\n".join(lines) + "\n"


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
            "# the archive of the day: the only packages that do not come from the snapshot.",
            _run(
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
                    f"curl -fsSL --proto '=https' -o /wazuh-agent.deb {url}",
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
        if host.services:
            parts += [
                "# A login must not fail because a container may not set the audit login id.",
                "RUN sed -i -E 's/^(session[[:space:]]+)required([[:space:]]+pam_loginuid[.]so)/\\1optional\\2/' "
                "/etc/pam.d/*",
            ]
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
            f'LABEL {LABEL_RANGE}="{spec.range}"',
        ]
    return "\n".join(parts) + "\n"


def files(spec: Spec) -> dict[str, bytes]:
    """The build context, without bake.json: relative path to content."""

    found = {DOCKERFILE: dockerfile(spec).encode()}
    built = [host for host in spec.hosts.values() if host.built and host.kind != "defense"]
    if built:
        found["files/rsyslog.conf"] = RSYSLOG_CONF.encode()
        found["files/snoopy.ini"] = SNOOPY_INI.encode()
    for host in built:
        found[f"files/range-start-{host.name}"] = start_script(spec, host.name).encode()
    if spec.wazuh:
        found["files/ossec.py"] = Path(ossec.__file__).read_bytes()
        found["files/ossec-settings.json"] = (json.dumps(conf_settings(spec), indent=2) + "\n").encode()
        found["files/local_internal_options.conf"] = LOCAL_INTERNAL_OPTIONS.encode()
        found["files/bluefire_snoopy.xml"] = SNOOPY_DECODER.encode()
        found["files/filebeat-down"] = FILEBEAT_DOWN.encode()
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


def render(spec: Spec, out: Path) -> Rendered:
    """Write the build context and the bake file into the folder `out`."""

    out = Path(out)
    context = files(spec)
    digest = context_hash(context)
    tagged = tags(spec, digest)
    out.mkdir(parents=True, exist_ok=True)
    for relative, content in context.items():
        path = out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (out / BAKE).write_text(json.dumps(bake(spec, tagged), indent=2) + "\n", encoding="utf-8")
    return Rendered(out, digest, tagged)

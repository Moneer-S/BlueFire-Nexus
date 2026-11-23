"""The seal: the checks that show a range has no way out, before anything runs in it.

Every check is a dictionary with the check's name, what it is about, the
command whose output it read, the value it observed, the value it expected and
whether it passed. The functions here read the output of Docker commands and
of the probe script; running those commands is the job of `engine`.
"""

from __future__ import annotations

import ipaddress
import shlex

from .spec import Spec, matrix

LABEL_RUN = "bluefire.lab.run"
LABEL_RANGE = "bluefire.lab.range"
GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
# Containers do not forward packets between their networks. The engine sets this on every
# container: inside a container the value otherwise follows the Docker host's, which can be 1.
SYSCTLS = {"net.ipv4.ip_forward": "0"}
UNSAFE_SECURITY = ("apparmor=unconfined", "seccomp=unconfined", "label=disable", "systempaths=unconfined")
# Addresses outside the range: public resolvers, and the metadata and platform endpoints of
# cloud runners.
OUTSIDE = (("1.1.1.1", 443), ("8.8.8.8", 53), ("169.254.169.254", 80), ("168.63.129.16", 80))
OUTSIDE_NAMES = ("example.com", "host.docker.internal", "gateway.docker.internal")
RESOLVER = "nameserver 127.0.0.11"
PROBE_SECONDS = 3

CONNECTED = "CONNECTED"
ENETUNREACH = "ENETUNREACH"
EHOSTUNREACH = "EHOSTUNREACH"
REFUSED = "REFUSED"
TIMEOUT = "TIMEOUT"
TOOL_ERROR = "TOOL_ERROR"
# A probe that must fail passes only when nothing answered. A refusal means a packet was routed
# to something that answered it.
FAILED_AS_REQUIRED = (ENETUNREACH, EHOSTUNREACH, TIMEOUT)


def check(name: str, subject: str, command: list[str] | str, observed, expected, passed: bool) -> dict:
    return {
        "check": name,
        "subject": subject,
        "command": command if isinstance(command, str) else quote_command(command),
        "observed": observed,
        "expected": expected,
        "pass": bool(passed),
    }


def passed(checks: list[dict]) -> bool:
    return all(item["pass"] for item in checks)


def objects(
    spec: Spec,
    labelled_containers: list[str],
    labelled_networks: list[str],
    prefixed: list[tuple[str, str]],
    containers: dict[str, str],
    networks: dict[str, str],
    run_id: str,
) -> list[dict]:
    """Check a: the run's label and the prefix name exactly the objects the engine recorded.

    `prefixed` holds (ID, name) of every container and network whose name has the prefix.
    """

    label = f"label={LABEL_RUN}={run_id}"
    expected_names = {spec.container_name(host) for host in containers} | {
        spec.network_name(network) for network in networks
    }
    return [
        check(
            "objects: containers",
            "range",
            ["docker", "ps", "-a", "--no-trunc", "-q", "--filter", label],
            sorted(labelled_containers),
            sorted(containers.values()),
            sorted(labelled_containers) == sorted(containers.values()),
        ),
        check(
            "objects: networks",
            "range",
            ["docker", "network", "ls", "--no-trunc", "-q", "--filter", label],
            sorted(labelled_networks),
            sorted(networks.values()),
            sorted(labelled_networks) == sorted(networks.values()),
        ),
        check(
            "objects: names",
            "range",
            f"docker ps -a --no-trunc --filter name={spec.prefix}-; "
            f"docker network ls --no-trunc --filter name={spec.prefix}-",
            sorted(name for _, name in prefixed),
            sorted(expected_names),
            {identifier for identifier, _ in prefixed} == set(containers.values()) | set(networks.values())
            and {name for _, name in prefixed} == expected_names,
        ),
    ]


def joins(inspected: dict, targets: set[str]) -> dict[str, str]:
    """The namespaces a container shares with one of `targets` (container IDs or names), by mode.

    A container started with `--network container:<id>` has no endpoint of its own on any
    network, so only its own `docker inspect` shows that it runs inside a range container's
    network. Docker records the target as its full ID.
    """

    config = inspected.get("HostConfig") or {}
    found = {}
    for key in ("NetworkMode", "PidMode", "IpcMode"):
        value = config.get(key) or ""
        if value.startswith("container:") and value.split(":", 1)[1].lstrip("/") in targets:
            found[key] = value
    return found


def joiners(everything: list[dict], containers: dict[str, str], spec: Spec) -> dict:
    """Check a: no container outside the range shares a namespace with a range container.

    `everything` is `docker inspect` of every container on the daemon.
    """

    targets = set(containers.values()) | {spec.container_name(host) for host in containers}
    found = {}
    for inspected in everything:
        if inspected.get("Id") in containers.values():
            continue
        shared = joins(inspected, targets)
        if shared:
            found[inspected.get("Id", "")] = {"name": inspected.get("Name"), **shared}
    return check(
        "objects: shared namespaces",
        "range",
        "docker ps -a --no-trunc -q; docker inspect <every container>",
        found,
        "no container outside the range in a range container's network, pid or ipc namespace",
        not found,
    )


def network(
    spec: Spec, name: str, identifier: str, inspected: dict, members: dict[str, str] | None
) -> list[dict]:
    """Check b for one network, from `docker network inspect`.

    `members` maps each host that joins the network to its container ID once the
    containers have started. Before that, Docker lists no container on a network.
    """

    command = ["docker", "network", "inspect", identifier]
    subject = f"network {name}"
    options = inspected.get("Options") or {}
    listed = sorted(inspected.get("Containers") or {})
    expected_members = sorted(members.values()) if members is not None else []
    labels = inspected.get("Labels") or {}
    return [
        check(
            "network: id",
            subject,
            command,
            inspected.get("Id"),
            identifier,
            inspected.get("Id") == identifier,
        ),
        check(
            "network: internal",
            subject,
            command,
            inspected.get("Internal"),
            True,
            inspected.get("Internal") is True,
        ),
        check(
            "network: driver",
            subject,
            command,
            inspected.get("Driver"),
            "bridge",
            inspected.get("Driver") == "bridge",
        ),
        check(
            "network: IPv6",
            subject,
            command,
            inspected.get("EnableIPv6"),
            False,
            inspected.get("EnableIPv6") is False,
        ),
        check(
            "network: gateway mode",
            subject,
            command,
            options.get(GATEWAY_MODE),
            "isolated",
            options.get(GATEWAY_MODE) == "isolated",
        ),
        check(
            "network: label",
            subject,
            command,
            labels.get(LABEL_RANGE),
            spec.range,
            labels.get(LABEL_RANGE) == spec.range and inspected.get("Name") == spec.network_name(name),
        ),
        check("network: members", subject, command, listed, expected_members, listed == expected_members),
    ]


def container(
    spec: Spec,
    host: str,
    identifier: str,
    inspected: dict,
    image_id: str,
    networks: dict[str, str],
    started: bool,
) -> list[dict]:
    """Check c for one container, from `docker inspect`."""

    command = ["docker", "inspect", identifier]
    subject = f"container {host}"
    config = inspected.get("HostConfig") or {}
    settings = inspected.get("NetworkSettings") or {}
    joined = settings.get("Networks") or {}
    wanted = {spec.network_name(network): networks.get(network) for network in spec.hosts[host].networks}
    security = config.get("SecurityOpt") or []
    namespaces = {
        key: config.get(key) or "" for key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode")
    }
    mounts = (inspected.get("Mounts") or []) + (config.get("Mounts") or [])
    ports = settings.get("Ports") or {}
    state = (inspected.get("State") or {}).get("Status")
    network_ids = {name: entry.get("NetworkID") for name, entry in joined.items()}
    aliases = {name: entry.get("Aliases") or [] for name, entry in joined.items()}

    def empty(name: str, key: str) -> dict:
        value = config.get(key)
        return check(name, subject, command, value, "empty", not value)

    # --init makes Docker bind-mount its own docker-init program, read-only, at /sbin/docker-init.
    # That mount is not listed under Mounts, so the check names it: only hosts built from base have it.
    settings_of = spec.hosts[host]
    init = settings_of.built and settings_of.kind != "defense"

    return [
        check(
            "container: id",
            subject,
            command,
            inspected.get("Id"),
            identifier,
            inspected.get("Id") == identifier,
        ),
        check(
            "container: name",
            subject,
            command,
            inspected.get("Name"),
            "/" + spec.container_name(host),
            inspected.get("Name") == "/" + spec.container_name(host),
        ),
        check(
            "container: state",
            subject,
            command,
            state,
            "running" if started else "created",
            state == ("running" if started else "created"),
        ),
        check(
            "container: image",
            subject,
            command,
            inspected.get("Image"),
            image_id,
            inspected.get("Image") == image_id,
        ),
        check(
            "container: privileged",
            subject,
            command,
            config.get("Privileged"),
            False,
            config.get("Privileged") is False,
        ),
        empty("container: added capabilities", "CapAdd"),
        empty("container: port bindings", "PortBindings"),
        check(
            "container: publish all ports",
            subject,
            command,
            config.get("PublishAllPorts"),
            False,
            config.get("PublishAllPorts") is False,
        ),
        empty("container: devices", "Devices"),
        empty("container: binds", "Binds"),
        empty("container: volumes from", "VolumesFrom"),
        check("container: mounts", subject, command, mounts, [], not mounts),
        check(
            "container: init",
            subject,
            command,
            config.get("Init"),
            "true: Docker's docker-init, mounted read-only" if init else "not set",
            bool(config.get("Init")) == init,
        ),
        empty("container: extra hosts", "ExtraHosts"),
        empty("container: DNS servers", "Dns"),
        empty("container: DNS options", "DnsOptions"),
        check(
            "container: DNS search",
            subject,
            command,
            config.get("DnsSearch"),
            ["."],
            config.get("DnsSearch") == ["."],
        ),
        check(
            "container: sysctls",
            subject,
            command,
            config.get("Sysctls"),
            SYSCTLS,
            (config.get("Sysctls") or {}) == SYSCTLS,
        ),
        check(
            "container: namespaces",
            subject,
            command,
            namespaces,
            "none is host",
            all(value != "host" for value in namespaces.values()),
        ),
        check(
            "container: security options",
            subject,
            command,
            security,
            f"none of {', '.join(UNSAFE_SECURITY)}",
            not any(option.replace(":", "=") in UNSAFE_SECURITY for option in security),
        ),
        check(
            "container: network mode",
            subject,
            command,
            config.get("NetworkMode"),
            "one of the range's networks",
            config.get("NetworkMode") in set(networks.values()) | {spec.network_name(n) for n in networks},
        ),
        check(
            "container: networks",
            subject,
            command,
            network_ids if started else sorted(joined),
            wanted if started else sorted(wanted),
            network_ids == wanted if started else sorted(joined) == sorted(wanted),
        ),
        check(
            "container: aliases",
            subject,
            command,
            aliases,
            f"{host} on every network",
            bool(aliases) and all(host in names for names in aliases.values()),
        ),
        check(
            "container: published ports",
            subject,
            command,
            ports,
            "no host port",
            all(value is None for value in ports.values()),
        ),
        check(
            "container: label",
            subject,
            command,
            ((inspected.get("Config") or {}).get("Labels") or {}).get(LABEL_RANGE),
            spec.range,
            ((inspected.get("Config") or {}).get("Labels") or {}).get(LABEL_RANGE) == spec.range,
        ),
    ]


def image(host: str, image_ref: str, digest: str, inspected: dict) -> dict:
    """Check f for one host: the image it runs is the one the spec pins by digest."""

    found = [entry.split("@", 1)[1] for entry in inspected.get("RepoDigests") or [] if "@" in entry]
    return check(
        "pins: image digest",
        f"container {host}",
        ["docker", "image", "inspect", inspected.get("Id", "")],
        found,
        digest,
        digest in found,
    )


def built_on(layers: list[str], parent: list[str]) -> bool:
    """True when an image's layers start with every layer of the image it says it was built from."""

    return bool(parent) and layers[: len(parent)] == parent


def built_image(host: str, tag: str, image_id: str, inspected: dict, parent: dict) -> dict:
    """Check f for a host built from the spec: it runs the image found under the tag of this build, on the pinned image.

    The tag carries the hash of the rendered build context. Any image can carry a
    tag, so the check also needs the image's layers to start with the layers of
    the image its Dockerfile pins by digest (`parent`: its reference and layers,
    read from the registry). That shows what the image was built on, not that
    the rest of it is what the context would build today.
    """

    layers = (inspected.get("RootFS") or {}).get("Layers") or []
    found = {
        "id": inspected.get("Id"),
        "tags": inspected.get("RepoTags") or [],
        "built on": parent["image"] if built_on(layers, parent["layers"]) else "not the pinned image",
    }
    return check(
        "pins: built image",
        f"container {host}",
        ["docker", "image", "inspect", inspected.get("Id", "")],
        found,
        {"id": image_id, "tag": tag, "built on": parent["image"]},
        found["id"] == image_id and tag in found["tags"] and built_on(layers, parent["layers"]),
    )


def addresses(inspected: dict, spec: Spec) -> dict[str, str]:
    """A started container's IPv4 address in each range network, by the spec's network name."""

    joined = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    found = {}
    for network in spec.networks:
        entry = joined.get(spec.network_name(network))
        if entry and entry.get("IPAddress"):
            found[network] = entry["IPAddress"]
    return found


def classify(code: int, text: str) -> str:
    """What one probe, `timeout 3 bash -c 'exec 3<>/dev/tcp/<ip>/<port>'`, showed."""

    if code == 0:
        return CONNECTED
    if code == 124:
        return TIMEOUT
    if code == 1:
        if "Network is unreachable" in text:
            return ENETUNREACH
        if "No route to host" in text:
            return EHOSTUNREACH
        if "Connection refused" in text:
            return REFUSED
    return TOOL_ERROR


def script(control: tuple[str, str, int], probes: list[tuple[str, str, int]], names: list[str]) -> str:
    """The probe script run in one container, as root, with bash.

    It uses only bash, coreutils' timeout and getent. The connection that must
    work runs first and alone; then the other probes run side by side. Each
    result is one line of tab-separated fields.
    """

    lines = [
        "probe() {",
        f'  out=$(timeout {PROBE_SECONDS} bash -c "exec 3<>/dev/tcp/$2/$3" 2>&1); code=$?',
        '  printf \'probe\\t%s\\t%s\\t%s\\n\' "$1" "$code" "${out//$\'\\n\'/ }"',
        "}",
        "lookup() {",
        "  out=$(getent hosts \"$1\"); code=$?; found=''",
        '  while read -r address _; do found="$found $address"; done <<< "$out"',
        '  printf \'name\\t%s\\t%s\\t%s\\n\' "$1" "$code" "${found# }"',
        "}",
        f"probe {shlex.quote(control[0])} {shlex.quote(control[1])} {int(control[2])}",
    ]
    lines += [
        f"probe {shlex.quote(label)} {shlex.quote(address)} {int(port)} &" for label, address, port in probes
    ]
    lines += [
        "wait",
        "while IFS= read -r line; do printf 'route\\t%s\\n' \"$line\"; done < /proc/net/route",
        "if [ -e /proc/net/ipv6_route ]; then",
        "  while IFS= read -r line; do printf 'route6\\t%s\\n' \"$line\"; done < /proc/net/ipv6_route",
        "fi",
        "for table in /proc/net/tcp /proc/net/tcp6; do",
        '  if [ -e "$table" ]; then',
        '    while IFS= read -r line; do printf \'tcp\\t%s\\n\' "$line"; done < "$table"',
        "  fi",
        "done",
        "printf 'forward\\t%s\\n' \"$(cat /proc/sys/net/ipv4/ip_forward)\"",
        "for socket in /var/run/docker.sock /run/docker.sock; do",
        '  if [ -e "$socket" ]; then printf \'socket\\t%s\\n\' "$socket"; fi',
        "done",
        "while IFS= read -r line; do",
        "  case \"$line\" in ''|'#'*) ;; *) printf 'resolv\\t%s\\n' \"$line\" ;; esac",
        "done < /etc/resolv.conf",
    ]
    lines += [f"lookup {shlex.quote(name)}" for name in names]
    lines.append("printf 'done\\n'")
    return "\n".join(lines) + "\n"


def parse(output: str) -> dict:
    """The probe script's output, by kind of line."""

    found = {
        "probe": {},
        "name": {},
        "route": [],
        "route6": [],
        "tcp": [],
        "forward": None,
        "socket": [],
        "resolv": [],
        "done": False,
    }
    for line in output.splitlines():
        kind, _, rest = line.partition("\t")
        fields = rest.split("\t")
        if kind == "probe" and len(fields) == 3 and fields[1].isdigit():
            found["probe"][fields[0]] = {"code": int(fields[1]), "text": fields[2]}
        elif kind == "name" and len(fields) == 3 and fields[1].isdigit():
            found["name"][fields[0]] = {"code": int(fields[1]), "addresses": fields[2].split()}
        elif kind in ("route", "route6", "tcp", "socket", "resolv"):
            found[kind].append(rest)
        elif kind == "forward":
            found["forward"] = rest.strip()
        elif kind == "done":
            found["done"] = True
    return found


def _route_networks(lines: list[str]) -> list[str]:
    """The destinations of /proc/net/route, as networks, after its header line."""

    networks = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        destination = ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(fields[1]))))
        mask = ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(fields[7]))))
        networks.append(str(ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)))
    return networks


def _route6_foreign(lines: list[str]) -> list[str]:
    """IPv6 routes other than loopback ones and link-local ones."""

    foreign = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10:
            continue
        device, destination = fields[9], fields[0]
        if device == "lo" or destination.startswith("fe80"):
            continue
        foreign.append(line)
    return foreign


def listening(lines: list[str]) -> list[str]:
    """The TCP sockets in LISTEN state on an address other than loopback, as `address:port`, from the
    lines of /proc/net/tcp and /proc/net/tcp6 (their header lines are skipped)."""

    found = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A" or ":" not in fields[1]:
            continue
        address_hex, port_hex = fields[1].split(":")
        try:
            raw = bytes.fromhex(address_hex)
            port = int(port_hex, 16)
        except ValueError:
            continue
        # The kernel prints each 32-bit word of the address in host order (little-endian here).
        raw = b"".join(bytes(reversed(raw[i : i + 4])) for i in range(0, len(raw), 4))
        address = ipaddress.ip_address(raw)
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            continue
        found.add(f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}")
    return sorted(found)


def in_any(address: str, subnets: list[str]) -> bool:
    try:
        return any(ipaddress.ip_address(address) in ipaddress.ip_network(subnet) for subnet in subnets)
    except ValueError:
        return False


def inside(
    spec: Spec,
    host: str,
    command: list[str],
    exit_code: int,
    output: str,
    plan: dict,
) -> list[dict]:
    """Checks d and e for one container, from the probe script's output.

    `plan` is what `engine` built the script from: the control probe and the
    others, each with what it must do, the subnets of the host's networks and
    the subnets it shares with each other host.
    """

    subject = f"container {host}"
    found = parse(output)
    probes = found["probe"]
    checks = [
        check(
            "probes: script ran",
            subject,
            command,
            {"exit code": exit_code, "finished": found["done"]},
            {"exit code": 0, "finished": True},
            exit_code == 0 and found["done"],
        )
    ]

    def judged(name: str, label: str, must: str) -> dict:
        result = probes.get(label)
        seen = classify(result["code"], result["text"]) if result else TOOL_ERROR
        ok = seen == CONNECTED if must == "connect" else seen in FAILED_AS_REQUIRED
        observed = {"result": seen, "exit code": result["code"] if result else None}
        if result and seen != CONNECTED:
            observed["stderr"] = result["text"][:200]
        expected = CONNECTED if must == "connect" else " or ".join(FAILED_AS_REQUIRED)
        return check(name, f"{subject}: {label}", command, observed, expected, ok)

    control_label = plan["control"][0]
    checks.append(judged("probes: positive control", control_label, "connect"))
    for label, _, _, kind, must in plan["probes"]:
        checks.append(judged(kind, label, must))

    own = plan["subnets"]
    routes = _route_networks(found["route"])
    checks.append(
        check(
            "routes: only own subnets",
            subject,
            command,
            routes,
            sorted(own),
            bool(routes) and all(route in own for route in routes) and "0.0.0.0/0" not in routes,
        )
    )
    foreign6 = _route6_foreign(found["route6"])
    checks.append(
        check("routes: IPv6", subject, command, foreign6, "loopback and link-local only", not foreign6)
    )
    sockets = listening(found["tcp"])
    ports = sorted({int(socket.rsplit(":", 1)[1]) for socket in sockets})
    checks.append(
        check(
            "listening: only declared ports",
            subject,
            command,
            sockets,
            f"TCP ports {plan['listens']} (the spec's listens), on any address but loopback",
            ports == sorted(plan["listens"]),
        )
    )
    checks.append(check("forwarding off", subject, command, found["forward"], "0", found["forward"] == "0"))
    checks.append(check("no Docker socket", subject, command, found["socket"], [], not found["socket"]))
    resolver = found["resolv"]
    servers = [line for line in resolver if line.split()[:1] == ["nameserver"]]
    searches = [line for line in resolver if line.split()[:1] in (["search"], ["domain"])]
    checks.append(
        check(
            "names: resolver",
            subject,
            command,
            resolver,
            f"{RESOLVER} only, no search line",
            servers == [RESOLVER] and not searches,
        )
    )
    for name, shared in plan["names"].items():
        result = found["name"].get(name)
        if shared:
            ok = bool(result) and result["code"] == 0 and all(in_any(a, shared) for a in result["addresses"])
            expected = f"an address in {', '.join(shared)}"
        else:
            ok = bool(result) and result["code"] != 0
            expected = "not found"
        checks.append(check("names: lookup", f"{subject}: {name}", command, result, expected, ok))
    return checks


def plan_for(
    spec: Spec,
    host: str,
    addresses_by_host: dict[str, dict[str, str]],
    subnets: dict[str, list[str]],
    canary: tuple[list[str], int],
) -> dict:
    """What the probe script of one container tries, and what each probe must do.

    `addresses_by_host` maps each host to its address in each of its networks,
    `subnets` each spec network to its subnets, and `canary` holds the
    addresses at which the Docker host could be reached, with the canary's port.
    """

    probes = []
    control = None
    for probe in matrix(spec):
        if probe.source != host:
            continue
        address = addresses_by_host.get(probe.target, {}).get(probe.network, "")
        kind = "segmentation: must connect" if probe.must == "connect" else "segmentation: must fail"
        if probe.must == "connect" and control is None:
            control = ("control " + probe.label, address, probe.port)
        probes.append((probe.label, address, probe.port, kind, probe.must))
    for address, port in OUTSIDE:
        probes.append((f"outside {address}:{port}", address, port, "outside: must fail", "fail"))
    targets, port = canary
    for address in targets:
        probes.append((f"host canary {address}:{port}", address, port, "host canary: must fail", "fail"))
    own = sorted({subnet for network in spec.hosts[host].networks for subnet in subnets.get(network, [])})
    names = {}
    for other in spec.hosts:
        if other == host:
            continue
        names[other] = sorted(
            {subnet for network in spec.shared(host, other) for subnet in subnets.get(network, [])}
        )
    for name in OUTSIDE_NAMES:
        names[name] = []
    return {
        "control": control or ("control (none)", "", 0),
        "probes": probes,
        "subnets": own,
        "names": names,
        "listens": sorted(spec.hosts[host].listens),
    }


def script_for(plan: dict) -> str:
    return script(
        plan["control"],
        [(label, address, port) for label, address, port, _, _ in plan["probes"]],
        list(plan["names"]),
    )


def canary_targets(
    daemon_networks: list[dict], range_subnets: list[str], range_addresses: set[str], rootless: bool
) -> list[str]:
    """Addresses at which a container could reach the Docker host.

    Every gateway of every network the daemon has, the first address of each
    range subnet unless a range container holds it (with the isolated gateway
    mode Docker gives that address to a container), and 10.0.2.2 for rootless
    Docker.
    """

    found = []
    for inspected in daemon_networks:
        for entry in (inspected.get("IPAM") or {}).get("Config") or []:
            gateway = entry.get("Gateway")
            if gateway and gateway not in found:
                found.append(gateway)
    for subnet in range_subnets:
        first = str(next(ipaddress.ip_network(subnet).hosts()))
        if first not in range_addresses and first not in found:
            found.append(first)
    if rootless and "10.0.2.2" not in found:
        found.append("10.0.2.2")
    return found


def quote_command(arguments: list[str]) -> str:
    return " ".join(shlex.quote(argument) for argument in arguments)

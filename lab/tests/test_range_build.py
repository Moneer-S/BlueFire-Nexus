"""The images of a range, rendered from its spec: deterministic, and pinned."""

import copy
import json
from pathlib import Path

from bluefire_lab.range import build
from bluefire_lab.range import spec as range_spec

WAZUH_CHECK = Path(__file__).parents[1] / "range" / "wazuh-check.yaml"


def document() -> dict:
    return range_spec.read(WAZUH_CHECK.read_text())


def loaded(changed: dict | None = None) -> range_spec.Spec:
    return range_spec.parse(changed or document())


def stage(dockerfile: str, name: str) -> str:
    """The lines of one stage of a rendered Dockerfile."""

    lines = dockerfile.split("\n")
    start = next(
        i for i, line in enumerate(lines) if line.startswith("FROM ") and line.endswith(f" AS {name}")
    )
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("FROM ")), len(lines))
    return "\n".join(lines[start:end])


def test_the_same_spec_renders_the_same_files_and_tags(tmp_path: Path) -> None:
    first = build.render(loaded(), tmp_path / "one")
    second = build.render(loaded(), tmp_path / "two")

    names = sorted(p.relative_to(first.folder).as_posix() for p in first.folder.rglob("*") if p.is_file())
    assert names == sorted(
        p.relative_to(second.folder).as_posix() for p in second.folder.rglob("*") if p.is_file()
    )
    for name in names:
        assert (first.folder / name).read_bytes() == (second.folder / name).read_bytes(), name
    assert (
        first.tags
        == second.tags
        == {
            "manager": f"bluefire-lab-wz-manager:{first.digest}",
            "web": f"bluefire-lab-wz-web:{first.digest}",
        }
    )
    assert len(first.digest) == 16


def test_a_changed_spec_changes_the_tag() -> None:
    changed = copy.deepcopy(document())
    changed["defense"]["watch"]["fim_realtime"].append("/srv")
    other = copy.deepcopy(document())
    other["hosts"]["web"]["packages"].append("curl")

    digests = {build.context_hash(build.files(loaded(d))) for d in (document(), changed, other)}

    assert len(digests) == 3


def test_the_bake_file_has_one_target_per_built_host_with_its_tag(tmp_path: Path) -> None:
    rendered = build.render(loaded(), tmp_path)
    bake = json.loads((tmp_path / build.BAKE).read_text())

    assert bake["group"]["default"]["targets"] == ["manager", "web"]
    assert bake["target"]["web"] == {
        "context": ".",
        "dockerfile": "Dockerfile",
        "target": "host-web",
        "tags": [rendered.tags["web"]],
    }


def test_every_base_image_is_pinned_and_the_agent_package_is_checked() -> None:
    spec = loaded()
    dockerfile = build.dockerfile(spec)

    froms = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert {f for f in froms if "@" in f} == {spec.base.image, spec.wazuh.manager_image}
    assert set(froms) - {spec.base.image, spec.wazuh.manager_image} == {"ubuntu", "base"}
    assert f'echo "{spec.wazuh.agent_sha512}  /wazuh-agent.deb" | sha512sum -c -' in stage(
        dockerfile, "fetch"
    )
    assert 'APT::Snapshot "20261120T000000Z"' in stage(dockerfile, "ubuntu")


def test_snoopy_is_preloaded_last_on_an_agent_host_and_the_manager_keeps_its_own_init() -> None:
    dockerfile = build.dockerfile(loaded())
    web = stage(dockerfile, "host-web").splitlines()
    manager = stage(dockerfile, "host-manager")

    runs = [line for line in web if line.startswith(("RUN", "COPY"))]
    assert runs[-1] == f"RUN echo {build.SNOOPY_LIBRARY} > /etc/ld.so.preload"
    assert 'ENTRYPOINT ["/usr/local/sbin/range-start"]' in web
    assert "ENTRYPOINT" not in manager
    assert "COPY --from=conf /out/manager/ossec.conf /wazuh-config-mount/etc/ossec.conf" in manager
    assert "ld.so.preload" not in manager


def test_the_start_script_starts_syslog_the_services_and_the_agent_without_an_init_system() -> None:
    script = build.start_script(loaded(), "web").splitlines()

    assert script[0] == "#!/bin/sh"
    assert (
        script.index("rsyslogd")
        < script.index("/usr/sbin/sshd")
        < script.index("/var/ossec/bin/wazuh-control start")
    )
    assert script[-1] == "exec sleep infinity"
    assert not [line for line in script if "systemctl" in line or "systemd" in line]


def test_the_settings_of_each_agent_are_the_defense_watch_and_then_the_hosts_own() -> None:
    changed = copy.deepcopy(document())
    changed["hosts"]["web"]["watch"] = {
        "logs": [{"path": "/var/log/nginx/access.log", "format": "syslog"}],
        "fim_realtime": ["/var/www", "/tmp"],
    }

    settings = build.conf_settings(loaded(changed))

    web = settings["agents"]["web"]
    assert settings["manager"] == "manager"
    assert [log["path"] for log in web["logs"]] == [
        "/var/log/auth.log",
        "/var/log/snoopy.log",
        "/var/log/dpkg.log",
        "/var/log/nginx/access.log",
    ]
    assert web["fim_realtime"] == ["/etc", "/home", "/root", "/tmp", "/var/tmp", "/var/www"]
    assert web["off"] == ["command_monitoring", "sca", "rootcheck", "syscollector"]

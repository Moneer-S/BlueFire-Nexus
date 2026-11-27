"""The images of a range, rendered from its spec: deterministic, pinned, and with what the spec plants."""

import copy
import dataclasses
import json
import re
import shutil
from pathlib import Path

import pytest

from bluefire_lab.range import atomics, build
from bluefire_lab.range import spec as range_spec

SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
# Stand-in contents of the published files the small range carries, as its lock gives them.
PUBLISHED = {
    "LICENSE.txt": b"The MIT License, a stand-in\n",
    "atomics/T1105/src/atomic.sh": b"#!/bin/sh\necho hello\n",
    "atomics/T1110.004/src/credstuffuserpass.txt": b"root:toor\nadmin:admin\n",
}


def fake_get(url: str) -> bytes:
    return PUBLISHED[url.split("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", 1)[1]]


def document() -> dict:
    return range_spec.read(SMALL.read_text())


def loaded(changed: dict | None = None) -> range_spec.Spec:
    return range_spec.parse(changed or document(), folder=SMALL.parent)


def rendered_files(spec: range_spec.Spec) -> dict[str, bytes]:
    return build.files(spec, atomics.fetch(spec, fake_get))


def stage(dockerfile: str, name: str) -> str:
    """The lines of one stage of a rendered Dockerfile."""

    lines = dockerfile.split("\n")
    start = next(
        i for i, line in enumerate(lines) if line.startswith("FROM ") and line.endswith(f" AS {name}")
    )
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("FROM ")), len(lines))
    return "\n".join(lines[start:end])


def test_the_same_spec_renders_the_same_files_and_tags(tmp_path: Path) -> None:
    first = build.render(loaded(), tmp_path / "one", fake_get)
    second = build.render(loaded(), tmp_path / "two", fake_get)

    names = sorted(p.relative_to(first.folder).as_posix() for p in first.folder.rglob("*") if p.is_file())
    assert names == sorted(
        p.relative_to(second.folder).as_posix() for p in second.folder.rglob("*") if p.is_file()
    )
    for name in names:
        assert (first.folder / name).read_bytes() == (second.folder / name).read_bytes(), name
    assert first.tags == second.tags
    assert first.tags == {
        host: f"bluefire-lab-sm-{host}:{first.digest}" for host in ("manager", "web", "db", "inet")
    }
    assert len(first.digest) == 16


def a_copy(tmp_path: Path) -> Path:
    """The small spec's folder, copied, beside a file outside it that a link could point to."""

    folder = tmp_path / "spec"
    shutil.copytree(SMALL.parent, folder)
    (tmp_path / "outside.txt").write_text("a file of the machine, outside the spec's folder\n")
    return folder


def test_a_file_the_spec_names_that_is_a_link_is_refused(tmp_path: Path) -> None:
    folder = a_copy(tmp_path)
    (folder / "page.txt").unlink()
    (folder / "page.txt").symlink_to(tmp_path / "outside.txt")
    spec = range_spec.parse(document(), folder=folder)

    with pytest.raises(range_spec.SpecError, match="page.txt beside it is a link"):
        rendered_files(spec)


def test_a_file_reached_through_a_linked_folder_is_refused(tmp_path: Path) -> None:
    folder = a_copy(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "page.txt").write_text("outside\n")
    (folder / "linked").symlink_to(tmp_path / "elsewhere")
    changed = document()
    changed["hosts"]["web"]["files"][1]["from"] = "linked/page.txt"
    spec = range_spec.parse(changed, folder=folder)

    with pytest.raises(range_spec.SpecError, match="linked beside it is a link"):
        rendered_files(spec)


def test_a_repository_beside_the_spec_that_holds_a_link_is_refused(tmp_path: Path) -> None:
    folder = a_copy(tmp_path)
    repository = folder / range_spec.REPOS / "shop"
    repository.mkdir(parents=True)
    (repository / "Makefile").write_text("all:\n")
    (repository / "notes.txt").symlink_to(tmp_path / "outside.txt")
    spec = dataclasses.replace(loaded(), folder=folder)

    with pytest.raises(range_spec.SpecError, match="notes.txt beside the spec is a link"):
        build.repo_files(spec, "shop")
    (repository / "notes.txt").unlink()
    assert build.repo_files(spec, "shop") == {"Makefile": b"all:\n"}


def test_a_changed_spec_changes_the_tag() -> None:
    changed = copy.deepcopy(document())
    changed["defense"]["watch"]["fim_realtime"].append("/srv")
    other = copy.deepcopy(document())
    other["hosts"]["web"]["files"][0]["mode"] = "0600"

    digests = {build.context_hash(rendered_files(loaded(d))) for d in (document(), changed, other)}

    assert len(digests) == 3


def test_the_bake_file_has_one_target_per_built_host_with_its_tag(tmp_path: Path) -> None:
    rendered = build.render(loaded(), tmp_path, fake_get)
    bake = json.loads((tmp_path / build.BAKE).read_text())

    assert bake["group"]["default"]["targets"] == ["manager", "web", "db", "inet"]
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


def test_a_download_that_fails_is_tried_again_before_it_fails_the_build() -> None:
    dockerfile = build.dockerfile(loaded())
    ubuntu = stage(dockerfile, "ubuntu")

    # The setting goes into apt's own settings folder before the first package list is fetched,
    # and every stage that installs a package starts from this one.
    written = ubuntu.index("echo 'Acquire::Retries \"8\";' > /etc/apt/apt.conf.d/80retries")
    assert written < ubuntu.index("apt-get update")
    assert "curl -fsSL --retry 5 --retry-all-errors " in stage(dockerfile, "fetch")


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
    assert "ld.so.preload" not in stage(dockerfile, "host-inet")


def test_the_start_script_starts_syslog_the_services_and_the_agent_without_an_init_system() -> None:
    spec = loaded()
    web = build.start_script(spec, "web").splitlines()
    db = build.start_script(spec, "db").splitlines()
    inet = build.start_script(spec, "inet")

    assert web[0] == "#!/bin/sh"
    assert (
        web.index("rsyslogd") < web.index("/usr/sbin/sshd") < web.index("/var/ossec/bin/wazuh-control start")
    )
    assert web[-1] == "exec sleep infinity"
    assert "mysqld --user=mysql > /dev/null 2>&1 &" in db
    # Every log the agent reads exists before the agent starts.
    assert db.index(
        'for log in /var/log/auth.log /var/log/snoopy.log /var/log/dpkg.log; do [ -e "$log" ] || : > "$log"; done'
    ) < db.index("/var/ossec/bin/wazuh-control start")
    assert f"python3 {build.INET_SERVER} {build.INET_TREE} {build.INET_UPLOADS} {build.INET_LOG}" in inet
    assert "wazuh-control" not in inet
    for script in (web, db, inet.splitlines()):
        assert not [line for line in script if "systemctl" in line or "systemd" in line]


def test_a_packet_capture_starts_on_every_non_loopback_interface_before_the_services() -> None:
    changed = copy.deepcopy(document())
    changed["hosts"]["web"]["packages"].append("tcpdump")
    changed["hosts"]["web"]["capture"] = "packets"

    script = build.start_script(loaded(changed), "web")
    lines = script.splitlines()
    command = next(line for line in lines if "tcpdump -i" in line)

    assert "for path in /sys/class/net/*; do" in lines
    assert '  iface=${path##*/}; [ "$iface" = lo ] && continue' in lines
    assert '-i "$iface" -p -nn -s 0 -U -Z tcpdump' in command
    assert build.CAPTURE_FILTER in command
    assert f'-w "{build.CAPTURE_DIR}/$iface.pcap"' in command
    assert f'2> "{build.CAPTURE_DIR}/$iface.log" &' in command
    assert f'  armed_file="{build.CAPTURE_RUN}/$iface{build.CAPTURE_ARMED_SUFFIX}"' in lines
    assert f'  pid_file="{build.CAPTURE_RUN}/$iface.pid"' in lines
    assert f'  status_file="{build.CAPTURE_RUN}/$iface{build.CAPTURE_STATUS_SUFFIX}"' in lines
    assert "    stopping=0" in lines
    assert any("forward_term() { stopping=1;" in line for line in lines)
    assert any("forward_int() { stopping=1;" in line for line in lines)
    assert "    trap forward_term TERM" in lines
    assert "    trap forward_int INT" in lines
    stopping_checks = [
        number for number, line in enumerate(lines) if line == '    if [ "$stopping" -ne 0 ]; then'
    ]
    assert len(stopping_checks) == 2
    before_child, after_child = stopping_checks
    armed = next(line for line in lines if 'printf "%s\\n" "$child" > "$armed_file.partial"' in line)
    assert '! mv "$armed_file.partial" "$armed_file"; then' in armed
    assert '      kill -TERM "$child" 2>/dev/null || :' in lines
    assert '      wait "$child"' in lines
    assert lines.index(armed) < lines.index("    set +e")
    assert '    wait "$child"' in lines
    assert '    printf "%s\\n" "$code" > "$status_file.partial"' in lines
    assert '    mv "$status_file.partial" "$status_file"' in lines
    normal_wait = next(
        number
        for number, line in enumerate(lines)
        if line == '    wait "$child"' and number > lines.index(armed)
    )
    assert (
        lines.index("    trap forward_term TERM")
        < before_child
        < lines.index(command)
        < lines.index("    child=$!")
        < after_child
        < lines.index(armed)
        < normal_wait
        < lines.index("  pid=$!")
    )
    assert lines.index("  pid=$!") < lines.index('  printf "%s\\n" "$pid" > "$pid_file.partial"')
    assert '  mv "$pid_file.partial" "$pid_file"' in lines
    assert f'  while [ ! -s "{build.CAPTURE_DIR}/$iface.pcap" ] || [ ! -s "$armed_file" ]; do' in lines
    assert any(line.strip() == '[ ! -e "$status_file" ] || exit 1' for line in lines)
    assert '  [ -s "$armed_file" ] && [ ! -e "$status_file" ] || exit 1' in lines
    assert any(line.strip() == 'kill -0 "$pid"' for line in lines)
    assert lines.index("rsyslogd") < lines.index(command) < lines.index("/usr/sbin/sshd")
    assert "--cap-add" not in script


def test_the_settings_of_each_agent_are_the_defense_watch_and_then_the_hosts_own() -> None:
    changed = copy.deepcopy(document())
    changed["hosts"]["web"]["watch"] = {
        "logs": [{"path": "/var/log/nginx/access.log", "format": "syslog"}],
        "fim_realtime": ["/var/www", "/tmp"],
    }

    settings = build.conf_settings(loaded(changed))

    web = settings["agents"]["web"]
    assert settings["manager"] == "manager"
    assert sorted(settings["agents"]) == ["db", "web"]
    assert [log["path"] for log in web["logs"]] == [
        "/var/log/auth.log",
        "/var/log/snoopy.log",
        "/var/log/dpkg.log",
        "/var/log/nginx/access.log",
    ]
    assert web["fim_realtime"] == ["/etc", "/home", "/root", "/tmp", "/var/tmp", "/var/www"]
    assert web["off"] == ["command_monitoring", "sca", "rootcheck", "syscollector"]


def test_accounts_get_their_shell_and_password_and_an_account_without_one_is_not_locked() -> None:
    web = stage(build.dockerfile(loaded()), "host-web")

    assert "useradd --create-home --shell /bin/bash admin" in web
    assert "echo admin:admin | chpasswd" in web
    assert "useradd --create-home --shell /bin/sh app" in web
    # A password field of * lets a key log the account in, where useradd's ! would lock it.
    assert "usermod -p '*' app" in web
    assert "COPY --chmod=0440 files/web/sudoers-admin /etc/sudoers.d/admin" in web


def test_the_sudo_rule_names_only_the_commands_the_spec_gives() -> None:
    files = rendered_files(loaded())

    assert files["files/web/sudoers-admin"] == b"admin ALL=(root) NOPASSWD: /usr/bin/id\n"


def test_keys_are_made_in_the_keys_stage_and_copied_with_their_owner_and_mode() -> None:
    spec = loaded()
    web = stage(build.dockerfile(spec), "host-web")
    script = build.keys_script(spec)
    admin_ssh = build.home("admin") + "/.ssh"
    app_ssh = build.home("app") + "/.ssh"

    assert "ssh-keygen -q -t ed25519 -N '' -C 'host key of web' -f /keys/host/web" in script
    assert "ssh-keygen -q -t rsa -b 3072 -N '' -C 'admin@web' -f /keys/key/deploy" in script
    assert "cat /keys/key/deploy.pub >> /keys/authorized/web/app" in script
    # The known_hosts entry names the host as the path's ssh looks it up: by its name alone.
    assert (
        "printf '%s %s\\n' web \"$(cut -d' ' -f1,2 /keys/host/web.pub)\" >> /keys/known_hosts/web/admin"
        in script
    )
    assert f"COPY --from=keys --chown=admin:admin --chmod=0600 /keys/key/deploy {admin_ssh}/id_rsa" in web
    assert (
        f"COPY --from=keys --chown=app:app --chmod=0600 /keys/authorized/web/app {app_ssh}/authorized_keys"
        in web
    )
    assert f"install -d -m 0700 -o admin -g admin {admin_ssh}" in web
    # The host keys the package made are replaced by the one made in the keys stage.
    assert web.index("RUN rm -f /etc/ssh/ssh_host_*") < web.index(f"/keys/host/web {build.HOST_KEY}")


def test_the_ssh_server_takes_the_spec_settings_and_pam_unix_loses_its_delay() -> None:
    spec = loaded()
    web = stage(build.dockerfile(spec), "host-web")
    conf = rendered_files(spec)["files/web/sshd.conf"].decode()

    assert "PasswordAuthentication yes\n" in conf
    assert "PermitRootLogin no\n" in conf
    assert f"HostKey {build.HOST_KEY}\n" in conf
    assert "/usr/sbin/sshd -t" in web
    assert "s/$/ nodelay/' /etc/pam.d/common-auth" in web
    # The build stops if the edit did not take.
    assert "grep -Eq '^auth[[:space:]].*pam_unix[.]so.* nodelay$' /etc/pam.d/common-auth" in web


def test_folders_and_files_get_their_owner_group_and_mode_and_their_content() -> None:
    spec = loaded()
    web = stage(build.dockerfile(spec), "host-web")
    files = rendered_files(spec)

    assert "install -d -o app -g app -m 0750 /srv/drop" in web
    assert "COPY --chown=root:app --chmod=0640 files/web/plant-1 /etc/app/secret.env" in web
    assert "COPY --chown=root:root --chmod=0644 files/web/plant-2 /srv/app/page.txt" in web
    # The folders come first: a COPY with --chmod would give a folder it makes the file's mode.
    assert web.index("RUN mkdir -p /etc/app /srv/app") < web.index("files/web/plant-1")
    assert files["files/web/plant-1"] == b"TOKEN=small-range-token\n"
    assert files["files/web/plant-2"] == (SMALL.parent / "page.txt").read_bytes()


def test_the_database_is_made_at_build_by_a_script_that_starts_and_stops_the_server() -> None:
    spec = loaded()
    db = stage(build.dockerfile(spec), "host-db")
    files = rendered_files(spec)
    script = files["files/db/db-init.sh"].decode()
    sql = files["files/db/db-init.sql"].decode()

    assert "RUN sh /tmp/db-init/db-init.sh && rm -rf /tmp/db-init" in db
    # The log the spec names exists, and the server, which runs as mysql, may write it.
    assert "chown mysql:adm /var/log/mysql/error.log" in db
    assert (
        script.index("mysqld --user=mysql --skip-networking")
        < script.index("mariadb < ")
        < script.index("mariadb-admin shutdown")
    )
    assert "CREATE USER 'store'@'%' IDENTIFIED BY 'Store-Db-1';" in sql  # pragma: allowlist secret
    assert "GRANT ALL PRIVILEGES ON `store`.* TO 'store'@'%';" in sql
    assert files["files/db/mariadb.cnf"].decode().splitlines()[-2:] == [
        "bind-address = 0.0.0.0",
        "log_error = /var/log/mysql/error.log",
    ]


def test_served_and_carried_files_are_copied_as_data_and_no_step_runs_them() -> None:
    spec = loaded()
    dockerfile = build.dockerfile(spec)
    inet = stage(dockerfile, "host-inet")
    web = stage(dockerfile, "host-web")
    files = rendered_files(spec)

    assert f"COPY --chmod=0444 atomics/T1105/src/atomic.sh {build.INET_TREE}/files/hello.sh" in inet
    assert "COPY atomics/T1110.004/src /opt/atomics/T1110.004/src" in web
    assert files["files/COMMIT"] == b"a" * 40 + b"\n"
    assert files["atomics/T1105/src/atomic.sh"] == PUBLISHED["atomics/T1105/src/atomic.sh"]
    # No RUN line names a published file, where the build context has it or where the image has it.
    runs = [line for line in dockerfile.splitlines() if line.startswith("RUN") or line.startswith(" && ")]
    assert not [line for line in runs if re.search(r"atomics/|/opt/atomics|hello\.sh|atomic\.sh", line)]


def test_the_published_projects_licence_travels_with_its_files_in_the_context_and_the_images() -> None:
    spec = loaded()
    dockerfile = build.dockerfile(spec)
    files = rendered_files(spec)

    # Beside the published files in the build context, which a CI run uploads with the run's folder.
    assert files["atomics/LICENSE.txt"] == PUBLISHED["LICENSE.txt"]
    for host in ("web", "inet"):
        assert "COPY --chmod=0444 atomics/LICENSE.txt /opt/atomics/LICENSE.txt" in stage(
            dockerfile, f"host-{host}"
        )
    assert "LICENSE" not in stage(dockerfile, "host-db")


def test_the_managers_api_listens_on_loopback_only_and_the_change_is_labelled() -> None:
    spec = loaded()
    manager = stage(build.dockerfile(spec), "host-manager")

    assert "COPY files/wazuh-api.yaml /wazuh-config-mount/api/configuration/api.yaml" in manager
    assert "host: ['127.0.0.1']" in rendered_files(spec)["files/wazuh-api.yaml"].decode()
    assert {"label": "removed", "file": build.WAZUH_API_FILE} in [
        {"label": item["label"], "file": item["file"]} for item in build.MANAGER_FILES
    ]

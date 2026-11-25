#!/usr/bin/env python3
"""Plant files in scratch repositories and check what the privacy scan says.

Run: python3 .github/scripts/test_privacy_scan.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

SCAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "privacy_scan.py")

# git exports variables such as GIT_DIR to hooks. Left in place, they would point
# the scratch repositories' commands at the repository the test was started from.
CLEAN = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}

# The strings the scan rejects are built from parts, so that this file passes it.
HOME = "/" + "home"
MAC_HOME = "/" + "Users"
WINDOWS_HOME = "C:" + "\\Users"
WINDOWS_HOME_IN_JSON = "C:" + "\\\\Users"
MARKERS = ("anti_" + "larping_acceptance_contract", "bluefire_real_" + "product_completion_prompt")


def git(repository: str, *arguments: str) -> str:
    settings = ["core.hooksPath=/dev/null", "commit.gpgsign=false", "user.name=lab", "user.email=lab@example.invalid"]
    command = ["git", "-C", repository, *(part for item in settings for part in ("-c", item)), *arguments]
    return subprocess.run(command, check=True, capture_output=True, text=True, env=CLEAN).stdout


def plant(repository: str, files: dict[str, bytes], links: dict[str, str] | None = None) -> None:
    for name, data in files.items():
        path = os.path.join(repository, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    for name, target in (links or {}).items():
        os.symlink(target, os.path.join(repository, name))
    git(repository, "add", "--all", "--force")


def run_scan(*arguments: str, cwd: str | None = None, env: dict | None = None) -> tuple[int, str, str]:
    command = [sys.executable, SCAN, *arguments]
    done = subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd, env=env or CLEAN)
    return done.returncode, done.stdout, done.stderr


def scan(files: dict[str, bytes], links: dict[str, str] | None = None) -> tuple[int, str]:
    """Track the given files in a new repository and run the scan on it."""

    with tempfile.TemporaryDirectory() as repository:
        git(repository, "init", "--quiet")
        plant(repository, files, links)
        status, output, _ = run_scan(repository)
        return status, output


class PrivacyScan(unittest.TestCase):
    def test_tree_that_names_only_runner_and_lab_accounts_passes(self) -> None:
        telemetry = "\n".join(
            [
                f'cwd={HOME}/runner/work/project image="{HOME}/runner"',
                f"<Data>{MAC_HOME}/runner</Data> &quot;{HOME}/runner&quot;",
                f"{WINDOWS_HOME}\\runneradmin\\AppData",
                f'{{"path": "{WINDOWS_HOME_IN_JSON}\\\\runneradmin\\\\AppData"}}',
                f"PATH=/usr/local/bin:{MAC_HOME}/runner/.cargo/bin",
                f"file://{MAC_HOME}/runner/work/report.html",
                f"The workspace is under {HOME}/runner.",
                f"rm {HOME}/bluefire-lab/.bash_history",
                f"useradd --create-home art; ls {HOME}/art/.bashrc",
                f"/tmp/claude-1000/-{HOME[1:]}-runner-work-project/x and /tmp/pytest" + "-of-runner/pytest-0",
            ]
        )
        not_names = "\n".join(
            [
                f"TargetFilename|startswith: '{HOME}/'",
                f'path.startswith("{HOME}/") or "{MAC_HOME}/" + user',
                f"{HOME}/*/.ssh/authorized_keys {HOME}/<user> {HOME}/$USER {HOME}/{{user}}",
                f"{WINDOWS_HOME}\\%USERNAME%\\AppData {WINDOWS_HOME}\\*\\AppData",
            ]
        )
        files = {
            "README.md": b"hello\n",
            "lab/telemetry.txt": telemetry.encode(),
            "lab/telemetry-utf16.txt": telemetry.encode("utf-16"),
            "lab/rules.txt": not_names.encode(),
        }
        self.assertEqual(scan(files), (0, ""))

    def test_home_path_is_reported_with_its_line_and_never_its_text(self) -> None:
        with tempfile.TemporaryDirectory() as repository:
            git(repository, "init", "--quiet")
            secret = f"first line\nsaved to {HOME}/alice/secretproject\n"
            plant(repository, {"docs/notes.txt": secret.encode(), "docs/private.md": f"x {MARKERS[0]}".encode()})
            status, output, errors = run_scan(repository)
        self.assertEqual((status, output), (1, "docs/notes.txt:2: user home path\ndocs/private.md: private marker\n"))
        for text in ("alice", "secretproject", MARKERS[0]):
            self.assertNotIn(text, output + errors)
        self.assertIn("user home path: ", errors)
        self.assertIn("private marker: ", errors)

    def test_every_form_of_home_path_is_reported_in_line_order(self) -> None:
        lines = [
            f"{HOME}/alice",
            f"{MAC_HOME}/alice/Library",
            f"{WINDOWS_HOME}\\alice\\Desktop",
            f'{{"path": "{WINDOWS_HOME_IN_JSON}\\\\alice\\\\Desktop"}}',
            "c:/" + "users/alice",
            "D:" + "\\Users" + "\\alice",
            "\\\\wsl.localhost\\Ubuntu" + "\\home" + "\\alice\\project",
            "\\Device\\HarddiskVolume3" + "\\Users" + "\\alice\\tool.exe",
            '{"cwd": "\\/' + 'home\\/alice\\/project"}',
            f"{HOME}/\\u00c9lodie/project",
            f"{HOME}//alice",
            "/tmp/claude-1000/-" + "home-alice-project/out.txt",
            "C--" + "Users-alice-project",
            "/tmp/pytest" + "-of-alice/pytest-0",
            f"{HOME}/runner2",
            f"{HOME}/runner.old",
            f"{HOME}/Runner",
            f"{HOME}/runner@corp.example",
            f"{HOME}/runneradmin",
            f"{WINDOWS_HOME}\\runneradministrator",
            f"{MAC_HOME}/bluefire-lab",
            f"{HOME}/bluefire-labs",
            f"{HOME}/arthur",
            f"{MAC_HOME}/art",
            "/x/-" + "home-runnerx-project",
            f'{{"a":"{HOME}/runner","b":"{WINDOWS_HOME_IN_JSON}\\\\alice"}}',
            f"{HOME}/alice then {HOME}/runner",
        ]
        status, output = scan({"paths.txt": "\n".join(lines).encode()})
        self.assertEqual(status, 1)
        self.assertEqual(output.splitlines(), [f"paths.txt:{number}: user home path" for number in range(1, len(lines) + 1)])

    def test_utf16_text_is_read_for_markers_and_home_paths(self) -> None:
        files = {
            "a.md": f"notes\n{MARKERS[0]}\n".encode(),
            "b.txt": f"notes {MARKERS[1]}".encode("utf-16"),
            "c.txt": f"first\nsaved to {HOME}/alice/out\n".encode("utf-16"),
            "d.txt": f"Image: {WINDOWS_HOME}\\Роман\\tool.exe".encode("utf-16-le"),
        }
        status, output = scan(files)
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            ["a.md: private marker", "b.txt: private marker", "c.txt:2: user home path", "d.txt:1: user home path"],
        )

    def test_home_path_inside_a_binary_file_is_reported(self) -> None:
        status, output = scan({"image.bin": b"\x89PNG\x00\xff" + f"{HOME}/alice".encode() + b"\xfe"})
        self.assertEqual((status, output), (1, "image.bin:1: user home path\n"))

    def test_names_of_files_are_scanned(self) -> None:
        files = {f"capture{HOME}/alice/.bash_history": b"ls\n", f"notes/{MARKERS[1]}.md": b"plain text\n"}
        status, output = scan(files)
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            [
                f"capture{HOME}/alice/.bash_history (file name): user home path",
                f"notes/{MARKERS[1]}.md (file name): private marker",
            ],
        )

    def test_every_kind_that_is_never_committed_is_reported(self) -> None:
        suffixes = [".db", ".sqlite", ".sqlite3", ".log", ".trace", ".key", ".PEM", ".p12", ".pfx"]
        suffixes += [".gz", ".tgz", ".zip", ".tar", ".7z", ".xz", ".bz2", ".rar"]
        folders = ["node_modules", "__pycache__", ".pytest_cache", "runs", "build", "Build"]
        planted = {f"kinds/file{suffix}": "file kind" for suffix in suffixes}
        planted |= {f"out/{folder}/file.txt": "output folder" for folder in folders}
        allowed = {"runs.txt": b"x", "scripts/build": b"x", "docs/building.md": b"x"}
        status, output = scan({name: b"x" for name in planted} | allowed)
        self.assertEqual(status, 1)
        expected = [f"{name}: {kind} never committed" for name, kind in sorted(planted.items())]
        self.assertEqual(output.splitlines(), expected)

    def test_link_to_a_home_path_is_reported(self) -> None:
        status, output = scan({"README.md": b"x"}, links={"data": f"{HOME}/alice/data"})
        self.assertEqual((status, output), (1, "data:1: user home path\n"))

    def test_an_accepted_string_is_accepted_only_in_its_file_and_only_whole(self) -> None:
        lab_home = f"{HOME}/bluefire"
        files = {
            "bluefire/prepared_lab.py": f'HOME = "{lab_home}"\n'.encode(),
            "bluefire/prepared_lab_install.py": f'NOTES = "{lab_home}/private-notes"\n'.encode(),
            "docs/notes.txt": f"{lab_home}\n".encode(),
        }
        status, output = scan(files)
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            ["bluefire/prepared_lab_install.py:1: user home path", "docs/notes.txt:1: user home path"],
        )

    def test_the_range_path_recording_accepts_its_home_folder_and_no_other_file_does(self) -> None:
        web_home = f"{HOME}/webadmin"
        lines = (
            f'"command": "find {web_home} -name id_rsa"\n'
            f'"text": "cat {web_home}/.ssh/id_rsa {web_home}/.ssh/known_hosts"\n'
        )
        files = {
            "bluefire/data/recordings/lab-range-one-path.json": f"{lines}{web_home}/notes.txt\n".encode(),
            "bluefire/data/recordings/other.json": lines.encode(),
            "docs/notes.md": f"{web_home}/notes.txt\n".encode(),
        }
        status, output = scan(files)
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            [
                "bluefire/data/recordings/lab-range-one-path.json:3: user home path",
                "bluefire/data/recordings/other.json:1: user home path",
                "bluefire/data/recordings/other.json:2: user home path",
                "docs/notes.md:1: user home path",
            ],
        )

    def test_the_range_path_page_accepts_its_home_folder_and_no_other_page_does(self) -> None:
        web_home = f"{HOME}/webadmin"
        line = (
            f'{{"command":"find {web_home} -name id_rsa",'
            f'"text":"cat {web_home}/.ssh/id_rsa","text":"cat {web_home}/.ssh/known_hosts"}}\n'
        )
        files = {
            "docs/live-view/attack-path.html": f"{line}{web_home}/notes.txt\n".encode(),
            "docs/live-view/replay.html": line.encode(),
        }
        status, output = scan(files)
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            ["docs/live-view/attack-path.html:2: user home path", "docs/live-view/replay.html:1: user home path"],
        )

    def test_the_whole_repository_is_scanned_from_a_subfolder(self) -> None:
        with tempfile.TemporaryDirectory() as repository:
            git(repository, "init", "--quiet")
            plant(repository, {"docs/notes.txt": f"{HOME}/alice\n".encode(), "lab/clean.txt": b"x\n"})
            status, output, _ = run_scan(os.path.join(repository, "lab"))
        self.assertEqual((status, output), (1, "docs/notes.txt:1: user home path\n"))

    def test_git_variables_of_a_hook_do_not_redirect_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as other, tempfile.TemporaryDirectory() as repository:
            git(other, "init", "--quiet")
            plant(other, {"clean.txt": b"x\n"})
            git(repository, "init", "--quiet")
            plant(repository, {"notes.txt": f"{HOME}/alice\n".encode()})
            hook = CLEAN | {"GIT_DIR": os.path.join(other, ".git"), "GIT_WORK_TREE": other}
            status, output, _ = run_scan(repository, env=hook)
        self.assertEqual((status, output), (1, "notes.txt:1: user home path\n"))

    def test_commits_are_scanned_even_when_a_later_commit_removed_the_path(self) -> None:
        with tempfile.TemporaryDirectory() as repository:
            git(repository, "init", "--quiet")
            plant(repository, {"README.md": b"x\n"})
            git(repository, "commit", "--quiet", "-m", "first")
            base = git(repository, "rev-parse", "HEAD").strip()
            plant(repository, {"notes.txt": f"line one\n{HOME}/alice/out\n".encode()})
            git(repository, "commit", "--quiet", "-m", "add a path")
            added = git(repository, "rev-parse", "HEAD").strip()
            plant(repository, {"notes.txt": b"line one\n<home>/out\n"})
            git(repository, "commit", "--quiet", "-m", "remove it")
            tree = run_scan(repository)
            commits = run_scan("--commits", f"{base}..HEAD", cwd=repository)
        self.assertEqual(tree[:2], (0, ""))
        self.assertEqual(commits[:2], (1, f"commit {added[:12]} notes.txt:2: user home path\n"))

    def test_a_wrong_command_line_is_refused(self) -> None:
        self.assertEqual(run_scan("--commits")[0], 2)
        self.assertEqual(run_scan("--everything")[0], 2)


if __name__ == "__main__":
    unittest.main()

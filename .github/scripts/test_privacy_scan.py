#!/usr/bin/env python3
"""Plant files in a scratch repository and check what the privacy scan says.

Run: python3 .github/scripts/test_privacy_scan.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

SCAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "privacy_scan.py")

# The strings the scan rejects are built from parts, so that this file passes it.
HOME = "/" + "home"
MAC_HOME = "/" + "Users"
WINDOWS_HOME = "C:" + "\\Users"
WINDOWS_HOME_IN_JSON = "C:" + "\\\\Users"
MARKERS = ("anti_" + "larping_acceptance_contract", "bluefire_real_" + "product_completion_prompt")


def scan(files: dict[str, bytes], links: dict[str, str] | None = None) -> tuple[int, str]:
    """Track the given files in a new repository and run the scan on it."""

    with tempfile.TemporaryDirectory() as repository:
        subprocess.run(["git", "init", "--quiet", repository], check=True)
        for name, data in files.items():
            path = os.path.join(repository, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)
        for name, target in (links or {}).items():
            os.symlink(target, os.path.join(repository, name))
        subprocess.run(["git", "-C", repository, "add", "--all", "--force"], check=True)
        result = subprocess.run(
            [sys.executable, SCAN, repository], capture_output=True, text=True, check=False
        )
        return result.returncode, result.stdout


class PrivacyScan(unittest.TestCase):
    def test_tree_that_names_only_hosted_runner_accounts_passes(self) -> None:
        telemetry = (
            f'cwd={HOME}/runner/work/project image="{HOME}/runner"\n'
            f"<Data>{MAC_HOME}/runner</Data>\n"
            f"{WINDOWS_HOME}\\runneradmin\\AppData\n"
            f'{{"path": "{WINDOWS_HOME_IN_JSON}\\\\runneradmin\\\\AppData"}}\n'
        )
        status, output = scan({"README.md": b"hello\n", "lab/telemetry.txt": telemetry.encode()})
        self.assertEqual((status, output), (0, ""))

    def test_home_path_is_reported_with_its_line_and_without_its_text(self) -> None:
        status, output = scan({"docs/notes.txt": f"first line\nsaved to {HOME}/alice/out\n".encode()})
        self.assertEqual((status, output), (1, "docs/notes.txt:2: user home path\n"))

    def test_every_form_of_home_path_is_reported(self) -> None:
        lines = [
            f"{HOME}/alice",
            f"{MAC_HOME}/alice/Library",
            f"{WINDOWS_HOME}\\alice\\Desktop",
            f'{{"path": "{WINDOWS_HOME_IN_JSON}\\\\alice\\\\Desktop"}}',
            "c:/" + "users/alice",
            f"{HOME}/runner2",
            f"{HOME}/runner.old",
            f"{HOME}/Runner",
            f"{WINDOWS_HOME}\\runneradministrator",
        ]
        status, output = scan({"paths.txt": "\n".join(lines).encode()})
        self.assertEqual(status, 1)
        self.assertEqual(
            output.splitlines(),
            sorted(f"paths.txt:{number}: user home path" for number in range(1, len(lines) + 1)),
        )

    def test_marker_is_reported_in_utf8_and_utf16(self) -> None:
        status, output = scan(
            {
                "a.md": f"notes\n{MARKERS[0]}\n".encode(),
                "b.txt": f"notes {MARKERS[1]}".encode("utf-16"),
            }
        )
        self.assertEqual((status, output), (1, "a.md: private marker\nb.txt: private marker\n"))

    def test_home_path_inside_a_binary_file_is_reported(self) -> None:
        status, output = scan({"image.bin": b"\x89PNG\x00\xff" + f"{HOME}/alice".encode() + b"\xfe"})
        self.assertEqual((status, output), (1, "image.bin:1: user home path\n"))

    def test_file_kinds_that_are_never_committed_are_reported(self) -> None:
        planted = ["debug.log", "output/runs/7/report.html", "state.sqlite3", "tls/server.PEM"]
        status, output = scan({name: b"x" for name in planted} | {"runs.txt": b"x"})
        self.assertEqual(status, 1)
        self.assertEqual(output.splitlines(), [f"{name}: never committed" for name in planted])

    def test_link_to_a_home_path_is_reported(self) -> None:
        status, output = scan({"README.md": b"x"}, links={"data": f"{HOME}/alice/data"})
        self.assertEqual((status, output), (1, "data:1: user home path\n"))


if __name__ == "__main__":
    unittest.main()

"""Watchdog imports must not require the host application's third-party packages."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_IMPORT_PROBE = r"""
# CPython 3.10's stdlib copy probes optional Jython support. Initialize it
# before the dependency guard; do not allow that package during watchdog imports.
import copy
import importlib
import importlib.abc
import json
import runpy
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
branch = sys.argv[2]
script = root / "bluefire" / "runner_watchdog.py"
assert sys.flags.isolated == 1 and sys.flags.no_site == 1
assert "site" not in sys.modules
assert "cryptography" not in sys.modules
assert "org" not in sys.modules
blocked = []

class LocalAndStdlibOnly(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        top_level = fullname.partition(".")[0]
        if top_level != "bluefire" and top_level not in sys.stdlib_module_names:
            blocked.append(fullname)
            raise ModuleNotFoundError(
                "Third-party import refused by watchdog regression: " + fullname,
                name=fullname,
            )
        return None

def refuse_effects(event, args):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn"
    }:
        raise AssertionError("Import-only probe attempted an effect: " + event)

sys.addaudithook(refuse_effects)
sys.meta_path.insert(0, LocalAndStdlibOnly())
sys.path.insert(0, str(root))
if branch == "package":
    module = importlib.import_module("bluefire.runner_watchdog")
    namespace = vars(module)
    assert namespace["__package__"] == "bluefire"
elif branch == "script":
    # A script-shaped import exercises the absolute-import bootstrap without
    # invoking its __main__ guard, configuration reader, or task entry point.
    namespace = runpy.run_path(str(script), run_name="watchdog_import_probe")
    assert namespace["__package__"] == ""
else:
    raise AssertionError("Unexpected import branch")
assert Path(namespace["__file__"]).resolve(strict=True) == script
assert namespace["__name__"] != "__main__"
assert blocked == []
assert "cryptography" not in sys.modules
print(json.dumps({"branch": branch, "isolated": sys.flags.isolated,
                  "no_site": sys.flags.no_site, "imported": True}))
"""


@pytest.mark.parametrize("branch", ["package", "script"])
def test_watchdog_imports_without_third_party_dependencies(tmp_path: Path, branch: str) -> None:
    root = Path(__file__).resolve().parents[1]
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    completed = subprocess.run(
        [
            str(Path(sys.executable).absolute()),
            "-I",
            "-S",
            "-B",
            "-c",
            _IMPORT_PROBE,
            str(root),
            branch,
        ],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "branch": branch,
        "isolated": 1,
        "no_site": 1,
        "imported": True,
    }

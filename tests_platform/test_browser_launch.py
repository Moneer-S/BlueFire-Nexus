"""Desktop handoff contract with fake OS calls; no browser or process is started."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bluefire import browser_launch as launch

URL = "http://127.0.0.1:8765/#bluefire-session=" + "A" * 64


@pytest.mark.parametrize(
    "platform,executable", [("linux", "/usr/bin/xdg-open"), ("darwin", "/usr/bin/open")]
)
@pytest.mark.parametrize("outcome", [0, 1, "timeout", "missing"])
def test_fixed_desktop_handoff_is_quiet_scrubbed_and_never_retried(
    monkeypatch: pytest.MonkeyPatch, platform: str, executable: str, outcome: Any
) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(launch.sys, "platform", platform)
    monkeypatch.setenv("BROWSER", "arbitrary-browser-command")
    monkeypatch.setenv("OPENAI_API_KEY", "private-test-value")
    monkeypatch.setenv("PYTHONPATH", "private-module-path")
    monkeypatch.setenv("DISPLAY", ":8")
    monkeypatch.setenv("PATH", "arbitrary-program-path")

    class Process:
        def wait(self, *, timeout: int) -> int:
            assert timeout == 3
            if outcome == "timeout":
                raise launch.subprocess.TimeoutExpired([executable, URL], timeout)
            return outcome

    def popen(argv: Any, **kwargs: Any) -> Process:
        calls.append((argv, kwargs))
        if outcome == "missing":
            raise OSError("private diagnostic containing " + URL)
        return Process()

    monkeypatch.setattr(launch.subprocess, "Popen", popen)
    assert launch.open_console_url(URL) is (outcome in (0, "timeout"))
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == [executable, URL]
    assert kwargs == {
        "stdin": launch.subprocess.DEVNULL,
        "stdout": launch.subprocess.DEVNULL,
        "stderr": launch.subprocess.DEVNULL,
        "close_fds": True,
        "shell": False,
        "start_new_session": True,
        "env": kwargs["env"],
    }
    assert kwargs["env"]["DISPLAY"] == ":8"
    assert kwargs["env"]["PATH"] == launch.os.defpath
    assert not {"BROWSER", "OPENAI_API_KEY", "PYTHONPATH"}.intersection(kwargs["env"])


@pytest.mark.parametrize("fails", [False, True])
def test_windows_handoff_uses_registered_url_handler_only(
    monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(launch.sys, "platform", "win32")

    def startfile(url: str) -> None:
        calls.append(url)
        if fails:
            raise OSError("no associated browser: " + url)

    monkeypatch.setattr(launch.os, "startfile", startfile, raising=False)
    monkeypatch.setattr(
        launch.subprocess, "Popen", lambda *_a, **_k: pytest.fail("not a desktop command")
    )
    assert launch.open_console_url(URL) is not fails
    assert calls == [URL]


@pytest.mark.parametrize(
    "url",
    [
        URL.replace("127.0.0.1", "example.com"),
        URL.replace("http:", "file:"),
        URL.replace("8765", "0"),
        URL.replace("8765", "65536"),
        URL.replace("127.0.0.1", "user@127.0.0.1"),
        URL.replace("/#", "/other#"),
        URL.replace("/#", "/?q=private#"),
        URL + "x",
        URL + "\n",
        "--help",
    ],
)
def test_non_console_urls_never_reach_the_desktop(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(launch.sys, "platform", "win32")
    monkeypatch.setattr(
        launch.os, "startfile", lambda *_a: pytest.fail("invalid URL"), raising=False
    )
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *_a, **_k: pytest.fail("invalid URL"))
    assert launch.open_console_url(url) is False


@pytest.mark.parametrize("host", ["localhost", "[::1]", "127.0.0.2"])
def test_other_literal_loopback_bindings_are_supported(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.setattr(launch.sys, "platform", "win32")
    calls: list[str] = []
    monkeypatch.setattr(launch.os, "startfile", calls.append, raising=False)
    url = URL.replace("127.0.0.1", host)
    assert launch.open_console_url(url) is True
    assert calls == [url]


def test_browser_boundary_source_pin_refuses_changed_launch_flags() -> None:
    from tools.provider_boundary_inventory import (
        _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES,
        _reviewed_python_process_boundary_sources,
    )

    root = Path(__file__).resolve().parents[1]
    sources = {
        name: (root / name).read_text(encoding="utf-8")
        for name in _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    assert _reviewed_python_process_boundary_sources(sources)
    path = "bluefire/browser_launch.py"
    assert "shell=False" in sources[path]
    sources[path] = sources[path].replace("shell=False", "shell=True")
    assert not _reviewed_python_process_boundary_sources(sources)

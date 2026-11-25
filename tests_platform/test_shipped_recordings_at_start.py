from __future__ import annotations

import threading
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

from bluefire import api, recording_deltas, recordings
from bluefire.api import BROWSER_BOOTSTRAP_HEADER, generate_browser_bootstrap_capability
from bluefire.service import BlueFireService
from tests_platform.test_api import json_body, request

ROOT = Path(__file__).resolve().parents[1]


def shipped_files(*folders: str) -> int:
    folder = resources.files("bluefire.data").joinpath("recordings")
    for name in folders:
        folder = folder.joinpath(name)
    return sum(1 for item in folder.iterdir() if item.name.endswith(".json"))


def test_the_service_reads_the_shipped_recordings_once_as_it_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reading starts with the service, before any request; requests made while it
    is under way wait for it, and neither they nor later ones read the files again."""

    read_recordings: list[str] = []
    read_deltas: list[str] = []
    reading, go_on = threading.Event(), threading.Event()
    shipped, parse_delta = recordings._shipped, recording_deltas.parse_delta_bytes

    def slow_shipped(payload: bytes) -> Any:
        read_recordings.append(threading.current_thread().name)
        reading.set()
        go_on.wait(30)
        return shipped(payload)

    def counted_delta(payload: bytes) -> Any:
        read_deltas.append(threading.current_thread().name)
        return parse_delta(payload)

    monkeypatch.setattr(recordings, "_shipped", slow_shipped)
    monkeypatch.setattr(recording_deltas, "parse_delta_bytes", counted_delta)
    service = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    capability = generate_browser_bootstrap_capability()
    ready: list[api.BlueFireHTTPServer] = []
    announced = threading.Event()

    def on_ready(server: api.BlueFireHTTPServer) -> None:
        ready.append(server)
        announced.set()

    serving = threading.Thread(
        target=api.serve,
        args=(service,),
        kwargs={
            "browser_bootstrap_capability": capability,
            "host": "127.0.0.1",
            "port": 0,
            "on_ready": on_ready,
        },
        daemon=True,
    )
    serving.start()
    try:
        # The address is announced while the reading is held, and the reading has begun
        # with no request made.
        assert announced.wait(30)
        assert reading.wait(30)
        server = ready[0]
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/session",
            extra_headers={BROWSER_BOOTSTRAP_HEADER: capability},
            authenticated=False,
        )
        assert status == 200
        server._test_browser_session = json_body(payload)["session"]  # type: ignore[attr-defined]

        answers: dict[int, tuple[int, Any]] = {}

        def ask(number: int, path: str) -> None:
            status, _, body = request(server, "GET", path, timeout=60)
            answers[number] = (status, json_body(body))

        paths = ["/api/v1/recordings", "/api/v1/recordings/deltas"] * 4
        asking = [
            threading.Thread(target=ask, args=(number, path)) for number, path in enumerate(paths)
        ]
        for thread in asking:
            thread.start()
        for thread in asking:
            thread.join(0.2)
        go_on.set()
        for thread in asking:
            thread.join(60)
        later = request(server, "GET", "/api/v1/recordings", timeout=60)
    finally:
        go_on.set()
        if ready:
            ready[0].shutdown()
        serving.join(60)

    assert sorted(answers) == list(range(len(paths)))
    assert all(status == 200 for status, _ in answers.values())
    assert all(len(body["recordings"]) > 0 for _, body in answers.values() if "recordings" in body)
    assert all(len(body["deltas"]) > 0 for _, body in answers.values() if "deltas" in body)
    assert later[0] == 200
    # Each shipped file was read once: the recordings by the thread the service started,
    # and the comparisons by that thread or by the first request that came for them.
    assert len(read_recordings) == shipped_files()
    assert set(read_recordings) == {"bluefire-shipped-recordings"}
    assert len(read_deltas) == shipped_files("deltas")

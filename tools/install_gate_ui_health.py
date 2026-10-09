"""Secret-free HTTP health evidence for the installed Gate 01 UI."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Mapping, cast


class UIHealthError(RuntimeError):
    """A bounded health failure safe to return through the acceptance log."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise UIHealthError(code, message)


def probe_ui_health(
    port: int,
    capability: str,
    *,
    raw_request: Callable[..., tuple[int, Mapping[str, str], bytes]],
    json_request: Callable[..., Mapping[str, Any]],
    scenario_id: str,
    schema: str,
) -> tuple[str, Mapping[str, Any], Mapping[str, Any], dict[str, Any]]:
    status, index_headers, index = raw_request(port, "GET", "/")
    _require(
        status == 200
        and index_headers.get("content-type", "").startswith("text/html")
        and b'<div id="root"></div>' in index
        and b'<script type="module" crossorigin src="/ui/app.js"></script>' in index
        and b'<link rel="stylesheet" crossorigin href="/ui/styles.css">' in index,
        "ui_index_invalid",
        "packaged UI index did not load",
    )
    assets: dict[str, dict[str, Any]] = {}
    for path, marker, media_type in (
        ("/ui/app.js", b"BlueFire", ("text/javascript", "application/javascript")),
        ("/ui/styles.css", b"--", ("text/css",)),
    ):
        asset_status, asset_headers, payload = raw_request(port, "GET", path)
        _require(
            asset_status == 200
            and len(payload) >= 512
            and marker in payload
            and asset_headers.get("content-type", "").split(";", 1)[0] in media_type,
            "ui_asset_invalid",
            "a packaged production UI asset did not load",
        )
        assets[path] = {
            "size_bytes": len(payload),
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
    session_status, session_headers, session_payload = raw_request(
        port, "POST", "/api/v1/session", capability=capability
    )
    try:
        exchanged = json.loads(session_payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UIHealthError(
            "ui_session_invalid", "production UI session exchange was invalid"
        ) from exc
    session = exchanged.get("session") if isinstance(exchanged, dict) else None
    _require(
        session_status == 200
        and isinstance(session, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{64}", session) is not None
        and set(exchanged) == {"session"}
        and "set-cookie" not in session_headers
        and session_headers.get("cache-control") == "no-store",
        "ui_session_invalid",
        "production UI session exchange was invalid",
    )
    session = cast(str, session)
    replay_status, _replay_headers, _replay_payload = raw_request(
        port, "POST", "/api/v1/session", capability=capability
    )
    _require(
        replay_status == 401,
        "ui_capability_reusable",
        "production UI launch capability was reusable",
    )
    session_check, _check_headers, check_payload = raw_request(
        port, "GET", "/api/v1/session", session=session
    )
    _require(
        session_check == 204 and check_payload == b"",
        "ui_session_unhealthy",
        "production UI session health check failed",
    )
    cookie_status, _cookie_headers, _cookie_payload = raw_request(
        port, "GET", "/api/v1/session", legacy_cookie=session
    )
    _require(
        cookie_status == 401,
        "ui_ambient_authority_accepted",
        "production UI accepted ambient session authority",
    )
    catalog = json_request(port, "GET", "/api/v1/catalog", session=session)
    scenarios = json_request(port, "GET", "/api/v1/scenarios", session=session)
    scenario_rows = scenarios.get("scenarios")
    _require(
        isinstance(catalog.get("behaviors"), list)
        and isinstance(scenario_rows, list)
        and any(isinstance(row, Mapping) and row.get("id") == scenario_id for row in scenario_rows),
        "ui_catalog_unhealthy",
        "production UI catalog health check failed",
    )
    scenario_rows = cast(list[Any], scenario_rows)
    report = {
        "schema_version": schema,
        "verified": True,
        "launch": {
            "command": [
                "{python}",
                "-I",
                "-m",
                "bluefire.cli",
                "--runs-dir",
                "{runs-dir}",
                "ui",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ],
            "loopback_only": True,
            "ephemeral_port": True,
            "capability_not_in_http_target": True,
            "capability_single_use": True,
            "session_header_required": True,
        },
        "assets": assets,
        "api": {
            "session_healthy": True,
            "catalog_behavior_count": len(catalog["behaviors"]),
            "scenario_count": len(scenario_rows),
            "seeded_scenario_present": True,
        },
    }
    return session, catalog, scenarios, report

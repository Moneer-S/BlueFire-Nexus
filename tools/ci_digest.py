"""Summarize one CI run in a few lines for people and agents.

The last CI job runs this. It lists every job that did not pass, the step that
failed, and the lines from that job's log that say why: failing pytest, Vitest
and cargo tests, Rust panics, lint, format and type errors, and the stage
reported by the installed-product verifiers. Reading the tail of this one job's
log is enough to know what to fix; no 90 KB job listing or separate log
downloads.

Uses the Actions REST API with the workflow's token (``actions: read``). Always
exits 0: the failed jobs themselves are the red checks.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from typing import Any

DIGEST_JOB_NAME = "Result digest"
MAX_SIGNALS_PER_JOB = 12
MAX_LINE = 240
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")
_SIGNALS = (
    re.compile(r"^(FAILED|ERROR) \S"),  # pytest short summary
    re.compile(r"would reformat "),  # black
    re.compile(r": error: "),  # mypy
    re.compile(r"^\S+:\d+:\d+: [A-Z]+\d+ "),  # ruff
    re.compile(r"error TS\d+"),  # tsc
    re.compile(r"^\s*(FAIL|×) "),  # vitest
    re.compile(r"^\s*\d+\) \[chromium\] › "),  # playwright
    re.compile(r"^test \S+ \.\.\. FAILED$"),  # cargo test
    re.compile(r"^thread '[^']+' (?:\(\d+\) )?panicked at "),  # Rust panic location
    re.compile(
        r"^error(?:\[\w+\])?: (?!test failed|could not compile|aborting due)"
    ),  # rustc, clippy
    re.compile(r"^Diff in \S+"),  # cargo fmt --check
)
_VERIFIER_KEYS = (
    "status",
    "failure_stage",
    "browser_phase_status",
    "assistant_fixture_phase_status",
    "receiver_phase_status",
    "error_type",
)
_FAILED = {"failure", "timed_out", "cancelled", "startup_failure"}


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_LINE else text[: MAX_LINE - 1] + "…"


def _verifier_signal(line: str) -> str | None:
    """Compact the JSON result line an installed-product verifier prints."""

    if not line.startswith("{") or "failure_stage" not in line and "_phase_status" not in line:
        return None
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or value.get("status") == "passed":
        return None
    parts = [f"{key}={value[key]}" for key in _VERIFIER_KEYS if isinstance(value.get(key), str)]
    progress = value.get("browser_progress")
    if isinstance(progress, dict):
        parts += [
            f"{key}={progress[key]}"
            for key in ("browser_stage", "browser_error_type")
            if isinstance(progress.get(key), str)
        ]
    return "verifier: " + ", ".join(parts) if parts else None


def extract_signals(log: str) -> list[str]:
    """Return the lines of a job log that say why it failed, deduplicated."""

    found: list[str] = []
    fallback: list[str] = []
    for raw in log.splitlines():
        line = _TIMESTAMP.sub("", raw).rstrip()
        verifier = _verifier_signal(line.strip())
        if verifier:
            found.append(verifier)
        elif any(pattern.search(line) for pattern in _SIGNALS):
            found.append(line.strip())
        elif line.startswith("##[error]") and "Process completed with exit code" not in line:
            fallback.append(line.removeprefix("##[error]").strip())
    lines = found or fallback
    unique = list(dict.fromkeys(_clip(line) for line in lines if line))
    if len(unique) > MAX_SIGNALS_PER_JOB:
        hidden = len(unique) - MAX_SIGNALS_PER_JOB
        unique = unique[:MAX_SIGNALS_PER_JOB] + [f"… and {hidden} more"]
    return unique


def failed_steps(job: Mapping[str, Any]) -> list[str]:
    return [
        str(step.get("name"))
        for step in job.get("steps") or []
        if step.get("conclusion") in _FAILED
    ]


def render(jobs: Iterable[Mapping[str, Any]], signals: Mapping[int, list[str]]) -> list[str]:
    """Render the digest: failed jobs first, then a one-line tally."""

    lines: list[str] = []
    tally: dict[str, int] = {}
    for job in jobs:
        if job.get("name") == DIGEST_JOB_NAME:
            continue
        conclusion = str(job.get("conclusion") or job.get("status") or "unknown")
        tally[conclusion] = tally.get(conclusion, 0) + 1
        if conclusion not in _FAILED:
            continue
        steps = failed_steps(job)
        lines.append(
            f"{conclusion.upper()}  {job.get('name')}"
            + (f"  (step: {', '.join(steps)})" if steps else "")
        )
        lines += [f"    {line}" for line in signals.get(int(job.get("id", 0)), [])]
    summary = ", ".join(f"{count} {name}" for name, count in sorted(tally.items()))
    return (lines or ["All jobs passed."]) + [f"Jobs: {summary or 'none'}"]


def _request(url: str, token: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def _get_json(url: str, token: str) -> Any:
    with urllib.request.urlopen(_request(url, token), timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_log(url: str, token: str) -> str:
    # The logs endpoint redirects to signed storage; follow it without the token.
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(_request(url, token), timeout=30) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as redirect:
        location = redirect.headers.get("Location")
        if redirect.code not in (301, 302, 303, 307, 308) or not location:
            raise
    with urllib.request.urlopen(location, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def main(environ: Mapping[str, str] = os.environ) -> int:
    api = environ.get("GITHUB_API_URL", "https://api.github.com")
    repository = environ.get("GITHUB_REPOSITORY", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    token = environ.get("GITHUB_TOKEN", "")
    if not (repository and run_id and token):
        print("ci_digest: GITHUB_REPOSITORY, GITHUB_RUN_ID and GITHUB_TOKEN are required")
        return 0
    base = f"{api}/repos/{repository}/actions"
    jobs: list[Mapping[str, Any]] = []
    try:
        for page in range(1, 6):
            batch = _get_json(f"{base}/runs/{run_id}/jobs?per_page=100&page={page}", token)
            jobs += batch.get("jobs", [])
            if len(jobs) >= int(batch.get("total_count", 0)):
                break
    except (OSError, ValueError) as error:
        print(f"ci_digest: could not list jobs ({type(error).__name__})")
        return 0
    signals: dict[int, list[str]] = {}
    for job in jobs:
        if job.get("conclusion") in _FAILED - {"cancelled"} and job.get("name") != DIGEST_JOB_NAME:
            try:
                signals[int(job["id"])] = extract_signals(
                    _get_log(f"{base}/jobs/{job['id']}/logs", token)
                )
            except (OSError, ValueError) as error:
                signals[int(job["id"])] = [f"(log unavailable: {type(error).__name__})"]
    lines = render(jobs, signals)
    print("\n".join(lines))
    summary = environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("## Result digest\n\n```\n" + "\n".join(lines) + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

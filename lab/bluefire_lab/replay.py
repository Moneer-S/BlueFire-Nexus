"""Write replay.html: the app's single replay page with a recording the lab made put inside it.

The app fills the same template the same way (replay_page in bluefire/recordings.py). The lab is
a package of its own and does not import the app, so these few lines are written twice on purpose.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# The page's template holds the recording, and where it comes from, each in one element of its own.
ELEMENTS = ("bluefire-recording", "bluefire-origin")
MADE_HERE = (
    "Made by this repository's lab workflow in the CI run at {run_url}, from the recording that run made."
)
RECORDED = "Recorded by this repository's lab workflow in the CI run at {run_url}."


def origin(recording: dict, made_in: str | None = None) -> dict | None:
    """Where the recording comes from: the lab's CI run that recorded it. The page says that run
    made it too only when the run writing the page names itself (made_in) and is that same run. A
    recording that names no run gets no origin, and the page then says that it does not say where
    its recording comes from."""

    run_url = recording.get("source", {}).get("run_url")
    if not run_url:
        return None
    note = MADE_HERE if made_in == run_url else RECORDED
    return {"kind": "lab run", "run_url": run_url, "note": note.format(run_url=run_url)}


def fill(template: str, recording: dict, made_in: str | None = None) -> str:
    """The template with the recording's JSON in its one bluefire-recording element and the
    origin's in its one bluefire-origin element. Every "<" is written as its JSON escape, which
    reads back as the same character, so no text can end the element or start another."""

    page = template
    for name, value in zip(ELEMENTS, (recording, origin(recording, made_in)), strict=True):
        exact = re.compile(rf'(<script id="{name}" type="application/json">)(.*?)(</script>)', re.DOTALL)
        # Any script element that names the id, however its attributes are written.
        loose = re.compile(rf"<script\b[^>]*\bid\s*=\s*[\"']?{name}[\"'\s/>]", re.IGNORECASE)
        found = list(exact.finditer(page))
        if len(found) != 1 or len(loose.findall(page)) != 1:
            raise ValueError(
                f'the template must hold exactly one <script id="{name}" type="application/json"> element'
            )
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        data = data.replace("<", "\\u003c")
        page = page[: found[0].start(2)] + data + page[found[0].end(2) :]
    return page


def main(recording: Path, template: Path, out: Path, run_url: str | None = None) -> int:
    if out.exists():
        print(f"{out} exists: the page is written to a new file only", file=sys.stderr)
        return 2
    if not recording.is_file():
        print(f"{recording} does not exist: there is no recording to put in the page", file=sys.stderr)
        return 2
    try:
        made = json.loads(recording.read_text(encoding="utf-8"))
    except ValueError as problem:
        print(f"{recording} is not a JSON file: {problem}", file=sys.stderr)
        return 2
    if not isinstance(made, dict) or not isinstance(made.get("source", {}), dict):
        print(
            f"{recording} is not a recording: it must be an object, and so must its `source`", file=sys.stderr
        )
        return 2
    if not template.is_file():
        print(f"{template} does not exist: the page's template is bluefire/ui/replay.html", file=sys.stderr)
        return 2
    if not out.parent.is_dir():
        print(f"{out.parent} is not a folder: the page is written into a folder that exists", file=sys.stderr)
        return 2
    try:
        page = fill(template.read_text(encoding="utf-8"), made, run_url)
    except ValueError as problem:
        print(f"{template}: {problem}", file=sys.stderr)
        return 2
    with out.open("x", encoding="utf-8") as written:
        written.write(page)
    print(f"{out.name}: the replay page of {recording.name}")
    return 0

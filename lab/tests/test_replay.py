"""The replay page of a lab run: the app's page template with the recording put inside it."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bluefire_lab.__main__ import main

# The template the app builds and the lab workflow fills.
TEMPLATE = Path(__file__).resolve().parents[2] / "bluefire" / "ui" / "replay.html"
RUN_URL = "https://github.com/example/lab/actions/runs/123"
HOSTILE = "</script><script>alert(1)</script><!-- <img src=x onerror=alert(2)>"
SMALL = (
    "<!doctype html><html><body><main id=root></main>"
    '<script id="bluefire-recording" type="application/json">null</script>'
    '<script id="bluefire-origin" type="application/json">null</script>'
    "<script>/* the page's own script */</script></body></html>"
)


def a_recording(**source) -> dict:
    return {
        "schema": "bluefire.recording/1",
        "id": "run-1",
        "title": f"One published test {HOSTILE}",
        "source": {"engine": "bluefire-lab", "run_url": RUN_URL, **source},
        "steps": [{"id": "1", "title": "Clear Bash history (rm)", "plain": "Deletes <the> history & more."}],
    }


def write(folder: Path, recording: dict, template: str = SMALL) -> tuple[Path, Path, Path]:
    (folder / "recording.json").write_text(json.dumps(recording), encoding="utf-8")
    (folder / "replay-template.html").write_text(template, encoding="utf-8")
    return folder / "recording.json", folder / "replay-template.html", folder / "replay.html"


def element(page: str, name: str) -> str:
    found = re.findall(rf'<script id="{name}" type="application/json">(.*?)</script>', page, re.DOTALL)
    assert len(found) == 1
    return found[0]


def replay(recording: Path, template: Path, out: Path, *more: str) -> int:
    return main(["replay", str(recording), "--template", str(template), "--out", str(out), *more])


def in_run(monkeypatch: pytest.MonkeyPatch, run_id: str | None) -> None:
    """Run the command as GitHub Actions would in the run with this ID, or outside any run."""

    for name in ("GITHUB_ACTIONS", "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"):
        monkeypatch.delenv(name, raising=False)
    if run_id is not None:
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_REPOSITORY", "example/lab")
        monkeypatch.setenv("GITHUB_RUN_ID", run_id)


def test_the_page_holds_the_recording_and_the_lab_run_that_made_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recording, template, out = write(tmp_path, a_recording())
    in_run(monkeypatch, "123")

    assert replay(recording, template, out) == 0

    page = out.read_text(encoding="utf-8")
    assert json.loads(element(page, "bluefire-recording")) == a_recording()
    assert json.loads(element(page, "bluefire-origin")) == {
        "kind": "lab run",
        "run_url": RUN_URL,
        "note": f"Made by this repository's lab workflow in the CI run at {RUN_URL}, "
        "from the recording that run made.",
    }
    # No text of the recording can end its element, open a comment or start another element:
    # every "<" is its JSON escape, and the rest of the template is as it was.
    assert "<" not in element(page, "bluefire-recording")
    assert page.count("<script") == SMALL.count("<script")
    assert page.endswith("<script>/* the page's own script */</script></body></html>")


@pytest.mark.parametrize("run_id", [None, "456"], ids=["outside CI", "another run"])
def test_a_page_made_outside_the_run_the_file_names_says_that_run_was_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id: str | None
) -> None:
    recording, template, out = write(tmp_path, a_recording())
    in_run(monkeypatch, run_id)

    assert replay(recording, template, out) == 0

    # The page reads an imported origin as the app does: it does not link the run the file names.
    assert json.loads(element(out.read_text(encoding="utf-8"), "bluefire-origin")) == {
        "kind": "imported",
        "note": "Written by bluefire-lab replay from a file; the CI run it names was not checked.",
    }


def test_a_missing_recording_is_refused_in_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, template, out = write(tmp_path, a_recording())

    assert replay(tmp_path / "none.json", template, out) == 2

    assert not out.exists()
    assert "does not exist" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    ["{ not json", "[1, 2]", '{"source": "a run"}'],
    ids=["not JSON", "not an object", "a source that is not an object"],
)
def test_a_file_that_is_not_a_recording_is_refused_in_one_line(
    tmp_path: Path, text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    recording, template, out = write(tmp_path, a_recording())
    recording.write_text(text, encoding="utf-8")

    assert replay(recording, template, out) == 2

    assert not out.exists()
    assert "is not a" in capsys.readouterr().err


def test_a_missing_template_or_folder_is_refused_in_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recording, template, out = write(tmp_path, a_recording())

    assert replay(recording, tmp_path / "none.html", out) == 2
    assert "does not exist" in capsys.readouterr().err

    assert replay(recording, template, tmp_path / "no-folder" / "replay.html") == 2
    assert "is not a folder" in capsys.readouterr().err
    assert not (tmp_path / "no-folder").exists()


def test_a_recording_that_names_no_run_gets_no_origin(tmp_path: Path) -> None:
    made = a_recording()
    del made["source"]["run_url"]
    recording, template, out = write(tmp_path, made)

    assert replay(recording, template, out) == 0

    assert element(out.read_text(encoding="utf-8"), "bluefire-origin") == "null"


def test_the_apps_own_template_is_filled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recording, _, out = write(tmp_path, a_recording())
    in_run(monkeypatch, "123")

    assert replay(recording, TEMPLATE, out) == 0

    page = out.read_text(encoding="utf-8")
    held, said = element(page, "bluefire-recording"), element(page, "bluefire-origin")
    assert json.loads(held) == a_recording()
    assert json.loads(said)["kind"] == "lab run"
    # Apart from the two elements, the page is the template.
    assert page.replace(held, "null", 1).replace(said, "null", 1) == TEMPLATE.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "template",
    [
        SMALL.replace('<script id="bluefire-recording" type="application/json">null</script>', ""),
        SMALL.replace("</main>", '</main><script id="bluefire-recording" type="application/json">1</script>'),
        SMALL.replace("</main>", "</main><SCRIPT ID='bluefire-recording'>1</SCRIPT>"),
        SMALL.replace('<script id="bluefire-origin" type="application/json">null</script>', ""),
        SMALL.replace("</main>", "</main><script id=bluefire-origin>1</script>"),
    ],
    ids=["no recording element", "two", "a second written another way", "no origin element", "two origins"],
)
def test_a_template_without_exactly_one_of_each_element_is_refused(
    tmp_path: Path, template: str, capsys: pytest.CaptureFixture[str]
) -> None:
    recording, template_file, out = write(tmp_path, a_recording(), template)

    assert replay(recording, template_file, out) == 2

    assert not out.exists()
    assert "the template must hold exactly one" in capsys.readouterr().err


def test_an_existing_file_is_never_replaced(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    recording, template, out = write(tmp_path, a_recording())
    out.write_text("an earlier page", encoding="utf-8")

    assert replay(recording, template, out) == 2

    assert out.read_text(encoding="utf-8") == "an earlier page"
    assert "exists" in capsys.readouterr().err

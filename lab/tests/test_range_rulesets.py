"""The public rule sets of a range's defenses: locked file by file, fetched by the lock, and read back from a run.

The rule set here is made up for the tests (fixtures/range/rule-set): a few
rules of the lab's own writing and a stand-in licence, served to the lab from
that folder as GitHub would serve a repository at a commit (`served`, in
conftest.py). Nothing is fetched from a network.
"""

import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire_lab.range import rulesets
from bluefire_lab.range import spec as range_spec

SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
RULE_SET = Path(__file__).parent / "fixtures" / "range" / "rule-set"
SELECTION = Path(__file__).parent / "fixtures" / "range" / "rule-set-selection"
COMMIT = "b" * 40
MADE_UP = {
    "kind": "sigma",
    "repo": "example/rules",
    "commit": COMMIT,
    "folders": [
        "rules/linux/process_creation",
        "rules/linux/file_event",
        "rules/linux/builtin",
        "rules/web/webserver_generic",
    ],
    "licence": "LICENSE",
    "lock": "made-up.lock",
}
# The digest of the made-up set's rule files, as `sha256sum` gives it: what
# `cd fixtures/range/rule-set && find rules -type f | LC_ALL=C sort | xargs -d '\n' sha256sum | sha256sum`
# prints. The licence file is not among them.
DIGEST = "ee5857b859624cb58d824c22da5196c3404f047d043343da32a10b26f89ccaef"  # pragma: allowlist secret


def defended(folder: Path = RULE_SET) -> range_spec.Spec:
    """The small spec of the tests with the made-up rule set and a defense that runs it, its lock in `folder`."""

    document = range_spec.read(SMALL.read_text())
    document["rule_sets"] = {"made-up": MADE_UP}
    document["defenses"] = [
        {
            "id": "made-up-rules",
            "name": "Rules made up for the tests",
            "sensors": ["wazuh-agent"],
            "rules": ["made-up"],
        }
    ]
    return range_spec.parse(document, folder=folder)


def test_the_lock_command_lists_each_folder_and_writes_every_hash_under_the_sets_name(
    tmp_path: Path, served
) -> None:
    asked: list[str] = []

    written = rulesets.lock(defended(tmp_path), served(asked=asked))

    assert [path.name for path in written] == ["made-up.lock"]
    assert written[0].read_text() == (RULE_SET / "made-up.lock").read_text()
    lines = written[0].read_text().splitlines()
    assert lines[0] == f"# made-up: example/rules {COMMIT}"
    assert [line.split("  ")[1] for line in lines[1:]] == sorted(
        path.relative_to(RULE_SET).as_posix()
        for path in RULE_SET.rglob("*")
        if path.is_file() and path.name != "made-up.lock"
    )
    # Folders are listed through the API, the folders inside them too; every file comes from the raw address.
    assert (
        f"https://api.github.com/repos/example/rules/contents/rules/linux/builtin/sshd?ref={COMMIT}" in asked
    )
    assert f"https://raw.githubusercontent.com/example/rules/{COMMIT}/LICENSE" in asked


def test_a_run_fetches_the_rules_by_the_lock_with_the_licence_and_a_line_that_says_the_source(
    tmp_path: Path, served
) -> None:
    spec = defended()
    asked: list[str] = []

    made = rulesets.fetch(spec, spec.rule_sets[0], tmp_path, served(asked=asked))

    folder = tmp_path / "rules" / "made-up"
    assert (folder / "SOURCE").read_text() == f"example/rules@{COMMIT}\n"
    assert (folder / "LICENSE").read_bytes() == (RULE_SET / "LICENSE").read_bytes()
    rule = "rules/linux/builtin/sshd/lnx_made_up_sshd.yml"
    assert (folder / rule).read_bytes() == (RULE_SET / rule).read_bytes()
    # Nothing is listed or cloned: each file of the lock is asked for by its own address.
    assert all(url.startswith(f"https://raw.githubusercontent.com/example/rules/{COMMIT}/") for url in asked)
    assert len(asked) == len(made["lock"]) == made["files"] + 1
    assert made["folder"] == "rules/made-up" and made["digest"] == DIGEST
    assert rulesets.held(tmp_path, "made-up", made["lock"]) == folder


def selection_spec(
    tmp_path: Path,
    kind: str,
    folder: str,
    *,
    rule_paths: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    pipelines: tuple[str, ...] = (),
) -> range_spec.Spec:
    """A parsed spec changed only to exercise made-up format-aware discovery."""

    spec = defended(tmp_path)
    rule_set = replace(
        spec.rule_sets[0],
        kind=kind,
        folders=(folder,),
        rule_paths=rule_paths,
        include="rules",
        exclude=exclude,
        pipelines=pipelines,
    )
    return replace(spec, rule_sets=(rule_set,))


def test_a_sigma_set_locks_only_rules_in_selected_source_paths_and_records_what_was_left_out(
    tmp_path: Path, served
) -> None:
    spec = selection_spec(tmp_path, "sigma", "sigma", rule_paths=("sigma/source",))
    asked: list[str] = []
    upstream = served(SELECTION, asked=asked)

    def fetched(url: str) -> bytes:
        assert "sigma/tests/valid-looking.yml" not in url
        return upstream(url)

    rulesets.lock(spec, fetched)
    locked = rulesets.locked(spec, spec.rule_sets[0])
    made = rulesets.record(spec.rule_sets[0], locked)

    assert set(locked) == {"LICENSE", "sigma/source/atomic.yml", "sigma/source/correlation.yml"}
    assert made["selection"] == {
        "include": "rules",
        "rule paths": ["sigma/source"],
        "exclude": [],
        "pipelines": [],
        "selected files": 2,
        "left out files": 4,
        "left out by reason": {
            "Sigma pipeline": 1,
            "not a Sigma rule or correlation": 1,
            "not YAML": 1,
            "outside selected source paths": 1,
        },
    }
    assert len([url for url in asked if "raw.githubusercontent.com" in url]) == 6


def test_a_sigma_value_placeholder_pipeline_is_explicitly_locked_beside_the_rules(
    tmp_path: Path, served
) -> None:
    pipeline = "sigma/source/pipeline.yml"
    spec = selection_spec(
        tmp_path,
        "sigma",
        "sigma",
        rule_paths=("sigma/source",),
        pipelines=(pipeline,),
    )

    rulesets.lock(spec, served(SELECTION))
    locked = rulesets.locked(spec, spec.rule_sets[0])
    made = rulesets.record(spec.rule_sets[0], locked)

    assert set(locked) == {
        "LICENSE",
        pipeline,
        "sigma/source/atomic.yml",
        "sigma/source/correlation.yml",
    }
    assert made["selection"] == {
        "include": "rules",
        "rule paths": ["sigma/source"],
        "exclude": [],
        "pipelines": [pipeline],
        "selected files": 3,
        "left out files": 3,
        "left out by reason": {
            "not a Sigma rule or correlation": 1,
            "not YAML": 1,
            "outside selected source paths": 1,
        },
    }
    assert f"{rulesets.PIPELINE}{pipeline}" in (tmp_path / "made-up.lock").read_text().splitlines()


@pytest.mark.parametrize(
    "text",
    [
        "vars: {}\ntransformations:\n  - type: value_placeholders\n",
        "vars:\n  bad-name:\n    - value\ntransformations:\n  - type: value_placeholders\n",
        "vars:\n  source: value\ntransformations:\n  - type: value_placeholders\n",
        "vars:\n  source:\n    - ''\ntransformations:\n  - type: value_placeholders\n",
        "vars:\n  source:\n    - value\n    - value\ntransformations:\n  - type: value_placeholders\n",
        "vars:\n  source:\n    - value\ntransformations:\n  - type: field_name_mapping\n",
    ],
)
def test_a_declared_sigma_pipeline_must_have_exact_value_placeholder_shapes(text: str) -> None:
    assert (
        rulesets.sigma_pipeline_reason("sigma/pipelines/values.yml", text.encode())
        == "not a Sigma value-placeholder pipeline"
    )


def test_a_suricata_set_locks_only_active_rule_files_and_keeps_an_exact_exclusion_distinct(
    tmp_path: Path, served
) -> None:
    omitted = ("suricata/retired.rules",)
    spec = selection_spec(tmp_path, "suricata", "suricata", exclude=omitted)
    asked: list[str] = []

    rulesets.lock(spec, served(SELECTION, asked=asked))
    locked = rulesets.locked(spec, spec.rule_sets[0])
    made = rulesets.record(spec.rule_sets[0], locked)

    assert set(locked) == {"LICENSE", "suricata/active.rules"}
    assert made["selection"] == {
        "include": "rules",
        "rule paths": [],
        "exclude": list(omitted),
        "pipelines": [],
        "selected files": 1,
        "left out files": 3,
        "left out by reason": {
            "excluded by the spec": 1,
            "no active Suricata rule": 1,
            "not a Suricata .rules file": 1,
        },
    }
    assert not any(url.endswith("/suricata/retired.rules") for url in asked)


def test_locking_refuses_a_filter_that_does_not_describe_the_pinned_folders(tmp_path: Path, served) -> None:
    missing = selection_spec(tmp_path, "suricata", "suricata", exclude=("suricata/missing.rules",))
    unmatched = selection_spec(tmp_path, "suricata", "suricata", rule_paths=("suricata/missing",))

    with pytest.raises(
        range_spec.SpecError, match="exclude names suricata/missing.rules, which the configured"
    ):
        rulesets.lock(missing, served(SELECTION))
    with pytest.raises(range_spec.SpecError, match="rule_paths names suricata/missing, which match no file"):
        rulesets.lock(unmatched, served(SELECTION))


@pytest.mark.parametrize("existing", ["rules-link", "set-link", "set-folder"])
def test_a_run_fetch_refuses_an_existing_or_linked_rule_tree(tmp_path: Path, served, existing: str) -> None:
    run = tmp_path / "run"
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep.txt"
    marker.write_text("leave this outside the run\n")
    if existing == "rules-link":
        run.mkdir()
        (run / "rules").symlink_to(outside, target_is_directory=True)
        message = "rules is not a folder in the run's folder"
    else:
        target = run / "rules" / "made-up"
        target.parent.mkdir(parents=True)
        if existing == "set-link":
            target.symlink_to(outside, target_is_directory=True)
        else:
            target.mkdir()
            (target / "left-over.yml").write_text("title: left over\n")
        message = "rules/made-up exists already in the run's folder"

    with pytest.raises(range_spec.SpecError, match=message):
        rulesets.fetch(defended(), defended().rule_sets[0], run, served())

    assert marker.read_text() == "leave this outside the run\n"


def test_a_fetched_file_that_is_not_the_locks_stops_the_run_by_its_name(tmp_path: Path, served) -> None:
    changed = tmp_path / "repository"
    shutil.copytree(RULE_SET, changed)
    rule = "rules/linux/file_event/file_event_lnx_made_up_tmp.yml"
    (changed / rule).write_text((changed / rule).read_text().replace("level: medium", "level: critical"))
    spec = defended()

    with pytest.raises(range_spec.SpecError) as refused:
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run", served(changed))

    assert str(refused.value).startswith(f"{rule} of made-up at {COMMIT} has SHA-256 ")
    assert "made-up.lock says " in str(refused.value) and "the run stops" in str(refused.value)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda text: text.replace(COMMIT, "c" * 40),
            "has no section for the rule set made-up of example/rules",
        ),
        (
            lambda text: (
                "\n".join(line for line in text.splitlines() if not line.endswith("  LICENSE")) + "\n"
            ),
            "made-up.lock does not list LICENSE, the licence of made-up",
        ),
        (
            lambda text: (
                "\n".join(line for line in text.splitlines() if "/webserver_generic/" not in line) + "\n"
            ),
            "made-up.lock lists no file of rules/web/webserver_generic for made-up",
        ),
        (lambda text: text + "0" * 64 + "  rules/windows/other.yml\n", "outside the folders the spec names"),
        (lambda text: text + "0" * 64 + "  ../outside.yml\n", "is not '<sha256>  <path>' of a new file"),
    ],
)
def test_a_lock_that_is_not_of_the_specs_rule_set_is_refused(
    tmp_path: Path, served, change, message: str
) -> None:
    (tmp_path / "made-up.lock").write_text(change((RULE_SET / "made-up.lock").read_text()))
    spec = defended(tmp_path)

    with pytest.raises(range_spec.SpecError) as refused:
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run", served())

    assert message in str(refused.value)


def test_a_spec_without_its_lock_file_says_how_to_write_it(tmp_path: Path, served) -> None:
    spec = defended(tmp_path)

    with pytest.raises(
        range_spec.SpecError, match="no lock file made-up.lock beside the spec: write it with"
    ):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run", served())


def test_a_run_folders_rules_are_refused_when_a_file_is_missing_differs_or_was_added(
    tmp_path: Path, served
) -> None:
    spec = defended()
    lock = rulesets.fetch(spec, spec.rule_sets[0], tmp_path, served())["lock"]
    folder = tmp_path / "rules" / "made-up"
    rule = "rules/linux/builtin/lnx_made_up_word.yml"

    (folder / "rules" / "linux" / "added.yml").write_text("title: added after the run\n")
    with pytest.raises(
        range_spec.SpecError, match="rules/made-up holds rules/linux/added.yml, which the lock"
    ):
        rulesets.held(tmp_path, "made-up", lock)
    (folder / "rules" / "linux" / "added.yml").unlink()

    (folder / rule).write_text((folder / rule).read_text() + "# changed\n")
    with pytest.raises(range_spec.SpecError, match=f"rules/made-up/{rule} has SHA-256 "):
        rulesets.held(tmp_path, "made-up", lock)

    (folder / rule).unlink()
    with pytest.raises(range_spec.SpecError, match=f"rules/made-up/{rule} is not in the run's folder"):
        rulesets.held(tmp_path, "made-up", lock)


def test_a_run_folders_rules_are_refused_when_an_expected_parent_is_a_link(tmp_path: Path, served) -> None:
    spec = defended()
    lock = rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run", served())["lock"]
    parent = tmp_path / "run" / "rules" / "made-up" / "rules" / "linux" / "process_creation"
    outside = tmp_path / "outside"
    shutil.copytree(parent, outside)
    shutil.rmtree(parent)
    parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(range_spec.SpecError, match="is not in the run's folder"):
        rulesets.held(tmp_path / "run", "made-up", lock)


def test_range_ones_rule_set_and_defenses_are_those_its_spec_and_lock_give() -> None:
    spec = range_spec.load(Path(__file__).parents[1] / "range" / "range-one.yaml")

    (sigma,) = spec.rule_sets
    locked = rulesets.locked(spec, sigma)

    assert (sigma.repo, sigma.licence, sigma.lock) == ("SigmaHQ/sigma", "LICENSE", "range-one.rules.lock")
    assert rulesets.wanted(sigma, locked) == sorted(locked)
    assert {path.split("/")[1] for path in locked if path != "LICENSE"} == {"linux", "web"}
    assert [(defense.id, defense.sensors, defense.rules) for defense in spec.defenses] == [
        ("wazuh-stock", ("wazuh-agent",), ("wazuh",)),
        ("sigma-public", ("wazuh-agent",), ("sigma",)),
    ]

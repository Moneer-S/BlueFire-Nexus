"""The public rule sets of a range's defenses: locked file by file, fetched by the lock, and read back from a run.

The rule set here is made up for the tests (fixtures/range/rule-set): a few
rules of the lab's own writing and a stand-in licence, served to the lab from
that folder as GitHub would serve a repository at a commit (`served`, in
conftest.py). Nothing is fetched from a network.
"""

import hashlib
import shutil
from pathlib import Path

import pytest

from bluefire_lab.range import rulesets
from bluefire_lab.range import spec as range_spec

SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
RULE_SET = Path(__file__).parent / "fixtures" / "range" / "rule-set"
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


def test_a_repository_archive_is_copied_byte_for_byte_after_its_hash_is_checked(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").write_text("gitdir: elsewhere\n")
    source = repository / "lab" / "rules" / "published.tar.gz"
    source.parent.mkdir(parents=True)
    data = b"a made-up archive for this unit test"
    source.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    document = range_spec.read(SMALL.read_text())
    document["rule_sets"] = {
        "published": {
            "kind": "suricata",
            "source": "lab/rules/published.tar.gz",
            "sha256": digest,
            "version": "7",
        }
    }
    document["defenses"] = [{
        "id": "packets",
        "name": "Packets with published rules",
        "sensors": ["packet-capture"],
        "rules": ["published"],
    }]
    document["hosts"]["web"]["packages"].append("tcpdump")
    document["hosts"]["web"]["capture"] = "packets"
    spec = range_spec.parse(document, folder=repository / "lab" / "range")

    made = rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")

    copied = tmp_path / "run" / "rules" / "published" / "published.tar.gz"
    assert copied.read_bytes() == data
    assert made["version"] == "7" and made["digest"] == digest
    assert rulesets.held(tmp_path / "run", "published", made["lock"]) == copied.parent

    source.write_bytes(data + b"changed")
    with pytest.raises(range_spec.SpecError, match="has SHA-256 .* and the spec says"):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "other")


def test_range_ones_rule_set_and_defenses_are_those_its_spec_and_lock_give() -> None:
    spec = range_spec.load(Path(__file__).parents[1] / "range" / "range-one.yaml")

    sigma, et_open = spec.rule_sets
    locked = rulesets.locked(spec, sigma)

    assert (sigma.repo, sigma.licence, sigma.lock) == ("SigmaHQ/sigma", "LICENSE", "range-one.rules.lock")
    assert rulesets.wanted(sigma, locked) == sorted(locked)
    assert {path.split("/")[1] for path in locked if path != "LICENSE"} == {"linux", "web"}
    assert (et_open.kind, et_open.source_file, et_open.version) == (
        "suricata", "lab/rules/et-open/emerging.rules.tar.gz", "11342"
    )
    assert rulesets.locked(spec, et_open) == {"emerging.rules.tar.gz": et_open.sha256}
    assert [(defense.id, defense.sensors, defense.rules) for defense in spec.defenses] == [
        ("wazuh-stock", ("wazuh-agent",), ("wazuh",)),
        ("sigma-public", ("wazuh-agent",), ("sigma",)),
        ("packets-et-open", ("packet-capture",), ("et-open",)),
    ]

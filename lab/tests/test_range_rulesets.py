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


TRACKED_FILES = {
    "rules/LICENSE": b"made-up licence\r\n",
    "rules/classification.config": b"config kept byte for byte\n",
    "rules/alpha.rules": b'alert tcp any any -> any any (msg:"alpha"; sid:1;)\r\n\xff',
    "rules/nested/beta.rules": b'alert icmp any any -> any any (msg:"beta"; sid:2;)\n',
}


def tracked(
    repository: Path,
    *,
    manifest_data: bytes | None = None,
    files: dict[str, bytes] | None = None,
) -> tuple[range_spec.Spec, bytes, dict[str, str]]:
    """A spec whose Suricata rules are tracked behind a manifest in a stand-in worktree."""

    repository.mkdir()
    (repository / ".git").write_text("gitdir: elsewhere\n")
    source = repository / "lab" / "rules" / "published" / "SHA256SUMS"
    source.parent.mkdir(parents=True)
    payloads = TRACKED_FILES if files is None else files
    hashes = {path: hashlib.sha256(data).hexdigest() for path, data in payloads.items()}
    for relative, data in payloads.items():
        path = source.parent.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if manifest_data is None:
        manifest_data = "".join(f"{hashes[path]}  {path}\n" for path in hashes).encode("ascii")
    source.write_bytes(manifest_data)
    document = range_spec.read(SMALL.read_text())
    document["rule_sets"] = {
        "published": {
            "kind": "suricata",
            "source": "lab/rules/published/SHA256SUMS",
            "sha256": hashlib.sha256(manifest_data).hexdigest(),
            "version": "7",
        }
    }
    document["defenses"] = [
        {
            "id": "packets",
            "name": "Packets with published rules",
            "sensors": ["packet-capture"],
            "rules": ["published"],
        }
    ]
    document["hosts"]["web"]["packages"].append("tcpdump")
    document["hosts"]["web"]["capture"] = "packets"
    return range_spec.parse(document, folder=repository / "lab" / "range"), manifest_data, hashes


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


def test_a_tracked_manifest_and_every_listed_file_are_copied_byte_for_byte(tmp_path: Path) -> None:
    spec, manifest_data, hashes = tracked(tmp_path / "repository")
    source = tmp_path / "repository" / "lab" / "rules" / "published"
    (source / "not-listed.rules").write_bytes(b"must not be copied\n")

    made = rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")

    copied = tmp_path / "run" / "rules" / "published"
    expected_lock = {"SHA256SUMS": hashlib.sha256(manifest_data).hexdigest(), **hashes}
    assert (copied / "SHA256SUMS").read_bytes() == manifest_data
    assert {path: copied.joinpath(*path.split("/")).read_bytes() for path in TRACKED_FILES} == TRACKED_FILES
    assert not (copied / "not-listed.rules").exists()
    assert (copied / "SOURCE").read_text() == "lab/rules/published/SHA256SUMS@7\n"
    assert made["source"] == "lab/rules/published/SHA256SUMS"
    assert made["sha256"] == hashlib.sha256(manifest_data).hexdigest()
    assert made["version"] == "7" and made["files"] == 2
    assert made["lock"] == dict(sorted(expected_lock.items()))
    rule_listing = "".join(f"{hashes[path]}  {path}\n" for path in sorted(hashes) if path.endswith(".rules"))
    assert made["digest"] == hashlib.sha256(rule_listing.encode()).hexdigest()
    without_rule_changes = {
        **expected_lock,
        "rules/LICENSE": "0" * 64,
        "rules/classification.config": "1" * 64,
    }
    assert rulesets.digest(spec.rule_sets[0], without_rule_changes) == made["digest"]
    assert rulesets.held(tmp_path / "run", "published", made["lock"]) == copied


def test_a_changed_tracked_manifest_is_refused_before_a_run_folder_is_written(tmp_path: Path) -> None:
    spec, manifest_data, _ = tracked(tmp_path / "repository")
    source = tmp_path / "repository" / "lab" / "rules" / "published" / "SHA256SUMS"
    source.write_bytes(manifest_data + b"changed\n")

    with pytest.raises(range_spec.SpecError, match="manifest .* has SHA-256 .* and the spec says"):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")

    assert not (tmp_path / "run" / "rules").exists()


@pytest.mark.parametrize(
    "bad_line",
    [
        "A" * 64 + "  rules/alpha.rules",
        "0" * 64 + " rules/alpha.rules",
        "0" * 64 + "   rules/alpha.rules",
        "0" * 64 + "  rules/alpha.rules ",
        "0" * 64 + "  ../alpha.rules",
        "0" * 64 + "  /alpha.rules",
        "0" * 64 + r"  rules\alpha.rules",
        "0" * 64 + "  SOURCE/alpha.rules",
        "0" * 64 + "  SHA256SUMS/alpha.rules",
        "0" * 64 + "  rules/alpha.rules\n" + "0" * 64 + "  rules/alpha.rules",
    ],
)
def test_a_tracked_manifest_refuses_malformed_or_unsafe_entries(tmp_path: Path, bad_line: str) -> None:
    spec, _, _ = tracked(tmp_path / "repository", manifest_data=(bad_line + "\n").encode("ascii"))

    with pytest.raises(range_spec.SpecError, match="is not '<64 lower-case hex>  <relative path>'"):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")

    assert not (tmp_path / "run" / "rules").exists()


@pytest.mark.parametrize("problem", ["missing", "different", "file-link", "parent-link"])
def test_a_tracked_manifest_refuses_missing_changed_or_linked_files(tmp_path: Path, problem: str) -> None:
    spec, _, _ = tracked(tmp_path / "repository")
    source = tmp_path / "repository" / "lab" / "rules" / "published"
    alpha = source / "rules" / "alpha.rules"
    beta_parent = source / "rules" / "nested"
    if problem == "missing":
        alpha.unlink()
    elif problem == "different":
        alpha.write_bytes(b"different\n")
    elif problem == "file-link":
        outside = tmp_path / "outside.rules"
        outside.write_bytes(TRACKED_FILES["rules/alpha.rules"])
        alpha.unlink()
        alpha.symlink_to(outside)
    else:
        outside = tmp_path / "outside"
        shutil.copytree(beta_parent, outside)
        shutil.rmtree(beta_parent)
        beta_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(range_spec.SpecError):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")

    assert not (tmp_path / "run" / "rules").exists()


@pytest.mark.parametrize("problem", ["manifest-link", "no-repository"])
def test_a_tracked_manifest_needs_a_real_manifest_inside_a_repository(tmp_path: Path, problem: str) -> None:
    spec, manifest_data, _ = tracked(tmp_path / "repository")
    repository = tmp_path / "repository"
    if problem == "manifest-link":
        source = repository / "lab" / "rules" / "published" / "SHA256SUMS"
        outside = tmp_path / "outside-SHA256SUMS"
        outside.write_bytes(manifest_data)
        source.unlink()
        source.symlink_to(outside)
    else:
        (repository / ".git").unlink()

    with pytest.raises(range_spec.SpecError):
        rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")


def test_held_rechecks_the_tracked_manifest_and_the_exact_run_closure(tmp_path: Path) -> None:
    spec, manifest_data, _ = tracked(tmp_path / "repository")
    made = rulesets.fetch(spec, spec.rule_sets[0], tmp_path / "run")
    folder = tmp_path / "run" / "rules" / "published"

    (folder / "SHA256SUMS").write_bytes(manifest_data + b"changed\n")
    with pytest.raises(range_spec.SpecError, match="rules/published/SHA256SUMS has SHA-256"):
        rulesets.held(tmp_path / "run", "published", made["lock"])
    (folder / "SHA256SUMS").write_bytes(manifest_data)

    listed = folder / "rules" / "alpha.rules"
    listed.unlink()
    with pytest.raises(range_spec.SpecError, match="rules/published/rules/alpha.rules is not"):
        rulesets.held(tmp_path / "run", "published", made["lock"])
    listed.write_bytes(TRACKED_FILES["rules/alpha.rules"])

    outside = tmp_path / "outside"
    outside.write_text("outside\n")
    (folder / "extra.rules").symlink_to(outside)
    with pytest.raises(range_spec.SpecError, match="holds extra.rules, which the lock does not list"):
        rulesets.held(tmp_path / "run", "published", made["lock"])


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
    manifest_digest = "".join(
        ("a7b140e3", "95557d19", "a234b0fa", "465f4471", "39ba5071", "7ee6efcb", "0e23df6b", "7c6f30dc")
    )
    rule_digest = "".join(
        ("64294a19", "ec3946f5", "4c5e4cb3", "39a13766", "cd41aa69", "c2021d9f", "dbf7cbe4", "1efcc508")
    )

    sigma, et_open = spec.rule_sets
    locked = rulesets.locked(spec, sigma)

    assert (sigma.repo, sigma.licence, sigma.lock) == ("SigmaHQ/sigma", "LICENSE", "range-one.rules.lock")
    assert rulesets.wanted(sigma, locked) == sorted(locked)
    assert {path.split("/")[1] for path in locked if path != "LICENSE"} == {"linux", "web"}
    assert (et_open.kind, et_open.source_file, et_open.sha256, et_open.version) == (
        "suricata",
        "lab/rules/et-open/SHA256SUMS",
        manifest_digest,
        "11342",
    )
    et_lock = rulesets.locked(spec, et_open)
    assert len(et_lock) == 13 and et_lock["SHA256SUMS"] == et_open.sha256
    assert sum(path.endswith(".rules") for path in et_lock) == 8
    assert rulesets.record(et_open, et_lock)["files"] == 8
    assert rulesets.digest(et_open, et_lock) == rule_digest
    assert [(defense.id, defense.sensors, defense.rules) for defense in spec.defenses] == [
        ("wazuh-stock", ("wazuh-agent",), ("wazuh",)),
        ("sigma-public", ("wazuh-agent",), ("sigma",)),
        ("packets-et-open", ("packet-capture",), ("et-open",)),
    ]

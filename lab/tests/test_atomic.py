import json
import textwrap
from pathlib import Path

import pytest

from bluefire_lab import atomic
from bluefire_lab.__main__ import main

GUID = "11111111-2222-3333-4444-555555555555"


def technique_yaml(test: str) -> str:
    """A technique YAML with one test, given as the lines under its name."""

    return (
        "attack_technique: T1000\n"
        "display_name: Example\n"
        "atomic_tests:\n"
        "- name: Example test\n"
        f"  auto_generated_guid: {GUID}\n"
        "  description: An example.\n"
        "  supported_platforms: [linux]\n" + textwrap.indent(textwrap.dedent(test), "  ")
    )


def a_test(tmp_path: Path, test: str) -> dict:
    path = tmp_path / "T1000.yaml"
    path.write_text(technique_yaml(test), encoding="utf-8")
    return atomic.find_test(atomic.load_technique(path), GUID)


def attack(tmp_path: Path, test: str, args: dict | None = None) -> list[str]:
    return atomic.argvs(a_test(tmp_path, test), args or {})["attack"]


def test_the_lines_of_a_command_are_joined_with_a_semicolon(tmp_path: Path) -> None:
    test = """\
        executor:
          name: sh
          command: |
            echo one
            echo two
        """

    assert attack(tmp_path, test) == ["sh", "-c", "echo one; echo two"]


def test_a_line_that_ends_in_a_semicolon_keeps_its_newline(tmp_path: Path) -> None:
    test = """\
        executor:
          name: bash
          command: |
            cd /tmp;
            ls
            echo done
        """

    assert attack(tmp_path, test) == ["bash", "-c", "cd /tmp;\nls; echo done"]


def test_backslashes_are_doubled_except_before_a_quote_a_semicolon_or_the_end(tmp_path: Path) -> None:
    test = r"""
        executor:
          name: sh
          command: |
            echo "a\nb" \"q\" c\
        """

    assert attack(tmp_path, test) == ["sh", "-c", 'echo "a\\\\nb" \\"q\\" c\\']


def test_the_atomics_folder_replaces_both_spellings_in_any_case(tmp_path: Path) -> None:
    test = """\
        executor:
          name: sh
          command: cat "$PathToAtomicsFolder/T1000/src/a" pathtoatomicsfolder/T1000/src/b
        """

    assert attack(tmp_path, test) == ["sh", "-c", 'cat "/opt/atomics/T1000/src/a" /opt/atomics/T1000/src/b']


def test_an_argument_written_out_at_its_default_reaches_the_command_as_published(tmp_path: Path) -> None:
    test = r"""
        input_arguments:
          flags:
            description: flags for find
            type: string
            default: '-exec sh -c ''cat "$1"'' _ {} \;'
        executor:
          name: sh
          command: |
            find /tmp #{flags} 2>/dev/null
            exit 0
        """
    default = a_test(tmp_path, test)["input_arguments"]["flags"]["default"]

    assert attack(tmp_path, test, {"flags": default}) == [
        "sh",
        "-c",
        r"""find /tmp -exec sh -c 'cat "$1"' _ {} \; 2>/dev/null; exit 0""",
    ]


def test_an_argument_the_test_does_not_declare_is_refused(tmp_path: Path) -> None:
    test = """\
        input_arguments:
          host: {description: target, type: string, default: 192.168.1.1}
        executor: {name: bash, command: "ping -c 1 #{host}"}
        """

    with pytest.raises(ValueError, match="declares no input argument port"):
        attack(tmp_path, test, {"host": "web", "port": "22"})


def test_a_declared_argument_left_out_is_refused_and_its_default_named(tmp_path: Path) -> None:
    test = """\
        input_arguments:
          host: {description: target, type: string, default: 192.168.1.1}
        executor: {name: bash, command: "ping -c 1 #{host}"}
        """

    with pytest.raises(ValueError, match="host: '192.168.1.1'"):
        attack(tmp_path, test)


def test_values_whose_order_would_change_the_command_are_refused(tmp_path: Path) -> None:
    test = """\
        input_arguments:
          first: {description: one, type: string, default: x}
          second: {description: two, type: string, default: y}
        executor: {name: sh, command: "echo #{first}"}
        """

    with pytest.raises(ValueError, match="different order"):
        attack(tmp_path, test, {"first": "#{second}", "second": "z"})


def test_prereq_lines_are_joined_with_and_and_run_by_the_dependency_executor(tmp_path: Path) -> None:
    test = """\
        dependency_executor_name: bash
        dependencies:
        - description: a tool
          prereq_command: |
            command -v tool
            test -d /tmp
          get_prereq_command: null
        executor: {name: sh, command: tool}
        """

    assert atomic.argvs(a_test(tmp_path, test), {})["prereqs"] == [
        ["bash", "-c", "command -v tool && test -d /tmp"]
    ]


def test_a_test_without_a_published_cleanup_has_an_empty_cleanup_command(tmp_path: Path) -> None:
    vectors = atomic.argvs(a_test(tmp_path, "executor: {name: sh, command: 'true'}\n"), {})

    assert (vectors["cleanup"], vectors["cleanup_published"]) == (["sh", "-c", ""], False)


def a_spec(**step) -> dict:
    return {
        "range": "example",
        "networks": {"edge": {}},  # a section this command does not read
        "path": {
            "steps": [
                {
                    "id": "s01",
                    "technique": "T1000",
                    "guid": GUID,
                    "name": "Example test",
                    "host": "web",
                    "account": "webadmin",
                    "args": {"path": "/tmp/out.txt"},
                    "cleanup": "after_check",
                    **step,
                }
            ]
        },
    }


@pytest.fixture
def atomics(tmp_path: Path) -> Path:
    folder = tmp_path / "atomics"
    (folder / "T1000").mkdir(parents=True)
    test = """\
        input_arguments:
          path: {description: where, type: path, default: /tmp/x}
        executor:
          name: sh
          command: "echo hi > #{path}"
          cleanup_command: "rm -f #{path}"
        """
    (folder / "T1000" / "T1000.yaml").write_text(technique_yaml(test), encoding="utf-8")
    return folder


def test_the_command_writes_every_steps_vectors(tmp_path: Path, atomics: Path) -> None:
    spec = tmp_path / "spec.yaml"
    spec.write_text(json.dumps(a_spec()), encoding="utf-8")

    assert (
        main(["atomic", "argv", str(spec), "--atomics", str(atomics), "--out", str(tmp_path / "argv.json")])
        == 0
    )
    step = json.loads((tmp_path / "argv.json").read_text(encoding="ascii"))["steps"][0]
    assert (step["id"], step["attack"], step["prereqs"], step["cleanup"]) == (
        "s01",
        ["sh", "-c", "echo hi > /tmp/out.txt"],
        [],
        ["sh", "-c", "rm -f /tmp/out.txt"],
    )


def test_a_step_whose_name_is_not_the_published_one_is_refused(atomics: Path) -> None:
    with pytest.raises(ValueError, match="is 'Example test' upstream"):
        atomic.path_argvs(a_spec(name="Another test"), atomics)


def test_a_cleanup_is_refused_for_a_test_that_publishes_none(atomics: Path) -> None:
    path = atomics / "T1000" / "T1000.yaml"
    published = path.read_text(encoding="utf-8")
    path.write_text(published.replace('    cleanup_command: "rm -f #{path}"\n', ""), encoding="utf-8")

    with pytest.raises(ValueError, match="cleanup must be none"):
        atomic.path_argvs(a_spec(), atomics)


def edit_published(atomics: Path, old: str, new: str) -> None:
    path = atomics / "T1000" / "T1000.yaml"
    published = path.read_text(encoding="utf-8")
    assert old in published
    path.write_text(published.replace(old, new), encoding="utf-8")


@pytest.mark.parametrize("null", ["null", "~", "NULL"])
def test_a_null_cleanup_is_an_empty_command_and_no_published_cleanup(atomics: Path, null: str) -> None:
    edit_published(atomics, '"rm -f #{path}"', null)

    assert atomic.path_argvs(a_spec(cleanup="none"), atomics)[0]["cleanup"] == ["sh", "-c", ""]
    with pytest.raises(ValueError, match="cleanup must be none"):
        atomic.path_argvs(a_spec(), atomics)


@pytest.mark.parametrize(
    ("step", "old", "new", "refusal"),
    [
        ({"guid": "00000000-0000-0000-0000-000000000000"}, "", "", "0 tests with GUID"),
        ({}, "attack_technique: T1000", "attack_technique: T1001", "the technique YAML is for T1001"),
        ({}, "[linux]", "[windows]", "is not a Linux test"),
        ({}, "    name: sh\n", "    name: sh\n    elevation_required: true\n", "account must be root"),
        ({"cleanup": "sometimes"}, "", "", "cleanup is one of"),
        ({"id": None}, "", "", "step 1 of the path has no id"),
        ({"args": ["/tmp/out.txt"]}, "", "", "args must map"),
    ],
)
def test_a_step_the_pinned_test_does_not_allow_is_refused(
    atomics: Path, step: dict, old: str, new: str, refusal: str
) -> None:
    edit_published(atomics, old, new)

    with pytest.raises(ValueError, match=refusal):
        atomic.path_argvs(a_spec(**step), atomics)


def test_a_test_that_needs_elevation_is_allowed_as_root(atomics: Path) -> None:
    edit_published(atomics, "    name: sh\n", "    name: sh\n    elevation_required: true\n")

    assert atomic.path_argvs(a_spec(account="root"), atomics)[0]["attack"] == [
        "sh",
        "-c",
        "echo hi > /tmp/out.txt",
    ]


def test_prereqs_run_by_the_tests_own_executor_when_it_names_no_other(tmp_path: Path) -> None:
    test = """\
        dependencies:
        - description: a tool
          prereq_command: command -v tool
        executor: {name: bash, command: tool}
        """

    assert atomic.argvs(a_test(tmp_path, test), {})["prereqs"] == [["bash", "-c", "command -v tool"]]


def test_an_argument_published_without_a_default_left_out_is_refused(tmp_path: Path) -> None:
    test = """\
        input_arguments:
          flags:
        executor: {name: sh, command: "ls #{flags}"}
        """

    with pytest.raises(ValueError, match="flags: ''"):
        attack(tmp_path, test)


def test_the_atomics_folder_written_with_a_letter_that_is_not_ascii_is_refused(tmp_path: Path) -> None:
    test = """\
        input_arguments:
          path: {description: where, type: path, default: x}
        executor: {name: sh, command: "cat #{path}"}
        """
    # A capital I with a dot above, which -replace matches to i in some cultures and not in others.
    spelling = "PathToAtom" + chr(0x130) + "csFolder/T1000/a"

    with pytest.raises(ValueError, match="not ASCII"):
        attack(tmp_path, test, {"path": spelling})

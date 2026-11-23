"""Read published Atomic Red Team tests and give the argument vectors the upstream executor starts.

Each function follows one piece of Invoke-AtomicRedTeam at commit 8af478bb, named in its
docstring, and the .NET code that turns its command line into an argument vector. The
job atomic-parity in .github/workflows/range-one.yml runs that executor with stand-ins
for sh and bash and compares what they were started with, byte for byte, with what these
functions give.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

import yaml

# Where the atomics folder is on a range host.
ATOMICS_PATH = "/opt/atomics"
SHELLS = ("sh", "bash")
CLEANUPS = ("after_check", "after_path", "none")
# Upstream merges input arguments in the order of a .NET hash table, which differs from one
# process to the next. The merge is checked to give the same text in every order, up to this
# many arguments.
MOST_ARGUMENTS = 8
# What .NET's String.Trim removes: the characters for which Char.IsWhiteSpace is true.
DOTNET_WHITESPACE = "".join(
    chr(code)
    for code in [*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029]
    + [0x202F, 0x205F, 0x3000]
)


class _Loader(yaml.BaseLoader):
    """Every scalar as its text, except a plain null, ~ or empty value, which becomes "".

    powershell-yaml gives $null for those, and upstream stores the YAML in classes whose
    fields are strings, so they reach a command as "". The null words are matched in any
    case, as powershell-yaml does.
    """


_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:null", re.compile(r"^(?:~|[nN][uU][lL][lL]|)$"), [*"~nN", ""]
)
_Loader.add_constructor("tag:yaml.org,2002:null", lambda loader, node: "")


def load_technique(path: Path) -> dict:
    """A technique YAML of Atomic Red Team, every value as text."""

    return yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)


def find_test(document: dict, guid: str) -> dict:
    """The test with this GUID in a technique YAML."""

    found = [test for test in document.get("atomic_tests") or [] if test.get("auto_generated_guid") == guid]
    if len(found) != 1:
        raise ValueError(f"the technique YAML has {len(found)} tests with GUID {guid}")
    return found[0]


def dotnet_trim(text: str) -> str:
    return text.strip(DOTNET_WHITESPACE)


# PathToAtomicsFolder with any character that is not ASCII allowed in place of a letter. How
# -replace matches such a character to a letter depends on the culture pwsh runs under.
_NEAR_ATOMICS_FOLDER = re.compile(
    "(?=(" + "".join(f"(?:[{c.lower()}{c.upper()}]|[^\\x00-\\x7f])" for c in "PathToAtomicsFolder") + "))"
)


def _merge_once(text: str, order: tuple[str, ...], args: dict[str, str], atomics_path: str) -> str:
    for key in order:
        text = text.replace("#{" + key + "}", args[key])
    if any(not match.group(1).isascii() for match in _NEAR_ATOMICS_FOLDER.finditer(text)):
        raise ValueError("a letter of PathToAtomicsFolder is written with a character that is not ASCII")
    # PowerShell's -replace ignores case. A function as replacement keeps the path literal.
    text = re.sub(r"\$PathToAtomicsFolder", lambda _: atomics_path, text, flags=re.IGNORECASE | re.ASCII)
    return re.sub("PathToAtomicsFolder", lambda _: atomics_path, text, flags=re.IGNORECASE | re.ASCII)


def merge(text: str | None, args: dict[str, str], atomics_path: str = ATOMICS_PATH) -> str:
    """Merge-InputArgs (Private/Replace-InputArgs.ps1): each #{name} replaced by its value as
    plain text, then $PathToAtomicsFolder and PathToAtomicsFolder by the atomics folder. A
    missing command gives "", as PowerShell's -replace does with $null.

    -replace ignores case by the rules of the current culture. This follows the invariant
    culture, so pwsh must run with invariant globalization (DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1),
    and text that would be matched differently in another culture is refused."""

    if text is None:
        text = ""
    if "$" in atomics_path:
        raise ValueError(f"the atomics folder {atomics_path!r} holds a $, which -replace would read")
    if len(args) > MOST_ARGUMENTS:
        raise ValueError(f"more than {MOST_ARGUMENTS} input arguments: the merge order cannot be checked")
    results = {_merge_once(text, order, args, atomics_path) for order in itertools.permutations(args)}
    if len(results) != 1:
        raise ValueError(
            "the input arguments give a different command in a different order, and upstream's order "
            "is not fixed: a value must not make or break another argument's #{name}"
        )
    return results.pop()


def command_line(command: str, executor: str) -> str:
    """The Arguments string Invoke-ExecuteCommand (Private/Invoke-ExecuteCommand.ps1) builds
    for sh and bash: the command trimmed, every backslash not followed by ; doubled, every
    double quote escaped, every newline not after ; replaced by "; ", all after -c in quotes."""

    if executor not in SHELLS:
        raise ValueError(f"the executor {executor!r} is not sh or bash")
    command = dotnet_trim(command)
    command = re.sub(r"\\(?!;)", lambda _: "\\\\", command)
    command = command.replace('"', '\\"')
    command = re.sub(r"(?<!;)\n", "; ", command)
    return f'-c "{command}"'


def split_arguments(arguments: str) -> list[str]:
    """ParseArgumentsIntoList of .NET's Process.Unix.cs: how ProcessStartInfo.Arguments
    becomes the argument vector on Linux."""

    results: list[str] = []
    i, length = 0, len(arguments)
    while i < length:
        while i < length and arguments[i] in " \t":
            i += 1
        if i == length:
            break
        current: list[str] = []
        in_quotes = False
        while i < length:
            backslashes = 0
            while i < length and arguments[i] == "\\":
                i += 1
                backslashes += 1
            if backslashes:
                if i >= length or arguments[i] != '"':
                    current.append("\\" * backslashes)
                else:
                    current.append("\\" * (backslashes // 2))
                    if backslashes % 2:
                        current.append('"')
                        i += 1
                continue
            character = arguments[i]
            if character == '"':
                if in_quotes and i < length - 1 and arguments[i + 1] == '"':
                    current.append('"')
                    i += 1
                else:
                    in_quotes = not in_quotes
                i += 1
                continue
            if character in " \t" and not in_quotes:
                break
            current.append(character)
            i += 1
        results.append("".join(current))
        i += 1
    return results


def shell_argv(command: str, executor: str) -> list[str]:
    """The argument vector upstream starts for a merged command: the bare name sh or bash,
    which .NET looks up in PATH, then what the command line splits into."""

    argv = [executor, *split_arguments(command_line(command, executor))]
    for element in argv:
        if "\x00" in element:
            raise ValueError("a command holds a NUL character, which no argument vector can carry")
        try:
            element.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("a command holds a character that has no UTF-8 form") from error
    return argv


def declared(test: dict) -> list[str]:
    """The test's input arguments, in the order the YAML declares them."""

    return list(test.get("input_arguments") or {})


def check_args(test: dict, args: dict) -> None:
    """Refuse arguments that are not exactly the declared ones, each written out as text.

    A default left out would reach the command unseen, and upstream drops an argument the
    test does not declare without a word.
    """

    if not isinstance(args, dict):
        raise ValueError("args must map each input argument's name to its value")
    names = declared(test)
    missing = [name for name in names if name not in args]
    if missing:
        published = test["input_arguments"]
        defaults = ", ".join(
            f"{name}: {(published[name] if isinstance(published[name], dict) else {}).get('default', '')!r}"
            for name in missing
        )
        raise ValueError(f"write out every declared input argument, even at its default ({defaults})")
    extra = sorted(set(args) - set(names))
    if extra:
        raise ValueError(f"the test declares no input argument {', '.join(extra)}")
    for name, value in args.items():
        if not isinstance(value, str):
            raise ValueError(f'the input argument {name} must be text, as in {name}: "{value}"')


def argvs(test: dict, args: dict[str, str], atomics_path: str = ATOMICS_PATH) -> dict:
    """The argument vectors upstream starts for one test with these input arguments: the
    attack (Invoke-AtomicTest), one prereq check per dependency (-CheckPrereqs, through
    Private/Invoke-CheckPrereqs.ps1) and the cleanup (-Cleanup).

    A prereq_command is trimmed and its lines joined with " && " first, and runs with
    dependency_executor_name when the test names one (Private/Get-PrereqExecutor.ps1). A
    test without a published cleanup still gets a cleanup vector: upstream starts the
    shell with an empty command.
    """

    check_args(test, args)
    executor = test["executor"]["name"]
    prereq_executor = test.get("dependency_executor_name", executor)
    if prereq_executor not in SHELLS:
        raise ValueError(f"the dependency executor {prereq_executor!r} is not sh or bash")
    prereqs = []
    for dependency in test.get("dependencies") or []:
        command = merge(dependency.get("prereq_command"), args, atomics_path)
        prereqs.append(shell_argv(dotnet_trim(command).replace("\n", " && "), prereq_executor))
    cleanup = test["executor"].get("cleanup_command")
    return {
        "attack": shell_argv(merge(test["executor"].get("command"), args, atomics_path), executor),
        "prereqs": prereqs,
        "cleanup": shell_argv(merge(cleanup, args, atomics_path), executor),
        "cleanup_published": bool(dotnet_trim(cleanup or "")),
    }


def check_step(step: dict, document: dict, test: dict) -> None:
    """The rules for a step of a range's path that need only the pinned technique YAML."""

    label = f"step {step.get('id')}"
    techniques = document.get("attack_technique")
    techniques = techniques if isinstance(techniques, list) else [techniques]
    if step.get("technique") not in techniques:
        raise ValueError(f"{label}: the technique YAML is for {', '.join(map(str, techniques))}")
    if test.get("name") != step.get("name"):
        raise ValueError(
            f"{label}: {step.get('guid')} is {test.get('name')!r} upstream, not {step.get('name')!r}"
        )
    if "linux" not in (test.get("supported_platforms") or []):
        raise ValueError(f"{label}: {test.get('name')!r} is not a Linux test")
    elevated = str(test["executor"].get("elevation_required", "")).lower() == "true"
    if elevated and step.get("account") != "root":
        raise ValueError(f"{label}: {test.get('name')!r} needs elevation, so its account must be root")
    if step.get("cleanup") not in CLEANUPS:
        raise ValueError(f"{label}: cleanup is one of {', '.join(CLEANUPS)}")
    if step["cleanup"] != "none" and not dotnet_trim(test["executor"].get("cleanup_command") or ""):
        raise ValueError(f"{label}: {test.get('name')!r} has no published cleanup, so cleanup must be none")


def path_argvs(spec: dict, atomics: Path, atomics_path: str = ATOMICS_PATH) -> list[dict]:
    """For every step of the spec's path, its test checked against the pinned YAML in the
    atomics folder and the argument vectors upstream would start for it."""

    steps = []
    for number, step in enumerate((spec.get("path") or {}).get("steps") or [], start=1):
        if not isinstance(step, dict) or not step.get("id"):
            raise ValueError(f"step {number} of the path has no id")
        technique, guid = str(step.get("technique")), str(step.get("guid"))
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
            raise ValueError(f"step {step.get('id')}: {technique!r} is not a technique id")
        try:
            document = load_technique(atomics / technique / f"{technique}.yaml")
            test = find_test(document, guid)
            check_step(step, document, test)
            vectors = argvs(test, step.get("args") or {}, atomics_path)
        except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
            raise ValueError(f"step {step.get('id')} ({technique} {guid}): {error}") from error
        steps.append(
            {
                "id": step["id"],
                "technique": technique,
                "guid": guid,
                "args": step.get("args") or {},
                **vectors,
            }
        )
    if not steps:
        raise ValueError("the spec has no path steps")
    return steps


def write(spec_file: Path, atomics: Path, out: Path, atomics_path: str = ATOMICS_PATH) -> int:
    """Write every step's argument vectors as JSON. Every character that is not ASCII is
    written as an escape, and the file is read back and compared before the command ends."""

    spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
    try:
        steps = path_argvs(spec, atomics, atomics_path)
    except ValueError as error:
        raise SystemExit(f"{spec_file}: {error}") from error
    document = {
        "schema": "bluefire-lab/atomic-argv/1",
        "range": spec.get("range"),
        "atomic_red_team": spec.get("atomic_red_team"),
        "executor": spec.get("executor"),
        "atomics_path": atomics_path,
        "steps": steps,
    }
    out.write_text(json.dumps(document, indent=1, ensure_ascii=True) + "\n", encoding="ascii")
    if json.loads(out.read_text(encoding="ascii")) != document:
        raise SystemExit(f"{out} does not read back as what was written")
    print(f"{out}: {len(steps)} steps")
    return 0

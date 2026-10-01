from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from bluefire import release_rights_audit
from bluefire.release_rights_audit import RightsAuditError, run_release_rights_audit

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "bluefire/data/release_rights_policy.json").read_text(encoding="utf-8"))


def _with_policy(monkeypatch: pytest.MonkeyPatch, mutate: object) -> None:
    policy = copy.deepcopy(POLICY)
    assert callable(mutate)
    mutate(policy)
    monkeypatch.setattr(release_rights_audit, "_read_policy", lambda _repository: policy)


def test_release_rights_audit_covers_the_release_tree() -> None:
    report = run_release_rights_audit(ROOT)

    assert report.to_dict() == {
        "decision": "retain-mit",
        "project_license": "MIT",
        "python_runtime_distributions": 6,
        "python_optional_distributions": 3,
        "frontend_runtime_packages": 69,
        "frontend_locked_packages": 391,
        "rust_release_crates": 43,
        "rust_locked_crates": 49,
        "classified_assets": 47,
        "project_source_files": report.project_source_files,
        "unresolved_items": [],
    }
    assert report.project_source_files > 250


def test_conditional_parser_dependency_requires_reviewed_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(monkeypatch, lambda policy: policy["python"].pop("runtime_backports_sha256"))
    with pytest.raises(RightsAuditError, match="backport inventory changed"):
        run_release_rights_audit(ROOT)


def test_conditional_parser_dependency_cannot_be_omitted_from_declarations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch, lambda policy: policy["python"]["declared_runtime_requirements"].pop()
    )
    with pytest.raises(RightsAuditError, match="requirement declarations drifted"):
        run_release_rights_audit(ROOT)


def test_backport_inventory_is_separate_from_the_python312_wheelhouse() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    count, _, _ = release_rights_audit._verify_python(ROOT, POLICY, pyproject)
    wheelhouse = json.loads(
        (ROOT / POLICY["python"]["locked_runtime_source"]).read_text(encoding="utf-8")
    )
    assert wheelhouse["python"] == {"implementation": "cpython", "major": 3, "minor": 12}
    assert len(wheelhouse["wheels"]) == 5
    assert "tomli" not in {row["distribution"] for row in wheelhouse["wheels"]}
    assert count == 6


@pytest.mark.parametrize(
    "target",
    [
        "'cfg(target_os = \"linux\")'",
        r'"cfg(target_os = \"windows\")"',
        "x86_64-unknown-linux-musl",
        '"x86_64-pc-windows-msvc"',
    ],
)
def test_cargo_direct_dependencies_include_every_target_but_not_development(target: str) -> None:
    manifest = f"""[dependencies]
shared = "1"
[dev-dependencies]
root_test_only = "1"
[ target . {target} . dependencies ] # target production roots
target_only = {{ version = "1", default-features = false }}
shared = "1"
[target.{target}.dev-dependencies]
target_test_only = "1"
"""

    assert release_rights_audit._cargo_direct_dependencies(manifest) == [
        "shared",
        "target_only",
    ]


def test_cargo_direct_dependencies_accept_target_only_manifest() -> None:
    manifest = """[target.'cfg(target_os = "linux")'.dependencies]
linux-raw-sys = { version = "=0.12.1", default-features = false, features = ["general", "no_std"] }
"""

    assert release_rights_audit._cargo_direct_dependencies(manifest) == ["linux-raw-sys"]


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        ('[dev-dependencies]\ntest_only = "1"\n', "dependencies are missing"),
        (
            "[target.'cfg(unix)'.dev-dependencies]\ntest_only = \"1\"\n",
            "dependencies are missing",
        ),
        ("[dependencies]\n# no production roots\n", "release dependencies are empty"),
        (
            "[target.'cfg(unix)'.dependencies]\n# no production roots\n",
            "release dependencies are empty",
        ),
    ],
)
def test_cargo_direct_dependencies_refuse_missing_or_empty_roots(
    manifest: str, message: str
) -> None:
    with pytest.raises(RightsAuditError, match=message):
        release_rights_audit._cargo_direct_dependencies(manifest)


@pytest.fixture
def target_cargo_repository(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    runner = tmp_path / "runner"
    runner.mkdir()
    (runner / "Cargo.toml").write_text(
        """[dependencies]
base = "1"
[target.'cfg(target_os = "linux")'.dependencies]
target = "1"
[dev-dependencies]
development = "1"
[target.'cfg(target_os = "windows")'.dev-dependencies]
development = "1"
""",
        encoding="utf-8",
    )
    lock = "\n".join(
        f"""[[package]]
name = "{name}"
version = "1.0.0"
checksum = "{'0' * 64}"
""" + ('dependencies = [\n "target-leaf",\n]\n' if name == "target" else "")
        for name in ("base", "target", "target-leaf", "development")
    )
    (runner / "Cargo.lock").write_bytes(lock.encode("utf-8"))
    policy = {
        "rust": {
            "lockfile_sha256": hashlib.sha256(lock.encode("utf-8")).hexdigest(),
            "locked_crates_by_license": {
                "MIT": [
                    "base@1.0.0",
                    "target@1.0.0",
                    "target-leaf@1.0.0",
                    "development@1.0.0",
                ]
            },
            "release_graph": ["base@1.0.0", "target@1.0.0", "target-leaf@1.0.0"],
        }
    }
    return tmp_path, policy


def test_rust_release_graph_includes_target_transitives_and_excludes_development(
    target_cargo_repository: tuple[Path, dict[str, Any]],
) -> None:
    repository, policy = target_cargo_repository

    assert release_rights_audit._verify_rust(repository, policy) == (3, 4, {"MIT"})


@pytest.mark.parametrize("package", ["target@1.0.0", "target-leaf@1.0.0"])
def test_rust_target_dependency_requires_license_classification(
    target_cargo_repository: tuple[Path, dict[str, Any]], package: str
) -> None:
    repository, policy = target_cargo_repository
    policy["rust"]["locked_crates_by_license"]["MIT"].remove(package)

    with pytest.raises(RightsAuditError, match="Rust locked crate is unclassified or stale"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize("package", ["target@1.0.0", "target-leaf@1.0.0"])
def test_rust_target_dependency_requires_reviewed_release_graph_entry(
    target_cargo_repository: tuple[Path, dict[str, Any]], package: str
) -> None:
    repository, policy = target_cargo_repository
    policy["rust"]["release_graph"].remove(package)

    with pytest.raises(RightsAuditError, match="Rust release dependency graph drifted"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.fixture(params=["dependencies", "target.'cfg(unix)'.dependencies"])
def detailed_cargo_repository(
    request: pytest.FixtureRequest,
    target_cargo_repository: tuple[Path, dict[str, Any]],
) -> tuple[Path, dict[str, Any]]:
    repository, policy = target_cargo_repository
    manifest = f"""[dependencies]
base = "1"
[{request.param}.target]
version = "1"
features = [
    "first",
    "second",
]
[dev-dependencies.development]
version = "1"
[target.'cfg(windows)'.dev-dependencies.development]
version = "1"
"""
    (repository / "runner/Cargo.toml").write_text(manifest, encoding="utf-8")
    return repository, policy


def test_rust_detailed_dependency_includes_full_closure_and_excludes_development(
    detailed_cargo_repository: tuple[Path, dict[str, Any]],
) -> None:
    repository, policy = detailed_cargo_repository

    assert release_rights_audit._verify_rust(repository, policy) == (3, 4, {"MIT"})


@pytest.mark.parametrize("missing", ["target@1.0.0", "target-leaf@1.0.0", "both"])
def test_rust_detailed_dependency_cannot_be_omitted_despite_an_ordinary_root(
    detailed_cargo_repository: tuple[Path, dict[str, Any]], missing: str
) -> None:
    repository, policy = detailed_cargo_repository
    policy["rust"]["release_graph"] = [
        package
        for package in policy["rust"]["release_graph"]
        if package != missing and (missing != "both" or package == "base@1.0.0")
    ]

    with pytest.raises(RightsAuditError, match="Rust release dependency graph drifted"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize("package", ["target@1.0.0", "target-leaf@1.0.0"])
def test_rust_detailed_dependency_requires_license_classification(
    detailed_cargo_repository: tuple[Path, dict[str, Any]], package: str
) -> None:
    repository, policy = detailed_cargo_repository
    policy["rust"]["locked_crates_by_license"]["MIT"].remove(package)

    with pytest.raises(RightsAuditError, match="Rust locked crate is unclassified or stale"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize(
    "declaration",
    [
        "[ 'dependencies' . 'target' ]\nversion = '1'",
        r'["target"."cfg(target_os = \"linux\")"."dependencies"."tar\u0067et"]' '\nversion = "1"',
        "[target.'cfg(unix)'.'dependencies']\n\"target\".version = '1'",
        '"target"."cfg(unix)"."dependencies"."target".version = "1"',
    ],
)
def test_rust_detailed_dependency_accepts_quoted_and_dotted_keys(
    target_cargo_repository: tuple[Path, dict[str, Any]], declaration: str
) -> None:
    repository, policy = target_cargo_repository
    # The root dotted form must precede any table header; ordinary roots still exist.
    manifest = declaration + '\n[dependencies]\n"base" = "1"\n'
    if declaration.startswith("["):
        manifest = '[dependencies]\n"base" = "1"\n' + declaration
    (repository / "runner/Cargo.toml").write_text(manifest, encoding="utf-8")

    assert release_rights_audit._verify_rust(repository, policy) == (3, 4, {"MIT"})


@pytest.mark.parametrize(
    "declaration",
    [
        '[dependencies.development]\npackage = "target"\nversion = "1"',
        "[target.'cfg(unix)'.dependencies.development]\n'package' = 'target'\nversion = '1'",
        r'[target."cfg(unix)".dependencies]'
        "\n" + r'development = { "pac\u006bage" = "target", version = "1" }',
    ],
)
def test_rust_dependency_alias_is_refused_even_when_alias_name_is_locked(
    target_cargo_repository: tuple[Path, dict[str, Any]], declaration: str
) -> None:
    repository, policy = target_cargo_repository
    (repository / "runner/Cargo.toml").write_text(
        '[dependencies]\nbase = "1"\n' + declaration, encoding="utf-8"
    )
    policy["rust"]["release_graph"] = ["base@1.0.0", "development@1.0.0"]

    with pytest.raises(RightsAuditError, match="aliases or workspace inheritance"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize(
    "declaration",
    [
        "[dependencies.target]\nworkspace = true",
        '[target."cfg(unix)".dependencies]\ntarget.workspace = true',
        '[dependencies.target.extra]\nversion = "1"',
    ],
)
def test_cargo_unsupported_dependency_shapes_require_review(declaration: str) -> None:
    with pytest.raises(RightsAuditError, match="require.*review"):
        release_rights_audit._cargo_direct_dependencies(
            '[dependencies]\nbase = "1"\n' + declaration
        )


@pytest.mark.parametrize("scope", ["dependencies", "target.'cfg(unix)'.dependencies"])
def test_rust_multiline_inline_alias_cannot_select_a_development_decoy(
    target_cargo_repository: tuple[Path, dict[str, Any]], scope: str
) -> None:
    repository, policy = target_cargo_repository
    manifest = f"""dependencies.base = "1"
{scope}.development = {{ path = "../target",
 package = "target" }}
[dev-dependencies]
development = "1"
"""
    (repository / "runner/Cargo.toml").write_text(manifest, encoding="utf-8")
    policy["rust"]["release_graph"] = ["base@1.0.0", "development@1.0.0"]

    # TOML 1.0 parsers refuse the multiline inline table; TOML 1.1 parsers
    # must see its complete value and refuse the alias. Neither may accept
    # the development-only decoy while omitting target and target-leaf.
    with pytest.raises(RightsAuditError, match="unsupported TOML syntax|aliases or workspace"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize("scope", ["dependencies", "target.'cfg(unix)'.dependencies"])
@pytest.mark.parametrize("attribute", ['package = "target"', "workspace = true"])
def test_rust_alias_after_multiline_array_is_refused_before_resolving_a_decoy(
    target_cargo_repository: tuple[Path, dict[str, Any]], scope: str, attribute: str
) -> None:
    repository, policy = target_cargo_repository
    # Newlines within the array value are valid even in TOML 1.0. The alias
    # attribute is outside the first physical line of its dependency value.
    manifest = f"""dependencies.base = "1"
{scope}.development = {{ features = [
 "feature",
], version = "1", {attribute} }}
[dev-dependencies]
development = "1"
"""
    (repository / "runner/Cargo.toml").write_text(manifest, encoding="utf-8")
    policy["rust"]["release_graph"] = ["base@1.0.0", "development@1.0.0"]

    with pytest.raises(RightsAuditError, match="aliases or workspace inheritance"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize(
    "manifest",
    [
        'dependencies = { base = "1", target = { version = "1" } }',
        """dependencies.base = "1"
target = { 'cfg(unix)' = { dependencies = { target = "1" } } }
""",
        """dependencies.base = "1"
dependencies.target = { features = [
 "first",
 "second",
], version = "1" }
""",
        '''[package]
description = """
[dependencies.development]
package = "unrelated"
"""
[dependencies]
base = "1"
target = "1"
''',
    ],
)
def test_rust_complete_toml_values_preserve_the_production_closure(
    target_cargo_repository: tuple[Path, dict[str, Any]], manifest: str
) -> None:
    repository, policy = target_cargo_repository
    (repository / "runner/Cargo.toml").write_text(
        manifest + '\n[dev-dependencies]\ndevelopment = "1"\n', encoding="utf-8"
    )

    assert release_rights_audit._verify_rust(repository, policy) == (3, 4, {"MIT"})
    policy["rust"]["release_graph"].remove("target-leaf@1.0.0")
    with pytest.raises(RightsAuditError, match="Rust release dependency graph drifted"):
        release_rights_audit._verify_rust(repository, policy)


@pytest.mark.parametrize(
    "manifest",
    [
        'dependencies.base = "1"\ndependencies.base = "2"',
        'dependencies = ["base"]',
        "dependencies.base = 1",
        'dependencies.base = { version = "1", features = "feature" }',
        'dependencies.base = { version = "1", optional = "false" }',
        'dependencies.base = { version = "1", path = { nested = "source" } }',
        'dependencies.base = "1"\ntarget = ["cfg(unix)"]',
        'dependencies.base = "1"\ntarget."cfg(unix)" = "target"',
        '[[dependencies.base]]\nversion = "1"',
        'dependencies.base = { version = "1"',
    ],
)
def test_cargo_invalid_syntax_or_dependency_types_fail_closed(manifest: str) -> None:
    with pytest.raises(RightsAuditError):
        release_rights_audit._cargo_direct_dependencies(manifest)


def test_reviewed_text_hash_is_stable_across_git_line_endings(tmp_path: Path) -> None:
    lockfile = tmp_path / "reviewed.lock"
    lockfile.write_bytes(b"first\nsecond\n")
    expected = hashlib.sha256(b"first\nsecond\n").hexdigest()

    assert release_rights_audit._reviewed_text_sha256(lockfile) == expected

    lockfile.write_bytes(b"first\r\nsecond\r\n")
    assert release_rights_audit._reviewed_text_sha256(lockfile) == expected


@pytest.mark.parametrize("payload", [b"mixed\rline\n", b"binary\x00lock", b"bad-utf8-\xff"])
def test_reviewed_text_hash_rejects_noncanonical_text(
    tmp_path: Path,
    payload: bytes,
) -> None:
    lockfile = tmp_path / "reviewed.lock"
    lockfile.write_bytes(payload)

    with pytest.raises(RightsAuditError, match="reviewed file"):
        release_rights_audit._reviewed_text_sha256(lockfile)


def test_release_rights_audit_fails_closed_on_unresolved_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(monkeypatch, lambda policy: policy["unresolved_items"].append("unknown asset"))

    with pytest.raises(RightsAuditError, match="unresolved release items"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_refuses_unclassified_python_wheel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch,
        lambda policy: policy["python"]["locked_runtime_distributions"].pop(),
    )

    with pytest.raises(RightsAuditError, match="Python dependency inventory"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_refuses_unclassified_frontend_runtime_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch,
        lambda policy: policy["frontend"]["runtime_packages_by_license"]["MIT"].remove(
            "react@19.2.8"
        ),
    )

    with pytest.raises(RightsAuditError, match="frontend runtime dependency"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_refuses_unclassified_rust_crate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch,
        lambda policy: policy["rust"]["locked_crates_by_license"]["MIT"].remove("spin@0.9.9"),
    )

    with pytest.raises(RightsAuditError, match="Rust locked crate"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_refuses_unclassified_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = release_rights_audit._asset_files
    monkeypatch.setattr(
        release_rights_audit,
        "_asset_files",
        lambda repository: original(repository) | {"bluefire/data/unreviewed.bin"},
    )

    with pytest.raises(RightsAuditError, match="asset inventory"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_refuses_unsubstantiated_relicense(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mutate(policy: dict[str, object]) -> None:
        decision = policy["release_decision"]
        assert isinstance(decision, dict)
        decision["decision"] = "AGPL-3.0-only"

    _with_policy(monkeypatch, mutate)

    with pytest.raises(RightsAuditError, match="unreviewed release license decision"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_requires_notice_in_wheel_license_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch,
        lambda policy: policy["project_license"]["license_files"].remove("THIRD_PARTY_NOTICES.md"),
    )

    with pytest.raises(RightsAuditError, match="license-files drifted"):
        run_release_rights_audit(ROOT)


def test_release_rights_audit_requires_reviewed_notice_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_policy(
        monkeypatch,
        lambda policy: policy["notices"]["required_fragments"].append(
            "a notice that was not committed"
        ),
    )

    with pytest.raises(RightsAuditError, match="third-party notice is incomplete"):
        run_release_rights_audit(ROOT)

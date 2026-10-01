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
        "python_runtime_distributions": 5,
        "python_optional_distributions": 3,
        "frontend_runtime_packages": 69,
        "frontend_locked_packages": 391,
        "rust_release_crates": 43,
        "rust_locked_crates": 49,
        "classified_assets": 46,
        "project_source_files": report.project_source_files,
        "unresolved_items": [],
    }
    assert report.project_source_files > 250


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

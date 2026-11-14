"""Offline, stdlib-only checks for the root-private service installer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

_REPOSITORY = Path(__file__).resolve().parents[1]
_SOURCE = _REPOSITORY / "tools" / "install_root_private_bluefire_service.py"
_SPEC = importlib.util.spec_from_file_location("root_private_service_installer", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
installer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(installer)
_LOCK = (_REPOSITORY / "bluefire" / "data" / "gate11_linux_wheelhouse.json").read_bytes()


class ExactPathsTests(unittest.TestCase):
    def test_product_wheel_keeps_installable_filename(self) -> None:
        self.assertIsNotNone(
            installer._PRODUCT_WHEEL_FILENAME.fullmatch("bluefire_nexus-3.0.0rc2-py3-none-any.whl")
        )
        for invalid in (
            "candidate.whl",
            "bluefire_nexus-3.0.0rc2.whl",
            "other-3.0-py3-none-any.whl",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(installer._PRODUCT_WHEEL_FILENAME.fullmatch(invalid))

    def test_run_paths_are_exact_and_non_discoverable(self) -> None:
        bootstrap, root = installer._paths("123456-2")
        self.assertEqual(str(bootstrap).replace("\\", "/"), "/root/bluefire-bootstrap-123456-2")
        self.assertEqual(str(root).replace("\\", "/"), "/root/bluefire-ci-123456-2")
        for value in ("", "0-1", "123-0", "123", "../123-1", "abc-1", "123-1/other"):
            with self.subTest(value=value), self.assertRaises(installer.InstallError):
                installer._paths(value)

    def test_preimport_bootstrap_rejects_runner_owned_or_symlinked_source(self) -> None:
        bootstrap = Path("/root/bluefire-bootstrap-123-1")
        good_dir = types.SimpleNamespace(st_mode=0o040700, st_uid=0)
        good_file = types.SimpleNamespace(st_mode=0o100600, st_uid=0)

        def observed(path: Path) -> object:
            if path in (Path("/"), Path("/root"), bootstrap):
                return good_dir
            return good_file

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=observed):
            installer._precheck_bootstrap(bootstrap)

        wrong = bootstrap / "verify_root_private_bluefire_service.py"

        def runner_owned(path: Path) -> object:
            if path == wrong:
                return types.SimpleNamespace(st_mode=0o100600, st_uid=1001)
            return observed(path)

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=runner_owned):
            with self.assertRaisesRegex(installer.InstallError, "bootstrap_custody_invalid"):
                installer._precheck_bootstrap(bootstrap)


class WheelhouseTests(unittest.TestCase):
    def test_exact_five_wheels_and_lock_digest_come_from_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "candidate.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(installer._LOCK_MEMBER, _LOCK)
            digest, rows = installer._locked_wheels(wheel)
        self.assertEqual(digest, "sha256:" + hashlib.sha256(_LOCK).hexdigest())
        self.assertEqual(len(rows), 5)
        self.assertEqual({row["distribution"] for row in rows}, installer._DISTRIBUTIONS)

    def test_duplicate_lock_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "candidate.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(installer._LOCK_MEMBER, _LOCK)
                archive.writestr(installer._LOCK_MEMBER, _LOCK)
            with self.assertRaisesRegex(installer.InstallError, "wheelhouse_lock_missing"):
                installer._locked_wheels(wheel)

    def test_receipt_and_directory_inventory_must_match_locked_wheels(self) -> None:
        rows = json.loads(_LOCK)["wheels"]
        lock_digest = "sha256:" + hashlib.sha256(_LOCK).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            for row in rows:
                (directory / row["filename"]).write_bytes(b"test fixture")
            receipt = directory / "service-wheelhouse-receipt.json"
            value = {
                "schema_version": "bluefire.service-wheelhouse-receipt.v1",
                "lock_sha256": lock_digest,
                "platform": "linux",
                "architecture": "x86_64",
                "python": "3.12",
                "wheelhouse_dir": str(directory),
                "wheel_inventory_digest": installer._inventory_digest(rows),
            }
            receipt.write_text(json.dumps(value), encoding="utf-8")
            installer._wheelhouse_source(directory, lock_digest, rows)
            value["lock_sha256"] = "sha256:" + "0" * 64
            receipt.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(installer.InstallError, "wheelhouse_receipt_invalid"):
                installer._wheelhouse_source(directory, lock_digest, rows)
            value["lock_sha256"] = lock_digest
            receipt.write_text(json.dumps(value), encoding="utf-8")
            (directory / "unexpected.whl").write_bytes(b"extra")
            with self.assertRaisesRegex(installer.InstallError, "wheelhouse_inventory_invalid"):
                installer._wheelhouse_source(directory, lock_digest, rows)

    def test_copied_wheel_is_hash_and_size_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.whl"
            source.write_bytes(b"verified wheel fixture")
            size = source.stat().st_size
            digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            target = root / "target.whl"
            installer._copy_exact(source, target, size=size, sha256=digest)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            bad = root / "bad.whl"
            with self.assertRaisesRegex(installer.InstallError, "source_changed"):
                installer._copy_exact(source, bad, size=size, sha256="sha256:" + "0" * 64)
            self.assertFalse(bad.exists())


class CleanupGuardTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX venv aliases")
    def test_cleanup_unlinks_only_conventional_venv_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bootstrap = Path(temporary) / "bootstrap"
            root = Path(temporary) / "root"
            bin_dir = root / "venv" / "bin"
            bin_dir.mkdir(parents=True)
            (root / "venv" / "lib").mkdir()
            bootstrap.mkdir()
            (bin_dir / "python3.12").write_bytes(b"copied interpreter")
            (bin_dir / "python").symlink_to("python3.12")
            (root / "venv" / "lib64").symlink_to("lib", target_is_directory=True)
            gate = types.ModuleType("gate")
            gate._secure_path = lambda path, **_kwargs: path.lstat()
            args = types.SimpleNamespace(run_id="123-1", retained_evidence_digest=None)
            with (
                mock.patch.object(installer, "_bootstrap", return_value=(gate, bootstrap, root)),
                mock.patch.object(installer, "_assert_no_mounts"),
                mock.patch.object(installer.os, "chdir"),
                mock.patch.object(installer.shutil.rmtree, "avoids_symlink_attacks", True),
            ):
                self.assertEqual(installer.cleanup(args), "evidence_missing")
            self.assertFalse(bootstrap.exists())
            self.assertFalse(root.exists())

    def test_cleanup_removes_exact_temporary_roots_and_reports_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bootstrap = Path(temporary) / "bootstrap"
            root = Path(temporary) / "root"
            bootstrap.mkdir()
            root.mkdir()
            gate = types.ModuleType("gate")
            gate._secure_path = lambda path, **_kwargs: path.lstat()
            args = types.SimpleNamespace(run_id="123-1", retained_evidence_digest=None)
            with (
                mock.patch.object(installer, "_bootstrap", return_value=(gate, bootstrap, root)),
                mock.patch.object(installer, "_assert_no_mounts"),
                mock.patch.object(installer.os, "chdir"),
                mock.patch.object(installer.shutil.rmtree, "avoids_symlink_attacks", True),
            ):
                self.assertEqual(installer.cleanup(args), "evidence_missing")
            self.assertFalse(bootstrap.exists())
            self.assertFalse(root.exists())

    def test_cleanup_preserves_roots_when_custody_check_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bootstrap = Path(temporary) / "bootstrap"
            root = Path(temporary) / "root"
            bootstrap.mkdir()
            root.mkdir()
            unsafe = root / "unsafe"
            unsafe.write_bytes(b"retained")
            gate = types.ModuleType("gate")

            def checked(path: Path, **_kwargs: object) -> object:
                if path == unsafe:
                    raise installer.InstallError("path_custody_invalid")
                return path.lstat()

            gate._secure_path = checked
            args = types.SimpleNamespace(run_id="123-1", retained_evidence_digest=None)
            with (
                mock.patch.object(installer, "_bootstrap", return_value=(gate, bootstrap, root)),
                mock.patch.object(installer, "_assert_no_mounts"),
            ):
                with self.assertRaisesRegex(installer.InstallError, "path_custody_invalid"):
                    installer.cleanup(args)
            self.assertTrue(bootstrap.is_dir())
            self.assertTrue(root.is_dir())


class ChildDiagnosticsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX pipe selector")
    def test_failed_child_stderr_is_drained_with_bounded_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            (root / "temp").mkdir()
            with self.assertRaisesRegex(installer.InstallError, "child_failed"):
                installer._run(
                    [
                        sys.executable,
                        "-c",
                        "import os; os.write(2, b'x' * 2_000_000); raise SystemExit(7)",
                    ],
                    root=root,
                    timeout=10,
                    phase="pip",
                )
            captured = (root / "temp" / "pip-failure.stderr").read_bytes()
            self.assertEqual(captured, b"x" * 16_384 + b"\n[truncated]\n")


if __name__ == "__main__":
    unittest.main()

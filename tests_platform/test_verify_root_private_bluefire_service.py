"""Focused stdlib checks for the root-private installed service gate."""

from __future__ import annotations

import importlib.util
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_SOURCE = Path(__file__).resolve().parents[1] / "tools" / "verify_root_private_bluefire_service.py"
_SPEC = importlib.util.spec_from_file_location("root_private_service_gate", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)


class PrivatePathTests(unittest.TestCase):
    def test_root_is_an_exact_child_of_root_with_bounded_name(self) -> None:
        self.assertEqual(
            str(gate._private_root("/root/bluefire-ci-12345-2")),
            str(Path("/root/bluefire-ci-12345-2")),
        )
        for value in (
            "/tmp/bluefire-ci-12345-2",
            "/home/runner/bluefire-ci-12345-2",
            "/root/bluefire-ci-12345-2/venv",
            "/root/bluefire-ci-12345-2/../other",
            "/root//bluefire-ci-12345-2",
            "/root/bluefire-ci-12345-2/",
            "/root/bluefire-ci-UPPER",
        ):
            with self.subTest(value=value), self.assertRaises(gate.VerificationError):
                gate._private_root(value)

    def test_secure_path_checks_ancestors_owner_mode_and_symlinks(self) -> None:
        target = Path.cwd() / "private" / "candidate.whl"
        good_dir = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        good_file = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)

        def observed(path: Path) -> object:
            return good_file if path == target else good_dir

        with mock.patch.object(gate.os, "lstat", side_effect=observed):
            gate._secure_path(target, kind="file", exact_mode=0o600)

        cases = (
            (target.parent, stat.S_IFDIR | 0o770, 0),
            (target.parent, stat.S_IFDIR | 0o700, 1001),
            (target, stat.S_IFLNK | 0o777, 0),
            (target, stat.S_IFREG | 0o620, 0),
        )
        for wrong_path, mode, uid in cases:

            def altered(
                path: Path, *, wrong_path: Path = wrong_path, mode: int = mode, uid: int = uid
            ) -> object:
                if path == wrong_path:
                    return types.SimpleNamespace(st_mode=mode, st_uid=uid)
                return observed(path)

            with self.subTest(path=wrong_path, mode=mode, uid=uid):
                with mock.patch.object(gate.os, "lstat", side_effect=altered):
                    with self.assertRaisesRegex(gate.VerificationError, "path_custody_invalid"):
                        gate._secure_path(target, kind="file", exact_mode=0o600)

    def test_venv_config_requires_one_disabled_system_site_setting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            venv = Path(temporary)
            config = venv / "pyvenv.cfg"
            with mock.patch.object(
                gate, "_secure_path", return_value=types.SimpleNamespace(st_size=100)
            ):
                config.write_text("include-system-site-packages = false\n", encoding="utf-8")
                gate._check_venv_config(venv)
                for value in (
                    "include-system-site-packages = true\n",
                    "include-system-site-packages = false\ninclude-system-site-packages = true\n",
                ):
                    with self.subTest(value=value):
                        config.write_text(value, encoding="utf-8")
                        with self.assertRaisesRegex(gate.VerificationError, "venv_config_invalid"):
                            gate._check_venv_config(venv)


class InstalledIdentityTests(unittest.TestCase):
    def test_build_identity_requires_embedded_source_and_packaged_ui(self) -> None:
        revision = "a" * 40
        files = [
            {"name": name, "sha256": "sha256:" + "b" * 64, "size": 1}
            for name in ("app.js", "index.html", "styles.css", "fonts/InterVariable.woff2")
        ]
        info = {
            "source": {"revision": revision, "provenance": "git_archive"},
            "build": {"metadata_status": "embedded"},
            "ui": {"digest": "sha256:" + "c" * 64, "files": files, "matches_build": True},
            "product": {"version": "3.0.0rc2"},
        }
        helper = types.ModuleType("binding_helper")
        helper.build_identity_valid = lambda value: (
            value["wheel_payload_digest"] == (value["installed_payload_digest"])
        )
        binding = {
            "wheel_member_count": 12,
            "wheel_payload_digest": "sha256:" + "d" * 64,
            "installed_payload_digest": "sha256:" + "d" * 64,
        }
        accepted = gate._identity(
            info=info,
            version="3.0.0rc2",
            wheel_digest="sha256:" + "e" * 64,
            provider_digest="sha256:" + "f" * 64,
            binding=binding,
            expected_revision=revision,
            helper=helper,
        )
        self.assertEqual(accepted["source_revision"], revision)
        self.assertEqual(accepted["ui_files"], files)
        for change in (
            {"source": {"revision": "0" * 40, "provenance": "git_archive"}},
            {"source": {"revision": revision, "provenance": "unavailable"}},
            {"build": {"metadata_status": "unavailable"}},
            {"ui": {"digest": "sha256:" + "c" * 64, "files": files, "matches_build": False}},
        ):
            altered = dict(info)
            altered.update(change)
            with self.subTest(change=change), self.assertRaises(gate.VerificationError):
                gate._identity(
                    info=altered,
                    version="3.0.0rc2",
                    wheel_digest="sha256:" + "e" * 64,
                    provider_digest="sha256:" + "f" * 64,
                    binding=binding,
                    expected_revision=revision,
                    helper=helper,
                )
        with self.assertRaisesRegex(gate.VerificationError, "installed_identity_invalid"):
            gate._identity(
                info=info,
                version="3.0.0rc2",
                wheel_digest="sha256:" + "e" * 64,
                provider_digest="sha256:" + "f" * 64,
                binding={**binding, "installed_payload_digest": "sha256:" + "0" * 64},
                expected_revision=revision,
                helper=helper,
            )


if __name__ == "__main__":
    unittest.main()

"""The hosted service dependency producer accepts only the committed closure."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import prepare_root_private_service_wheelhouse as producer

REVISION = "a" * 40


def _fixture(root: Path) -> tuple[Path, dict[str, bytes]]:
    repository = root / "source"
    lock_file = repository / "bluefire/data/gate11_linux_wheelhouse.json"
    lock_file.parent.mkdir(parents=True)
    (repository / "bluefire/_source_revision.txt").write_text(REVISION + "\n", encoding="ascii")
    original = json.loads(
        (Path(__file__).resolve().parents[1] / producer._LOCK).read_text(encoding="utf-8")
    )
    payloads: dict[str, bytes] = {}
    for row in original["wheels"]:
        content = (row["distribution"] + "-verified-wheel").encode("ascii")
        row["size"] = len(content)
        row["sha256"] = hashlib.sha256(content).hexdigest()
        payloads[row["filename"]] = content
    lock_file.write_text(json.dumps(original, sort_keys=True), encoding="utf-8")
    return repository, payloads


class ServiceWheelhouseProducerTests(unittest.TestCase):
    def test_exact_download_is_bound_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, payloads = _fixture(root)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "bluefire-service-wheelhouse"
            observed_command: list[str] = []

            def download(command, **kwargs) -> None:
                observed_command.extend(command)
                destination = Path(command[command.index("--dest") + 1])
                self.assertEqual(kwargs["env"].get("GITHUB_TOKEN"), None)
                self.assertTrue(kwargs["check"])
                for name, payload in payloads.items():
                    (destination / name).write_bytes(payload)

            with (
                mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}, clear=True),
                mock.patch.object(producer, "_platform_qualified", return_value=True),
                mock.patch.object(producer.subprocess, "run", side_effect=download),
            ):
                receipt = producer.prepare(repository, output, REVISION)

            self.assertEqual(receipt["schema_version"], "bluefire.service-wheelhouse-receipt.v1")
            self.assertEqual(receipt["wheelhouse_dir"], str(output / "wheelhouse"))
            self.assertEqual(
                set(item.name for item in (output / "wheelhouse").iterdir()),
                set(payloads) | {"service-wheelhouse-receipt.json"},
            )
            self.assertEqual(
                json.loads((output / "wheelhouse/service-wheelhouse-receipt.json").read_text()),
                receipt,
            )
            self.assertFalse((output / "requirements.txt").exists())
            self.assertEqual(observed_command[1:5], ["-m", "pip", "--isolated", "download"])
            self.assertIn("--require-hashes", observed_command)
            self.assertIn("--no-deps", observed_command)

    def test_extra_wheel_refuses_and_removes_partial_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, payloads = _fixture(root)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "bluefire-service-wheelhouse"

            def changed(command, **_kwargs) -> None:
                destination = Path(command[command.index("--dest") + 1])
                for name, payload in payloads.items():
                    (destination / name).write_bytes(payload)
                (destination / "extra.whl").write_bytes(b"unexpected")

            with (
                mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}, clear=True),
                mock.patch.object(producer, "_platform_qualified", return_value=True),
                mock.patch.object(producer.subprocess, "run", side_effect=changed),
            ):
                with self.assertRaisesRegex(
                    producer.WheelhousePreparationError, "inventory differs"
                ):
                    producer.prepare(repository, output, REVISION)
            self.assertFalse(output.exists())

    def test_wrong_hash_refuses_and_removes_partial_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, payloads = _fixture(root)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "bluefire-service-wheelhouse"

            def changed(command, **_kwargs) -> None:
                destination = Path(command[command.index("--dest") + 1])
                for name, payload in payloads.items():
                    (destination / name).write_bytes(payload)
                first = next(iter(payloads))
                (destination / first).write_bytes(b"x" * len(payloads[first]))

            with (
                mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}, clear=True),
                mock.patch.object(producer, "_platform_qualified", return_value=True),
                mock.patch.object(producer.subprocess, "run", side_effect=changed),
            ):
                with self.assertRaisesRegex(
                    producer.WheelhousePreparationError, "identity differs"
                ):
                    producer.prepare(repository, output, REVISION)
            self.assertFalse(output.exists())

    def test_uncommitted_or_wrong_lock_and_outside_destination_refuse_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _payloads = _fixture(root)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "bluefire-service-wheelhouse"
            with (
                mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}, clear=True),
                mock.patch.object(producer, "_platform_qualified", return_value=True),
                mock.patch.object(producer.subprocess, "run") as download,
            ):
                with self.assertRaisesRegex(
                    producer.WheelhousePreparationError, "archived source revision"
                ):
                    producer.prepare(repository, output, "b" * 40)
                with self.assertRaisesRegex(
                    producer.WheelhousePreparationError, "escaped runner private"
                ):
                    producer.prepare(repository, root / "outside", REVISION)
                lock_file = repository / producer._LOCK
                value = json.loads(lock_file.read_text())
                value["wheels"][0]["version"] = "0.0.0"
                lock_file.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(
                    producer.WheelhousePreparationError, "lock row differs"
                ):
                    producer.prepare(repository, output, REVISION)
                download.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

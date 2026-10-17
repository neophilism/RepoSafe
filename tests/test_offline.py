import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reposafe.common import BackupError, command
from reposafe.kit import REQUIRED_TOOLS, WHEEL_NAMES, build_kit, verify_kit
from reposafe.offline import enroll_media, export_offline, media_policy, verify_copy
from support_evidence import EvidenceFixture


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = EvidenceFixture(self.root)
        self.keys = self.fixture.keys
        self.source = self.root / "reviewed-source"
        (self.source / "reposafe").mkdir(parents=True)
        (self.source / "reposafe/__init__.py").write_text('"""Synthetic kit source fixture."""\n')
        (self.source / "README.md").write_text("Synthetic test software, not an operational runtime.\n")
        (self.source / "pyproject.toml").write_text('[project]\nname="fixture"\nversion="0.0.0"\n')
        command(["git", "init", self.source])
        command(["git", "-C", self.source, "add", "."])
        command(["git", "-C", self.source, "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture",
                 "-c", "user.email=fixture@example.test", "commit", "-m", "test fixture"])
        self.revision = command(["git", "-C", self.source, "rev-parse", "HEAD"]).decode().strip()
        software = self.root / "software-fixture"
        software.write_bytes(b"fixture software file, not executable")
        self.tools = {name: software for name in REQUIRED_TOOLS}
        self.wheels = []
        for package in WHEEL_NAMES:
            wheel = self.root / (package + "-0.0.0-py3-none-any.whl")
            wheel.write_bytes(b"fixture dependency file; presence test only")
            self.wheels.append(wheel)
        self.kit = self.root / "recovery-kit"
        build_kit(self.source, self.revision, self.kit, self.keys["kit"][0],
                  {role: paths[1] for role, paths in self.keys.items()}, tools=self.tools, wheels=self.wheels)
        self.media = self.root / "mounted-media"
        self.media.mkdir()
        # Only test injection bypasses OS mount lookup; there is no CLI bypass.
        self.identity = lambda root: "filesystem-a"
        enroll_media(self.media, "rotation-a", "filesystem-a", self.keys["offline"][0],
                     encrypted_acknowledged=True, identity=self.identity)

    def export(self, queue, event, **kwargs):
        return export_offline(queue, self.media, self.keys["offline"][1], self.keys["offline"][0],
            self.keys["collector"][1], event, self.keys["witness"][1], self.kit, self.keys["kit"][1],
            identity=self.identity, **kwargs)

    def test_kit_is_pinned_clean_revision_only_and_detects_tampering_or_extra_files(self):
        self.assertTrue(verify_kit(self.kit, self.keys["kit"][1], require_tools=True)["ready_for_drill"])
        with self.assertRaises(BackupError):
            verify_kit(self.kit, self.keys["offline"][1])
        (self.kit / "unexpected.env").write_text("should never be accepted")
        with self.assertRaises(BackupError):
            verify_kit(self.kit, self.keys["kit"][1])
        (self.source / "README.md").write_text("uncommitted change")
        with self.assertRaises(BackupError):
            build_kit(self.source, self.revision, self.root / "dirty-kit", self.keys["kit"][0], {"witness": self.keys["witness"][1]})

    def test_private_keys_cannot_be_enrolled_as_tool_files(self):
        with self.assertRaises(BackupError):
            build_kit(self.source, self.revision, self.root / "secret-kit", self.keys["kit"][0],
                      {"witness": self.keys["witness"][1]}, tools={"age": self.keys["collector"][0]})
        self.assertFalse((self.root / "secret-kit").exists())

    def test_media_requires_matching_identity_external_pin_and_explicit_encryption_ack(self):
        with self.assertRaises(BackupError):
            media_policy(self.media, self.keys["offline"][1], identity=lambda root: "wrong-filesystem")
        with self.assertRaises(BackupError):
            media_policy(self.media, self.keys["kit"][1], identity=self.identity)
        with self.assertRaises(BackupError):
            enroll_media(self.root, "rotation-b", "filesystem-a", self.keys["offline"][0], identity=self.identity)

    def test_offline_copy_reads_all_bytes_preserves_prior_copies_and_is_idempotent(self):
        queue, event = self.fixture.generation()
        target = self.export(queue, event)
        report = verify_copy(target, self.keys["offline"][1], self.keys["collector"][1], self.keys["witness"][1], self.keys["kit"][1])
        self.assertTrue(report["verified"])
        first_report = (target / "copy.json").read_bytes()
        self.assertEqual(target, self.export(queue, event))
        self.assertEqual(first_report, (target / "copy.json").read_bytes())
        self.assertTrue((queue / "snapshot.tar.gz.age").is_file())
        payload = target / "snapshot/snapshot.tar.gz.age"
        payload.write_bytes(b"X" * payload.stat().st_size)
        with self.assertRaises(BackupError):
            verify_copy(target, self.keys["offline"][1], self.keys["collector"][1], self.keys["witness"][1], self.keys["kit"][1])

    def test_failed_media_capacity_or_copy_does_not_publish_complete_generation(self):
        queue, event = self.fixture.generation()
        with patch("reposafe.offline.shutil.disk_usage", return_value=SimpleNamespace(free=0)), self.assertRaises(BackupError):
            self.export(queue, event)
        with patch("reposafe.offline.copy_file", side_effect=OSError("fixture media error")), self.assertRaises(OSError):
            self.export(queue, event)
        self.assertFalse(any((self.media / "RepoSafe").glob("*/copy.json")))

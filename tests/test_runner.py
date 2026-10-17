import tempfile
import os
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from reposafe.common import BackupError
from reposafe.config import Config, Destination
from reposafe.delivery import Delivery
from reposafe.runner import execute, read_state, run_lock, collect_only
from reposafe.snapshot import Capture


class RunnerTests(unittest.TestCase):
    def test_isolated_collection_refuses_destination_credentials_before_source_access(self):
        github = Mock()
        with patch.dict(os.environ, {"RCLONE_CONFIG": "/fixture", "REPOSAFE_COLLECTOR_SIGNING_KEY_FILE": "/fixture"}), self.assertRaisesRegex(BackupError, "destination"):
            collect_only(self.config, github, self.root / "out", self.state)
        github.inventory.assert_not_called()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.config = Config(("neophilism",), (), destinations=(Destination("drive", "g:"),))

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, expected, complete=True, ids=(1, 2)):
        def fixture(config, github, output, **kwargs):
            self.assertEqual(expected, kwargs["expected_repository_ids"])
            return Capture(self.root / "encrypted", "fixture-run", complete, len(ids), 0, ids)
        return fixture

    def test_success_advances_only_after_all_required_providers_verify(self):
        execute(self.config, None, self.root / "out", self.state, capture_fn=self.capture([]),
                deliver_fn=lambda *args: [Delivery("drive", True, True)])
        first = read_state(self.state)
        self.assertIsNotNone(first["last_success"])
        execute(self.config, None, self.root / "out", self.state, capture_fn=self.capture([1, 2], ids=(1, 2, 3)),
                deliver_fn=lambda *args: [Delivery("drive", True, False)])
        second = read_state(self.state)
        self.assertEqual(first["last_success"], second["last_success"])
        self.assertEqual([1, 2, 3], second["observed_repository_ids"])
        self.assertFalse(second["last_attempt"]["delivered"])

    def test_partial_capture_cannot_be_promoted(self):
        _, _, success = execute(self.config, None, self.root / "out", self.state,
                               capture_fn=self.capture([], complete=False),
                               deliver_fn=lambda *args: [Delivery("drive", True, True)])
        self.assertFalse(success)
        self.assertIsNone(read_state(self.state)["last_success"])

    def test_observed_inventory_never_silently_shrinks(self):
        execute(self.config, None, self.root / "out", self.state, capture_fn=self.capture([]),
                deliver_fn=lambda *args: [Delivery("drive", True, True)])
        execute(self.config, None, self.root / "out", self.state, capture_fn=self.capture([1, 2], complete=False, ids=(1,)),
                deliver_fn=lambda *args: [Delivery("drive", True, True)])
        self.assertEqual([1, 2], read_state(self.state)["observed_repository_ids"])

    def test_concurrent_run_is_rejected(self):
        with run_lock(self.state):
            with self.assertRaisesRegex(BackupError, "active"):
                with run_lock(self.state):
                    self.fail("second lock must not enter")

    def test_corrupt_state_and_symlink_lock_fail_closed(self):
        self.state.mkdir(mode=0o700)
        (self.state / "state.json").write_text("invalid json")
        (self.state / "state.json").chmod(0o600)
        with self.assertRaises(BackupError):
            read_state(self.state)
        (self.state / "run.lock").symlink_to(self.root / "unrelated")
        with self.assertRaises(OSError):
            with run_lock(self.state):
                self.fail("symlink lock entered")

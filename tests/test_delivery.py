import json
import shutil
import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError, sha256, write_json
from reposafe.config import Destination
from reposafe.delivery import Rclone, deliver_all, delivery_succeeded, verify_snapshot


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        payload = self.source / "snapshot.tar.gz.age"
        payload.write_bytes(b"encrypted fixture")
        self.run_id = "20261017T010000Z-0123456789abcdef"
        write_json(self.source / "receipt.json", {
            "schema_version": 1, "run_id": self.run_id, "complete": True,
            "repositories": 2, "failed": 0, "files": [{"name": payload.name,
            "sha256": sha256(payload), "bytes": payload.stat().st_size}],
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_failure_of_first_required_provider_does_not_stop_second(self):
        seen = []
        class Transport:
            def deliver(inner, directory, destination, run_id):
                seen.append(destination.name)
                if destination.name == "drive":
                    raise BackupError("offline")
        results = deliver_all(self.source, (Destination("drive", "x:"), Destination("dropbox", "y:")), transport=Transport())
        self.assertEqual(["drive", "dropbox"], seen)
        self.assertFalse(delivery_succeeded(results))
        self.assertTrue(results[1].verified)

    def test_receipt_is_uploaded_only_after_ciphertext_verification(self):
        calls = []
        def runner(args):
            calls.append(args)
            if args[1] == "check":
                raise BackupError("mismatch")
        with self.assertRaises(BackupError):
            Rclone(runner=runner).deliver(self.source, Destination("drive", "x:"), self.run_id)
        self.assertEqual(2, len(calls))
        self.assertTrue(all("/receipt.json" not in call for call in calls))
        self.assertTrue(all(call[1] in ("copy", "check") for call in calls))

    def test_tampering_or_path_traversal_is_rejected_before_delivery(self):
        (self.source / "snapshot.tar.gz.age").write_bytes(b"tampered fixture!")
        with self.assertRaises(BackupError):
            verify_snapshot(self.source)
        receipt = json.loads((self.source / "receipt.json").read_text())
        receipt["files"][0]["name"] = "../../private.txt"
        (self.source / "receipt.json").write_text(json.dumps(receipt))
        with self.assertRaises(BackupError):
            verify_snapshot(self.source)

    def test_zero_destinations_are_not_a_success(self):
        self.assertFalse(delivery_succeeded([]))

    @unittest.skipUnless(shutil.which("rclone"), "rclone required")
    def test_real_rclone_copies_both_and_preserves_existing_snapshots(self):
        (self.source / "private.txt").write_text("must not upload")
        targets = tuple(Destination(name, str(self.root / name)) for name in ("drive", "dropbox"))
        results = deliver_all(self.source, targets)
        self.assertTrue(delivery_succeeded(results))
        for target in targets:
            path = Path(target.remote) / self.run_id
            self.assertEqual({"snapshot.tar.gz.age", "receipt.json"}, {p.name for p in path.iterdir()})
            self.assertEqual((self.source / "snapshot.tar.gz.age").read_bytes(), (path / "snapshot.tar.gz.age").read_bytes())
        self.assertTrue(delivery_succeeded(deliver_all(self.source, targets)))
        # Same-size corruption must fail immutability or downloaded-byte checking.
        corrupt = Path(targets[0].remote) / self.run_id / "snapshot.tar.gz.age"
        corrupt.write_bytes(b"x" * corrupt.stat().st_size)
        outcomes = deliver_all(self.source, targets)
        self.assertFalse(outcomes[0].verified)
        self.assertTrue(outcomes[1].verified)

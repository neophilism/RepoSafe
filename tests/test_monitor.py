import io
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reposafe.common import BackupError, sha256, write_json
from reposafe.monitor import MonitorPolicy, monitor, notify
from reposafe.signing import generate_keys, sign_file


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        generate_keys(self.root / "witness")
        generate_keys(self.root / "wrong")
        self.key = self.root / "witness/private.pem"
        self.public = self.root / "witness/public.pem"
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        self.now = datetime.now(timezone.utc)
        self.policy = MonitorPolicy(("aws", "b2"), maximum_offline_days=None)

    def event(self, sequence=1, previous=None, *, captured=None, mutate=None, key=None):
        captured = captured or self.now - timedelta(hours=1)
        directory = self.inbox / str(sequence)
        directory.mkdir()
        destinations = [{"destination": name, "required": True, "provider": provider,
            "catalog_sha256": "a" * 64, "independent_cloud_readback": True,
            "minimum_retain_until": (self.now + timedelta(days=90)).isoformat()} for name, provider in (("aws", "s3"), ("b2", "b2"))]
        event = {"schema_version": 1, "kind": "witness-event", "sequence": sequence,
            "previous_sha256": previous, "run_id": captured.strftime("%Y%m%dT%H%M%SZ") + "-0123456789abcdef",
            "captured_at": captured.isoformat(), "witnessed_at": (captured + timedelta(minutes=1)).isoformat(),
            "receipt_sha256": "a" * 64, "complete": True, "destinations": destinations,
            "independently_verified_immutable_copies": 2}
        if mutate:
            mutate(event)
        path = directory / "event.json"
        write_json(path, event)
        sign_file(path, key or self.key, directory / "event.sig.json", "witness-event")
        return path

    def check(self, **kwargs):
        return monitor(self.inbox, self.public, self.root / "state", self.policy, clock=lambda: self.now, **kwargs)

    def test_no_backup_is_unhealthy_and_ordinary_heartbeat_is_ignored(self):
        self.assertIn("no_verified_complete_backup", self.check()["issues"])
        (self.inbox / "success-heartbeat.json").write_text('{"success":true}')
        self.assertFalse(self.check()["healthy"])

    def test_valid_chain_advances_and_old_inbox_cannot_reset_freshness(self):
        first = self.event(captured=self.now - timedelta(hours=2))
        self.assertTrue(self.check()["healthy"])
        self.event(2, sha256(first), captured=self.now - timedelta(hours=1))
        self.assertEqual(2, self.check()["sequence"])
        report = monitor(self.inbox, self.public, self.root / "state", self.policy,
                         clock=lambda: self.now + timedelta(hours=31))
        self.assertEqual(2, report["sequence"])
        self.assertIn("backup_stale", report["issues"])

    def test_replaced_sequence_and_missing_chain_link_are_unhealthy(self):
        first = self.event()
        self.assertTrue(self.check()["healthy"])
        raw = json.loads(first.read_text())
        raw["receipt_sha256"] = "b" * 64
        first.write_text(json.dumps(raw))
        first.with_name("event.sig.json").unlink()
        sign_file(first, self.key, first.with_name("event.sig.json"), "witness-event")
        self.assertIn("witness_sequence_replaced", self.check()["issues"])
        self.event(3, "a" * 64, captured=self.now)
        self.assertIn("witness_chain_gap", self.check()["issues"])

    def test_wrong_signer_and_future_capture_fail_before_state_advancement(self):
        self.event(key=self.root / "wrong/private.pem")
        self.assertIn("witness_event_invalid", self.check()["issues"])
        self.assertEqual(0, self.check()["sequence"])
        # A correctly signed but future event is also unacceptable.
        import shutil
        shutil.rmtree(self.inbox / "1")
        self.event(captured=self.now + timedelta(hours=1))
        self.assertIn("witness_event_policy_failed", self.check()["issues"])

    def test_required_copy_and_retention_policy_cannot_be_lowered_by_witness(self):
        self.event()
        self.policy = replace(self.policy, required_destinations=("aws", "b2", "drive"))
        self.assertFalse(self.check()["healthy"])
        self.policy = replace(self.policy, required_destinations=("aws", "b2"), minimum_retention_hours=24 * 91)
        self.assertIn("retention_horizon_short", self.check()["issues"])

    def test_offline_proof_is_signed_fresh_and_monotonic(self):
        self.event()
        self.policy = replace(self.policy, maximum_offline_days=7)
        self.assertIn("offline_evidence_missing", self.check()["issues"])
        path = self.root / "copy.json"
        def report(verified):
            path.unlink(missing_ok=True)
            path.with_name("copy.sig.json").unlink(missing_ok=True)
            write_json(path, {"schema_version": 1, "kind": "offline-copy", "verified": True,
                             "verified_at": verified.isoformat(), "captured_at": (verified - timedelta(hours=1)).isoformat()})
            sign_file(path, self.key, path.with_name("copy.sig.json"), "offline-copy")
        report(self.now)
        self.assertTrue(self.check(offline_report=path, offline_key=self.public)["healthy"])
        inbox = self.root / "offline-inbox"
        generation = inbox / "generation"
        generation.mkdir(parents=True)
        import shutil
        for name in ("copy.json", "copy.sig.json"):
            shutil.copyfile(self.root / name, generation / name)
        self.assertTrue(self.check(offline_report=inbox, offline_key=self.public)["healthy"])
        report(self.now - timedelta(days=1))
        self.assertIn("offline_evidence_rollback", self.check(offline_report=path, offline_key=self.public)["issues"])

    def test_webhook_has_aggregate_payload_no_redirects_and_sanitized_failures(self):
        captured = []
        class Response(io.BytesIO):
            status = 202
        class Opener:
            def open(self, request, timeout):
                captured.append(request)
                return Response(b"ok")
        report = self.check()
        notify(report, "https://alerts.example/private-token", opener=Opener())
        self.assertEqual(report, json.loads(captured[0].data))
        self.assertNotIn("private-token", captured[0].data.decode())
        for url in ("http://alerts.example", "https://user:secret@alerts.example"):
            with self.assertRaises(BackupError):
                notify(report, url, opener=Opener())
        class Failure:
            def open(self, request, timeout):
                raise OSError("secret response")
        with self.assertRaises(BackupError) as caught:
            notify(report, "https://alerts.example/private-token", opener=Failure())
        self.assertNotIn("secret", str(caught.exception))

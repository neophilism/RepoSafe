import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reposafe.common import BackupError, sha256
from reposafe.retention import retention_report
from support_evidence import EvidenceFixture


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = EvidenceFixture(self.root)
        self.now = datetime.now(timezone.utc)
        self.fixture.generation(self.now - timedelta(days=300))
        _, self.latest = self.fixture.generation(self.now - timedelta(days=1))

    def report(self, **kwargs):
        return retention_report(self.fixture.config, self.root / "witness-state/events", self.fixture.keys["witness"][1],
            {"aws": self.fixture.keys["writer"][1]}, self.fixture.keys["collector"][1], latest_sequence=2,
            latest_sha256=sha256(self.latest), minimum_generations=1, minimum_age_days=90,
            clock=lambda: self.now, **kwargs)

    def test_only_old_unlocked_no_hold_versions_are_proposed_and_no_delete_is_called(self):
        calls = []
        def audit(destination, record):
            calls.append(record["version_id"])
            return {"mode": "COMPLIANCE", "retain_until": (self.now - timedelta(days=10)).isoformat(), "legal_hold": "OFF"}
        report = self.report(audit=audit, rates={"aws": "0.02"}, daily_bytes=1024 ** 3)
        self.assertTrue(report["read_only"])
        self.assertEqual(3, report["eligible_versions"])
        self.assertEqual(3, len(calls))
        self.assertEqual(3, sum(item["decision"] == "keep" for item in report["objects"]))
        self.assertEqual("1.80", report["costs"][0]["full_daily_forecast_storage_usd"])

    def test_unverified_live_state_legal_hold_and_active_lock_are_blocked(self):
        self.assertEqual(0, self.report(without_live_audit=True)["eligible_versions"])
        for hold, until in (("ON", self.now - timedelta(days=10)), ("OFF", self.now + timedelta(days=1))):
            report = self.report(audit=lambda *args: {"mode": "COMPLIANCE", "retain_until": until.isoformat(), "legal_hold": hold})
            self.assertEqual(0, report["eligible_versions"])
        def fail(*args):
            raise OSError("fixture read denied")
        self.assertEqual(0, self.report(audit=fail)["eligible_versions"])

    def test_wrong_independent_anchor_and_tampered_catalog_fail_closed(self):
        self.latest.write_bytes(self.latest.read_bytes() + b" ")
        with self.assertRaises(BackupError):
            self.report(without_live_audit=True)

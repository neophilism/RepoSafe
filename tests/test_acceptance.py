import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reposafe.acceptance import CHECKS, template, verify_acceptance
from reposafe.common import BackupError, sha256, write_json
from reposafe.signing import generate_keys, sign_file


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for role in ("owner", "witness"):
            generate_keys(self.root / role)
        self.document = self.root / "acceptance.json"

    def sign(self):
        self.document.with_name("acceptance.sig.json").unlink(missing_ok=True)
        sign_file(self.document, self.root / "owner/private.pem", self.root / "acceptance.sig.json", "production-acceptance")

    def verify(self):
        return verify_acceptance(self.document, self.root / "owner/public.pem", self.root / "witness/public.pem")

    def test_template_is_entirely_pending_and_cannot_become_acceptance_by_signing_alone(self):
        record = template(self.document)
        self.assertTrue(all(item["status"] == "pending" for item in record["checks"].values()))
        self.sign()
        with self.assertRaises(BackupError):
            self.verify()

    def test_signed_operator_attestation_binds_witness_monitor_and_each_evidence_hash(self):
        now = datetime.now(timezone.utc)
        captured = now - timedelta(hours=1)
        destinations = []
        for name, provider in (("aws", "s3"), ("b2", "b2"), ("drive", "rclone"), ("dropbox", "rclone")):
            destinations.append({"destination": name, "required": True, "provider": provider,
                "catalog_sha256": "a" * 64, "independent_cloud_readback": provider != "rclone",
                "minimum_retain_until": (now + timedelta(days=90)).isoformat() if provider != "rclone" else None})
        event = self.root / "event.json"
        write_json(event, {"schema_version": 1, "kind": "witness-event", "sequence": 1, "previous_sha256": None,
            "run_id": captured.strftime("%Y%m%dT%H%M%SZ") + "-0123456789abcdef", "captured_at": captured.isoformat(),
            "witnessed_at": (captured + timedelta(minutes=1)).isoformat(), "receipt_sha256": "a" * 64,
            "complete": True, "independently_verified_immutable_copies": 2, "destinations": destinations})
        sign_file(event, self.root / "witness/private.pem", self.root / "event.sig.json", "witness-event")
        report = self.root / "monitor.json"
        write_json(report, {"healthy": True, "sequence": 1, "checked_at": (now - timedelta(seconds=1)).isoformat()})
        notes = self.root / "operator-fixture.txt"
        notes.write_text("Synthetic attestation fixture, not real provider/media acceptance.\n")
        evidence = [{"path": path.name, "sha256": sha256(path)} for path in (event, report, notes)]
        record = {"schema_version": 1, "kind": "production-acceptance", "reviewed_commit": "a" * 40,
            "accepted_at": now.isoformat(), "witness_event": event.name, "monitor_report": report.name,
            "checks": {name: {"status": "accepted", "evidence": evidence} for name in CHECKS}}
        write_json(self.document, record)
        self.sign()
        self.assertTrue(self.verify()["owner_attestation_valid"])
        report.write_text('{"healthy":true,"sequence":100}')
        with self.assertRaises(BackupError):
            self.verify()

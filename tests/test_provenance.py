import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from reposafe.agents import deliver_agent, verify_catalog
from reposafe.common import BackupError, sha256, write_json
from reposafe.config import Config, Destination
from reposafe.delivery import Rclone
from reposafe.signing import generate_keys, read_regular, sign_file, verify_file
from reposafe.vault import ObjectVault
from reposafe.witness import verify_event, witness
from reposafe.queues import agent_sweep, witness_sweep
from test_vault import FakeVault


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keys = {}
        for role in ("collector", "writer", "witness", "wrong"):
            directory = self.root / role
            generate_keys(directory)
            self.keys[role] = (directory / "private.pem", directory / "public.pem")
        self.queue = self.root / "queue"
        self.queue.mkdir()
        self.now = datetime.now(timezone.utc)
        self.run_id = self.now.strftime("%Y%m%dT%H%M%SZ") + "-0123456789abcdef"
        payload = self.queue / "snapshot.tar.gz.age"
        payload.write_bytes(b"encrypted test fixture")
        write_json(self.queue / "receipt.json", {"schema_version": 2, "run_id": self.run_id,
            "captured_at": self.now.isoformat(), "complete": True, "repositories": 1,
            "files": [{"name": payload.name, "sha256": sha256(payload), "bytes": payload.stat().st_size}]})
        self.sign_receipt()
        self.destination = Destination("vault", kind="s3", bucket="example-vault",
                                       expected_account="123456789012", retention_days=90)
        self.config = Config(("neophilism",), (), destinations=(self.destination,))
        self.client = FakeVault(self.now + timedelta(seconds=1))
        self.clean_environment = patch.dict(os.environ, {}, clear=True)
        # Preserve installed tool discovery for the real rclone fixture.
        path = os.environ.get("PATH", "")
        self.clean_environment.start()
        self.addCleanup(self.clean_environment.stop)
        os.environ["PATH"] = path

    def sign_receipt(self):
        (self.queue / "receipt.sig.json").unlink(missing_ok=True)
        sign_file(self.queue / "receipt.json", self.keys["collector"][0], self.queue / "receipt.sig.json", "collector-receipt")

    def vault(self, destination=None, *, read_only=False):
        return ObjectVault(destination or self.destination, client=self.client,
            identity_account=self.destination.expected_account, clock=lambda: self.now + timedelta(seconds=2), read_only=read_only)

    def deliver(self, **kwargs):
        return deliver_agent(self.config, self.queue, "vault", self.root / "agent-state",
                             self.keys["collector"][1], self.keys["writer"][0], transport=self.vault(), **kwargs)[0]

    def observe(self, catalog, **kwargs):
        return witness(self.config, [catalog], {"vault": self.keys["writer"][1]}, self.keys["collector"][1],
            self.root / "witness-state", self.keys["witness"][0], vault_factory=self.vault,
            clock=lambda: self.now + timedelta(seconds=3), **kwargs)

    def test_signatures_require_pinned_keys_correct_purpose_and_unchanged_bytes(self):
        path, signature = self.queue / "receipt.json", self.queue / "receipt.sig.json"
        verify_file(path, signature, self.keys["collector"][1], "collector-receipt")
        for key, purpose in ((self.keys["wrong"][1], "collector-receipt"), (self.keys["collector"][1], "writer-catalog")):
            with self.subTest(purpose=purpose), self.assertRaises(BackupError):
                verify_file(path, signature, key, purpose)
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(BackupError):
            verify_file(path, signature, self.keys["collector"][1], "collector-receipt")

    def test_explicit_key_rotation_ring_and_unsafe_key_files(self):
        ring = self.root / "pins"
        ring.mkdir()
        for role in ("collector", "wrong"):
            shutil.copyfile(self.keys[role][1], ring / (role + ".pem"))
        verify_file(self.queue / "receipt.json", self.queue / "receipt.sig.json", ring, "collector-receipt")
        os.mkfifo(self.root / "fifo")
        with self.assertRaises(BackupError):
            read_regular(self.root / "fifo", 4096)
        self.keys["collector"][0].chmod(0o644)
        with self.assertRaises(BackupError):
            self.sign_receipt()

    def test_delivery_is_idempotent_signed_and_witness_checks_stored_versions(self):
        catalog = self.deliver()
        self.assertEqual(catalog, self.deliver())
        verified, receipt = verify_catalog(catalog, self.keys["writer"][1], self.keys["collector"][1])
        self.assertTrue(verified["verified"])
        self.assertEqual(self.run_id, receipt["run_id"])
        self.assertEqual(3, len(self.client.calls))
        self.assertTrue(self.client.calls[-1].endswith("receipt.json"))
        event = self.observe(catalog)
        value = verify_event(event, self.keys["witness"][1])
        self.assertEqual(1, value["independently_verified_immutable_copies"])
        self.assertIsNotNone(value["destinations"][0]["minimum_retain_until"])
        with self.assertRaisesRegex(BackupError, "duplicate|rolled-back"):
            self.observe(catalog)
        with self.assertRaises(BackupError):
            verify_event(event, self.keys["witness"][1], minimum_sequence=2)

    def test_witness_does_not_trust_writer_retention_claims(self):
        catalog = self.deliver()
        self.client.corrupt = True
        with self.assertRaises(BackupError):
            self.observe(catalog)
        self.assertFalse((self.root / "witness-state/events").exists())

    def test_wrong_collector_pin_or_source_credential_prevents_any_delivery(self):
        with self.assertRaises(BackupError):
            deliver_agent(self.config, self.queue, "vault", self.root / "bad-pin",
                self.keys["wrong"][1], self.keys["writer"][0], transport=self.vault())
        self.assertEqual([], self.client.calls)
        with patch.dict(os.environ, {"GITHUB_BACKUP_TOKEN": "fixture-secret"}), self.assertRaises(BackupError):
            self.deliver()
        self.assertEqual([], self.client.calls)

    def test_queue_sweeps_retry_without_deleting_and_skip_verified_history(self):
        inbox = self.root / "inbox"
        inbox.mkdir()
        shutil.copytree(self.queue, inbox / self.run_id)
        counts = agent_sweep(self.config, inbox, "vault", self.root / "agent-state",
            self.keys["collector"][1], self.keys["writer"][0], transport=self.vault())
        self.assertEqual(1, counts["delivered"])
        counts = agent_sweep(self.config, inbox, "vault", self.root / "agent-state",
            self.keys["collector"][1], self.keys["writer"][0], transport=self.vault())
        self.assertEqual(1, counts["previously_delivered"])
        catalog_inbox = self.root / "catalog-inbox"
        shutil.copytree(self.root / "agent-state/catalogs", catalog_inbox / "vault")
        counts = witness_sweep(self.config, catalog_inbox, {"vault": self.keys["writer"][1]},
            self.keys["collector"][1], self.root / "witness-state", self.keys["witness"][0], vault_factory=self.vault)
        self.assertEqual(1, counts["witnessed"])
        self.assertTrue((inbox / self.run_id / "receipt.json").exists())

    def test_missing_destination_partial_and_stale_capture_cannot_be_witnessed(self):
        catalog = self.deliver()
        required = replace(self.config, destinations=(self.destination, Destination("other", "other:")))
        with self.assertRaises(BackupError):
            witness(required, [catalog], {"vault": self.keys["writer"][1]}, self.keys["collector"][1],
                self.root / "missing", self.keys["witness"][0], vault_factory=self.vault)
        receipt = json.loads((self.queue / "receipt.json").read_text())
        receipt["complete"] = False
        (self.queue / "receipt.json").write_text(json.dumps(receipt))
        self.sign_receipt()
        # Reusing a run ID with a different signed payload is rejected before another upload.
        with self.assertRaises(BackupError):
            self.deliver()
        with self.assertRaises(BackupError):
            witness(self.config, [catalog], {"vault": self.keys["writer"][1]}, self.keys["collector"][1],
                self.root / "stale", self.keys["witness"][0], vault_factory=self.vault,
                clock=lambda: self.now + timedelta(hours=31))

    @unittest.skipUnless(shutil.which("rclone"), "rclone required")
    def test_real_rclone_agent_transfers_signature_and_witness_labels_mutability(self):
        destination = Destination("drive", str(self.root / "drive"))
        config = replace(self.config, destinations=(destination,))
        catalog, _ = deliver_agent(config, self.queue, "drive", self.root / "drive-state",
            self.keys["collector"][1], self.keys["writer"][0], transport=Rclone())
        with self.assertRaises(BackupError):
            witness(config, [catalog], {"drive": self.keys["writer"][1]}, self.keys["collector"][1],
                self.root / "strict", self.keys["witness"][0])
        event = witness(config, [catalog], {"drive": self.keys["writer"][1]}, self.keys["collector"][1],
            self.root / "convenience-only", self.keys["witness"][0], minimum_immutable=0)
        self.assertFalse(verify_event(event, self.keys["witness"][1])["destinations"][0]["independent_cloud_readback"])
        self.assertTrue((self.root / "drive" / self.run_id / "receipt.sig.json").is_file())

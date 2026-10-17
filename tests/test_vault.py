import io
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reposafe.common import BackupError, sha256, write_json
from reposafe.config import Destination
from reposafe.vault import ObjectVault, check_b2_capabilities


class NotFound(Exception):
    response = {"ResponseMetadata": {"HTTPStatusCode": 404}}


class FakeVault:
    def __init__(self, now):
        self.now, self.objects, self.calls = now, {}, []
        self.mode, self.days, self.enabled = "COMPLIANCE", 90, "Enabled"
        self.corrupt, self.fail_key = False, None

    def get_bucket_versioning(self, **kwargs):
        return {"Status": self.enabled}

    def get_public_access_block(self, **kwargs):
        return {"PublicAccessBlockConfiguration": {key: True for key in
            ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}

    def get_object_lock_configuration(self, **kwargs):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", "Rule": {
            "DefaultRetention": {"Mode": self.mode, "Days": self.days}}}}

    def head_object(self, **kwargs):
        key = kwargs["Key"]
        if key not in self.objects:
            raise NotFound()
        return {"VersionId": self.objects[key][0], "ContentLength": len(self.objects[key][1])}

    def put_object(self, **kwargs):
        key = kwargs["Key"]
        self.calls.append(key)
        if self.fail_key and key.endswith(self.fail_key):
            raise OSError("fixture interruption")
        data = kwargs["Body"].read()
        version = "version-" + str(len(self.objects) + 1)
        self.objects[key] = (version, data)
        return {"VersionId": version}

    def get_object(self, **kwargs):
        version, data = self.objects[kwargs["Key"]]
        assert version == kwargs["VersionId"]
        if self.corrupt:
            data = b"X" * len(data)
        return {"VersionId": version, "ContentLength": len(data), "Body": io.BytesIO(data)}

    def get_object_retention(self, **kwargs):
        return {"Retention": {"Mode": self.mode, "RetainUntilDate": self.now + timedelta(days=self.days)}}

    def get_object_legal_hold(self, **kwargs):
        return {"LegalHold": {"Status": "OFF"}}


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
        self.destination = Destination("vault", kind="s3", bucket="example-vault", expected_account="123456789012", retention_days=90)
        self.client = FakeVault(self.now)
        self.vault = ObjectVault(self.destination, client=self.client, identity_account=self.destination.expected_account, clock=lambda: self.now)
        payload = self.root / "snapshot.tar.gz.age"
        payload.write_bytes(b"encrypted fixture")
        self.run_id = "20261017T120000Z-0123456789abcdef"
        write_json(self.root / "receipt.json", {"schema_version": 2, "run_id": self.run_id,
            "complete": True, "repositories": 1, "files": [{"name": payload.name,
            "sha256": sha256(payload), "bytes": payload.stat().st_size}]})

    def tearDown(self):
        self.temp.cleanup()

    def test_protected_versions_and_receipt_last_are_verified_and_idempotent(self):
        result = self.vault.deliver(self.root, self.destination, self.run_id)
        self.assertEqual(2, len(result["objects"]))
        self.assertTrue(self.client.calls[-1].endswith("receipt.json"))
        self.assertTrue(all(r["version_id"] and r["retention_mode"] == "COMPLIANCE" for r in result["objects"]))
        self.vault.deliver(self.root, self.destination, self.run_id)
        self.assertEqual(2, len(self.client.calls))
        receipt = json.loads((self.root / "receipt.json").read_text())
        output = self.root / "recovered"
        self.vault.retrieve(output, receipt, result)
        self.assertEqual((self.root / "snapshot.tar.gz.age").read_bytes(), (output / "snapshot.tar.gz.age").read_bytes())

    def test_missing_versioning_governance_short_retention_and_wrong_account_rejected(self):
        for setting, value in (("enabled", "Suspended"), ("mode", "GOVERNANCE"), ("days", 1)):
            original = getattr(self.client, setting)
            setattr(self.client, setting, value)
            with self.subTest(setting=setting), self.assertRaises(BackupError):
                self.vault.deliver(self.root, self.destination, self.run_id)
            setattr(self.client, setting, original)
        with self.assertRaises(BackupError):
            ObjectVault(self.destination, client=self.client, identity_account="wrong")

    def test_corrupt_readback_never_publishes_receipt(self):
        self.client.corrupt = True
        with self.assertRaises(BackupError):
            self.vault.deliver(self.root, self.destination, self.run_id)
        self.assertFalse(any(k.endswith("receipt.json") for k in self.client.objects))

    def test_interrupted_transfer_preserves_payload_and_resumes_same_versions(self):
        self.client.fail_key = "receipt.json"
        with self.assertRaises(BackupError):
            self.vault.deliver(self.root, self.destination, self.run_id)
        before = self.client.objects.copy()
        self.client.fail_key = None
        self.vault.deliver(self.root, self.destination, self.run_id)
        for key, value in before.items():
            self.assertEqual(value, self.client.objects[key])

    def test_b2_destructive_or_unrestricted_keys_are_rejected(self):
        destination = replace(self.destination, kind="b2", expected_account="account", endpoint="https://s3.us-west-001.backblazeb2.com")
        allowed = {"buckets": [{"name": destination.bucket}], "namePrefix": "reposafe/",
                   "capabilities": ["listBuckets", "listFiles", "readFiles", "writeFiles", "readBucketRetentions", "readFileRetentions"]}
        result = {"accountId": "account", "apiInfo": {"storageApi": {"allowed": allowed, "s3ApiUrl": destination.endpoint}}}
        check_b2_capabilities(destination, result)
        allowed["capabilities"].append("deleteFiles")
        with self.assertRaises(BackupError):
            check_b2_capabilities(destination, result)
        allowed["capabilities"].remove("deleteFiles")
        allowed["namePrefix"] = ""
        with self.assertRaises(BackupError):
            check_b2_capabilities(destination, result)

    def test_read_only_maintenance_audits_exact_version_and_legal_hold_without_extending_retention(self):
        evidence = self.vault.deliver(self.root, self.destination, self.run_id)
        record = evidence["objects"][0]
        value = self.vault.audit_version(record)
        self.assertEqual("OFF", value["legal_hold"])
        self.assertEqual("COMPLIANCE", value["mode"])
        with self.assertRaises(BackupError):
            self.vault.audit_version({**record, "bytes": record["bytes"] + 1})

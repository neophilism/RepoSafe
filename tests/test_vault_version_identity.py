import json
import io
import unittest

from reposafe.common import BackupError
import test_vault


class ExactVersionIdentityTests(unittest.TestCase):
    setUp = test_vault.VaultTests.setUp
    tearDown = test_vault.VaultTests.tearDown

    def alter_response(self, replacement):
        original = self.client.get_object
        bodies = []
        def response(**kwargs):
            result = original(**kwargs)
            bodies.append(result["Body"])
            if replacement is None:
                result.pop("VersionId")
            else:
                result["VersionId"] = replacement
            return result
        self.client.get_object = response
        return bodies

    def test_upload_readback_requires_explicit_exact_response_version(self):
        bodies = self.alter_response(None)
        with self.assertRaises(BackupError):
            self.vault.deliver(self.root, self.destination, self.run_id)
        self.assertTrue(bodies)
        self.assertTrue(all(body.closed for body in bodies))
        self.assertFalse(any(key.endswith("receipt.json") for key in self.client.objects))

    def test_upload_wrong_response_version_cannot_publish_receipt(self):
        bodies = self.alter_response("different-version")
        with self.assertRaises(BackupError):
            self.vault.deliver(self.root, self.destination, self.run_id)
        self.assertTrue(all(body.closed for body in bodies))
        self.assertFalse(any(key.endswith("receipt.json") for key in self.client.objects))

    def test_recovery_requires_response_version_and_removes_only_new_partial_output(self):
        evidence = self.vault.deliver(self.root, self.destination, self.run_id)
        receipt = json.loads((self.root / "receipt.json").read_text())
        stored = dict(self.client.objects)
        bodies = self.alter_response(None)
        output = self.root / "recovery"
        with self.assertRaises(BackupError):
            self.vault.retrieve(output, receipt, evidence)
        self.assertFalse(output.exists())
        self.assertEqual(stored, self.client.objects)
        self.assertTrue(bodies)
        self.assertTrue(all(body.closed for body in bodies))

    def test_cataloged_versions_recover_when_latest_pointers_are_unavailable(self):
        evidence = self.vault.deliver(self.root, self.destination, self.run_id)
        receipt = json.loads((self.root / "receipt.json").read_text())
        versions = dict(self.client.objects)
        writes = list(self.client.calls)
        self.client.objects.clear()  # Fixture-only simulation of hidden latest pointers.
        reads = []
        def exact_read(**kwargs):
            version, data = versions[kwargs["Key"]]
            self.assertEqual(version, kwargs["VersionId"])
            reads.append((kwargs["Key"], version))
            return {"VersionId": version, "ContentLength": len(data), "Body": io.BytesIO(data)}
        def forbidden_head(**kwargs):
            self.fail("recovery must not substitute the latest object")
        self.client.get_object = exact_read
        self.client.head_object = forbidden_head
        output = self.root / "recovery"
        self.vault.retrieve(output, receipt, evidence)
        self.assertEqual((self.root / "snapshot.tar.gz.age").read_bytes(),
                         (output / "snapshot.tar.gz.age").read_bytes())
        self.assertEqual(len(evidence["objects"]), len(reads))
        self.assertEqual(writes, self.client.calls)

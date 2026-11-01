import json
import unittest

from reposafe.auth import InstallationAuth
from reposafe.github import GitHub


class CoverageEvidenceTests(unittest.TestCase):
    def test_app_evidence_records_actual_selection_without_credentials_or_false_admin_comparison(self):
        auth = InstallationAuth("42", "/private/never-output.pem", ("metadata", "contents"))
        auth.installations = {"fixture-owner": {"id": 7, "repository_selection": "selected",
                                               "access_tokens_url": "sensitive-unneeded-field"}}
        auth.cached = {7: ("synthetic-secret-token", 1800003600)}
        evidence = GitHub("installation-auth", auth=auth).coverage_evidence()
        self.assertEqual([{"owner": "fixture-owner", "installation_id": 7, "repository_selection": "selected"}], evidence["installations"])
        self.assertEqual({"metadata": "read", "contents": "read"}, evidence["requested_permissions"])
        self.assertEqual("not_performed", evidence["owner_inventory_comparison"])
        self.assertEqual("not_independently_verified", evidence["organization_sso_validation"])
        for secret in ("synthetic-secret-token", "never-output.pem", "sensitive-unneeded-field"):
            self.assertNotIn(secret, json.dumps(evidence))

    def test_token_visibility_cannot_claim_all_repositories_or_app_permissions(self):
        evidence = GitHub("synthetic-secret-token").coverage_evidence()
        self.assertEqual("token", evidence["authentication"])
        self.assertEqual("unknown", evidence["repository_selection"])
        self.assertNotIn("requested_permissions", evidence)
        self.assertNotIn("synthetic-secret-token", json.dumps(evidence))

    def test_evidence_is_detached_from_live_permission_dictionary(self):
        auth = InstallationAuth("42", "/unused", ("metadata", "contents"))
        evidence = auth.coverage_evidence()
        evidence["requested_permissions"]["contents"] = "write"
        self.assertEqual("read", auth.permissions["contents"])

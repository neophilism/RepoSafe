import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from reposafe.auth import InstallationAuth
from reposafe.common import BackupError
from reposafe.config import Config


class TokenBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000
        self.auth = InstallationAuth("42", "/unused", ("contents", "metadata"), clock=lambda: self.now)
        self.client = Mock()

    def result(self, **patches):
        return {"token": "synthetic-fixture-token",
                "expires_at": datetime.fromtimestamp(self.now + 3600, timezone.utc).isoformat(),
                "permissions": {"contents": "read", "metadata": "read"}, **patches}

    def test_token_response_requires_all_requested_grants_and_no_unrequested_privileges(self):
        for permissions in ({}, {"contents": "read"}, {"contents": "none", "metadata": "read"},
                            {"contents": "read", "metadata": "read", "issues": "read"},
                            {"contents": "write", "metadata": "read"}):
            with self.subTest(permissions=permissions):
                self.auth.cached.clear()
                self.client.request.return_value = self.result(permissions=permissions)
                with patch.object(self.auth, "app_client", return_value=self.client), self.assertRaises(BackupError):
                    self.auth.installation_token({"id": 1})
                self.assertEqual({}, self.auth.cached)

    def test_naive_expired_and_excessively_long_expiries_are_not_cached(self):
        for expiry in (datetime.fromtimestamp(self.now + 3600, timezone.utc).replace(tzinfo=None).isoformat(),
                       datetime.fromtimestamp(self.now + 60, timezone.utc).isoformat(),
                       datetime.fromtimestamp(self.now + 86400, timezone.utc).isoformat(), None, "invalid"):
            with self.subTest(expiry=expiry):
                self.auth.cached.clear()
                self.client.request.return_value = self.result(expires_at=expiry)
                with patch.object(self.auth, "app_client", return_value=self.client), self.assertRaises(BackupError):
                    self.auth.installation_token({"id": 1})
                self.assertEqual({}, self.auth.cached)

    def test_invalid_tokens_fail_without_leaking_response_values(self):
        for token in ({"secret": "do-not-log"}, 42, "", "secret\nvalue", "two words", "\u00e9"):
            with self.subTest(token_type=type(token).__name__):
                self.auth.cached.clear()
                self.client.request.return_value = self.result(token=token)
                with patch.object(self.auth, "app_client", return_value=self.client), self.assertRaises(BackupError) as caught:
                    self.auth.installation_token({"id": 1})
                self.assertEqual("GitHub App returned invalid or excessive token privileges", str(caught.exception))
                self.assertEqual({}, self.auth.cached)

    def test_invalid_installation_identifiers_fail_before_token_request(self):
        for installation in ({}, {"id": True}, {"id": "1/other"}, {"id": 0}, {"id": -1}):
            with patch.object(self.auth, "app_client", return_value=self.client), self.assertRaises(BackupError):
                self.auth.installation_token(installation)
        self.client.request.assert_not_called()

    def test_selected_opt_in_does_not_accept_unknown_selection_metadata(self):
        self.client.pages.return_value = [{"id": 1, "account": {"login": "fixture-owner"},
            "repository_selection": "unknown", "permissions": {"contents": "read", "metadata": "read"}}]
        with patch.object(self.auth, "app_client", return_value=self.client), self.assertRaises(BackupError):
            list(self.auth.repositories(Config(("fixture-owner",), (), allow_selected_repositories=True)))
        self.client.request.assert_not_called()

    def test_revoked_grant_failure_cannot_reuse_near_expiry_token(self):
        self.client.request.return_value = self.result()
        with patch.object(self.auth, "app_client", return_value=self.client):
            self.assertEqual("synthetic-fixture-token", self.auth.installation_token({"id": 1}))
            self.now += 3500
            self.client.request.side_effect = BackupError("GitHub API failed (HTTP 403); no complete inventory/export")
            with self.assertRaises(BackupError):
                self.auth.installation_token({"id": 1})
        self.assertEqual(2, self.client.request.call_count)
        self.assertEqual({}, self.auth.cached)

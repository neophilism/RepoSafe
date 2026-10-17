import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from reposafe.auth import InstallationAuth, app_jwt
from reposafe.common import BackupError, sha256, write_json
from reposafe.config import Config
from reposafe.inventory import registry_ids


class AuthTests(unittest.TestCase):
    def test_jwt_is_signed_and_has_short_expiry(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        token = app_jwt("42", pem, now=1000)
        header, payload, signature = token.split(".")
        decode = lambda part: base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        claims = json.loads(decode(payload))
        self.assertEqual({"iat": 940, "exp": 1540, "iss": "42"}, claims)
        key.public_key().verify(decode(signature), (header + "." + payload).encode(), padding.PKCS1v15(), hashes.SHA256())

    def test_installation_tokens_refresh_and_never_request_write(self):
        now = [1000]
        client = Mock()
        def mint(*args, **kwargs):
            self.assertTrue(all(v == "read" for v in kwargs["data"]["permissions"].values()))
            return {"token": "fixture", "expires_at": datetime.fromtimestamp(now[0] + 3600, timezone.utc).isoformat(),
                    "permissions": {"contents": "read", "metadata": "read"}}
        client.request.side_effect = mint
        auth = InstallationAuth("42", "/unused", ("contents", "metadata"), clock=lambda: now[0])
        with patch.object(auth, "app_client", return_value=client):
            auth.installation_token({"id": 1})
            auth.installation_token({"id": 1})
            self.assertEqual(1, client.request.call_count)
            now[0] = 4500
            auth.installation_token({"id": 1})
            self.assertEqual(2, client.request.call_count)

    def test_selected_installations_and_missing_owner_fail_closed(self):
        auth = InstallationAuth("42", "/unused", ("contents", "metadata"))
        client = Mock()
        client.pages.return_value = [{"id": 1, "account": {"login": "neophilism"}, "repository_selection": "selected"}]
        with patch.object(auth, "app_client", return_value=client), self.assertRaises(BackupError):
            list(auth.repositories(Config(("neophilism",), ())))
        client.pages.return_value = []
        with patch.object(auth, "app_client", return_value=client), self.assertRaises(BackupError):
            list(auth.repositories(Config(("neophilism",), ())))

    def test_server_returning_write_permissions_is_rejected(self):
        auth = InstallationAuth("42", "/unused", ("contents", "metadata"))
        client = Mock()
        client.request.return_value = {"token": "fixture", "expires_at": "2099-01-01T00:00:00Z",
                                       "permissions": {"contents": "write"}}
        with patch.object(auth, "app_client", return_value=client), self.assertRaises(BackupError):
            auth.installation_token({"id": 1})

    def test_pinned_registry_and_explicit_retirement(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "registry.json"
            write_json(path, {"schema_version": 1, "repository_ids": [1, 2],
                              "retired": [{"id": 2, "reason": "intentional transfer", "retired_at": "2026-10-17"}]})
            config = Config(("neophilism",), (), registry=path, registry_sha256=sha256(path))
            self.assertEqual(({1, 2}, {2}), registry_ids(config))
            path.write_text("tampered")
            with self.assertRaises(BackupError):
                registry_ids(config)

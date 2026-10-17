"""Source-only GitHub App credentials, short-lived read-only installation tokens."""

import base64
import json
import os
import time
from datetime import datetime
from pathlib import Path

from .common import BackupError
from .github import GitHub


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def app_jwt(app_id, private_key, *, now=None):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        key = serialization.load_pem_private_key(private_key, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError
        now = int(time.time() if now is None else now)
        header = encoded(b'{"alg":"RS256","typ":"JWT"}')
        payload = encoded(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
        body = header + b"." + payload
        return (body + b"." + encoded(key.sign(body, padding.PKCS1v15(), hashes.SHA256()))).decode()
    except (ImportError, ValueError, TypeError):
        raise BackupError("GitHub App requires cryptography and a valid private RSA key") from None


class InstallationAuth:
    def __init__(self, app_id, key_path, permissions, *, clock=time.time, client_factory=GitHub):
        self.app_id, self.key_path = app_id, Path(key_path)
        self.permissions = {p: "read" for p in permissions}
        allowed = {"metadata", "contents", "issues", "pull_requests", "discussions", "actions", "administration"}
        if set(permissions) - allowed or not {"metadata", "contents"} <= set(permissions):
            raise BackupError("invalid read-only GitHub App permissions")
        self.clock, self.factory = clock, client_factory
        self.installations, self.cached = {}, {}

    def app_client(self):
        try:
            if self.key_path.is_symlink() or self.key_path.stat().st_mode & 0o077:
                raise ValueError
            return self.factory(app_jwt(self.app_id, self.key_path.read_bytes(), now=self.clock()))
        except (OSError, ValueError):
            raise BackupError("GitHub App private key must be a private regular file") from None

    def installation_token(self, installation):
        identifier = installation["id"]
        cached = self.cached.get(identifier)
        if cached and cached[1] > self.clock() + 120:
            return cached[0]
        result = self.app_client().request(f"/app/installations/{identifier}/access_tokens", method="POST",
                                          data={"permissions": self.permissions})
        try:
            token = result["token"]
            expiry = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00")).timestamp()
            if not token or expiry <= self.clock() + 120 or any(v != "read" for v in result["permissions"].values()):
                raise ValueError
        except (KeyError, ValueError, TypeError, AttributeError):
            raise BackupError("GitHub App returned invalid or excessive token privileges") from None
        self.cached[identifier] = (token, expiry)
        return token

    def repositories(self, config):
        owners = {o.lower() for o in config.owners}
        found = set()
        for installation in self.app_client().pages("/app/installations"):
            try:
                owner = installation["account"]["login"].lower()
                if owner not in owners:
                    continue
                if type(installation["id"]) is not int or installation["id"] < 1 or installation.get("suspended_at"):
                    raise ValueError
                if installation.get("repository_selection") != "all" and not config.allow_selected_repositories:
                    raise BackupError("selected-repository installation cannot establish owner-wide coverage")
                self.installations[owner] = installation
                found.add(owner)
                client = self.factory(self.installation_token(installation))
                yield from client.pages("/installation/repositories", key="repositories")
            except (KeyError, TypeError, AttributeError, ValueError):
                raise BackupError("invalid or suspended GitHub App installation") from None
        if found != owners:
            raise BackupError("GitHub App installation missing for a configured owner")

    def token_for(self, repo):
        try:
            return self.installation_token(self.installations[repo["owner"]["login"].lower()])
        except (KeyError, AttributeError):
            raise BackupError("repository has no discovered GitHub App installation") from None


def client_from_environment(config):
    app_id = os.environ.get("GITHUB_APP_ID")
    if not app_id:
        return GitHub(os.environ.get("GITHUB_BACKUP_TOKEN", ""))
    permissions = {"metadata", "contents"}
    for group in config.metadata:
        permissions.update({"collaboration": {"issues", "pull_requests"}, "releases": {"contents"},
                            "discussions": {"discussions"}, "actions": {"actions"},
                            "settings": {"administration"}}[group])
    key = os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE")
    if not key:
        raise BackupError("GITHUB_APP_PRIVATE_KEY_FILE is required for App authentication")
    return GitHub("installation-auth", auth=InstallationAuth(app_id, key, permissions))

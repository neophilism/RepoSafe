"""Signed synthetic cloud evidence; never evidence of a real provider deployment."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from reposafe.agents import deliver_agent
from reposafe.common import sha256, write_json
from reposafe.config import Config, Destination
from reposafe.signing import generate_keys, sign_file
from reposafe.vault import ObjectVault
from reposafe.witness import witness
from test_vault import FakeVault


class EvidenceFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.keys = {}
        for role in ("collector", "writer", "witness", "offline", "kit"):
            directory = self.root / ("key-" + role)
            generate_keys(directory)
            self.keys[role] = (directory / "private.pem", directory / "public.pem")
        self.destination = Destination("aws", kind="s3", bucket="fixture-vault",
                                       expected_account="123456789012", retention_days=90)
        self.config = Config(("neophilism",), (), destinations=(self.destination,))

    def generation(self, captured=None):
        captured = captured or datetime.now(timezone.utc) - timedelta(minutes=1)
        run_id = captured.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(8)
        queue = self.root / run_id
        queue.mkdir()
        payload = queue / "snapshot.tar.gz.age"
        payload.write_bytes(b"synthetic ciphertext fixture; not a real encrypted archive")
        write_json(queue / "receipt.json", {"schema_version": 2, "run_id": run_id,
            "captured_at": captured.isoformat(), "complete": True, "repositories": 1,
            "files": [{"name": payload.name, "bytes": payload.stat().st_size, "sha256": sha256(payload)}]})
        sign_file(queue / "receipt.json", self.keys["collector"][0], queue / "receipt.sig.json", "collector-receipt")
        client = FakeVault(captured + timedelta(seconds=1))
        def vault(destination=None, *, read_only=False):
            return ObjectVault(destination or self.destination, client=client,
                identity_account=self.destination.expected_account, clock=lambda: captured + timedelta(seconds=2), read_only=read_only)
        with patch.dict(os.environ, {"GITHUB_BACKUP_TOKEN": "", "GITHUB_APP_PRIVATE_KEY_FILE": ""}):
            catalog, _ = deliver_agent(self.config, queue, "aws", self.root / "writer-state",
                self.keys["collector"][1], self.keys["writer"][0], transport=vault(), clock=lambda: captured + timedelta(seconds=2))
        event = witness(self.config, [catalog], {"aws": self.keys["writer"][1]}, self.keys["collector"][1],
            self.root / "witness-state", self.keys["witness"][0], vault_factory=vault,
            clock=lambda: captured + timedelta(seconds=3))
        return queue, event

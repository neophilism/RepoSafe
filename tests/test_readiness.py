import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from reposafe.common import BackupError
from reposafe.config import Config, Destination
from reposafe.readiness import doctor
from reposafe.relay import pull_queue
from reposafe.signing import generate_keys


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        generate_keys(self.root / "key")
        self.private, self.public = self.root / "key/private.pem", self.root / "key/public.pem"
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)

    def test_monitor_preflight_never_claims_production_activation(self):
        with patch.dict(os.environ, {}, clear=True):
            missing = doctor(None, "monitor")
            ready = doctor(None, "monitor", witness_key=self.public, state_dir=self.state)
        self.assertFalse(missing["local_ready"])
        self.assertTrue(ready["local_ready"])
        self.assertFalse(ready["production_accepted"])
        self.assertIn("next_scheduled_run", ready["acceptance_pending"])

    def test_writer_detects_cross_role_credentials_and_only_inspects_cloud_with_live_flag(self):
        destination = Destination("aws", kind="s3", bucket="fixture", credential_prefix="REPOSAFE_AWS", expected_account="123456789012")
        config = Config(("neophilism",), (), destinations=(destination,))
        env = {"REPOSAFE_AWS_ACCESS_KEY_ID": "fixture", "REPOSAFE_AWS_SECRET_ACCESS_KEY": "fixture", "GITHUB_BACKUP_TOKEN": "secret-fixture"}
        with patch.dict(os.environ, env, clear=True), patch("reposafe.vault.ObjectVault") as vault:
            report = doctor(config, "writer", destination="aws", collector_key=self.public,
                            signing_key=self.private, state_dir=self.state)
            self.assertIn("source_credentials_in_noncollector_role", report["issues"])
            self.assertNotIn("secret-fixture", json.dumps(report))
            vault.assert_not_called()
            del os.environ["GITHUB_BACKUP_TOKEN"]
            vault.return_value.inspect.side_effect = BackupError("fixture retention unavailable")
            report = doctor(config, "writer", destination="aws", collector_key=self.public,
                            signing_key=self.private, state_dir=self.state, live=True)
            self.assertFalse(report["local_ready"])
            vault.assert_called_once()

    def sftp(self, extra=""):
        config = self.root / "sftp.conf"
        config.write_text("[queue]\ntype=sftp\nhost=fixture.invalid\nuser=readonly\ndisable_hashcheck=true\n" + extra)
        config.chmod(0o600)
        known = self.root / "known_hosts"
        known.write_text("fixture host-key fixture; not real deployment material\n")
        return config, known

    def test_read_only_queue_poll_pins_host_key_and_removes_ambient_credentials(self):
        config, known = self.sftp()
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return b""
        with patch.dict(os.environ, {"GITHUB_BACKUP_TOKEN": "source-secret", "RCLONE_CONFIG_PASS_COMMAND": "evil"}):
            result = pull_queue("queue:published", self.root / "inbox", config, known, "captures", 1024 ** 2, runner=runner)
        self.assertFalse(result["remote_deletion"])
        args, options = calls[0]
        self.assertEqual("copy", args[1])
        self.assertIn("--sftp-known-hosts-file", args)
        self.assertIn("--sftp-disable-hashcheck", args)
        self.assertNotIn("GITHUB_BACKUP_TOKEN", options["env"])
        self.assertNotIn("RCLONE_CONFIG_PASS_COMMAND", options["env"])

    def test_queue_transport_rejects_shell_helpers_unpinned_host_and_other_backends(self):
        for extra in ("md5sum_command=evil\n", "shell_type=unix\n"):
            config, known = self.sftp(extra)
            with self.assertRaises(BackupError):
                pull_queue("queue:published", self.root / "inbox", config, known, "events", 1024, runner=Mock())
        config, known = self.sftp()
        known.write_text("")
        with self.assertRaises(BackupError):
            pull_queue("queue:published", self.root / "inbox", config, known, "events", 1024, runner=Mock())

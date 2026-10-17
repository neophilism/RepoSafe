import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError
from reposafe.config import load


class ConfigTests(unittest.TestCase):
    def test_dataset_enrollment_requires_fixed_adapters_and_dedicated_credentials(self):
        base = '[github]\nowners=["neophilism"]\n[encryption]\nrecipients=["age1' + 'a' * 58 + '"]\n'
        valid = '[[datasets]]\nname="database"\nkind="postgres"\nservice="backup"\ncredential_prefix="REPOSAFE_DATABASE"\n'
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.toml"
            path.write_text(base + valid)
            self.assertEqual("postgres", load(path).datasets[0].kind)
            for extra in (valid.replace('kind="postgres"', 'kind="shell"'),
                          valid.replace('REPOSAFE_DATABASE', 'PG'), valid + valid):
                path.write_text(base + extra)
                with self.assertRaises(BackupError):
                    load(path)

    def test_invalid_and_duplicate_destinations_fail(self):
        recipient = "age1" + "a" * 58
        base = f'[github]\nowners=["neophilism"]\n[encryption]\nrecipients=["{recipient}"]\n'
        for extra in (
            '[[destinations]]\nname="drive"\nremote=":http:evil"\n',
            '[[destinations]]\nname="drive"\nremote="x:"\n[[destinations]]\nname="drive"\nremote="y:"\n',
            '[[destinations]]\nname="drive"\nremote="x:"\nrequired="yes"\n',
        ):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "config.toml"
                path.write_text(base + extra)
                with self.assertRaises(BackupError):
                    load(path)

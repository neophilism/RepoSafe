import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError
from reposafe.config import load


class ConfigTests(unittest.TestCase):
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

"""Materialize runner secrets without printing them or writing inside the checkout."""

import base64
import configparser
import os
import re
from pathlib import Path


def prepare(environment):
    os.umask(0o077)
    root = Path(environment["RUNNER_TEMP"])
    recipient = environment["AGE_RECIPIENT"].strip()
    if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
        raise ValueError("invalid public recipient")
    content = base64.b64decode(environment["RCLONE_CONFIG_B64"], validate=True)
    parsed = configparser.ConfigParser(interpolation=None)
    parsed.read_string(content.decode())
    if parsed["gdrive"]["type"] != "drive" or parsed["dropbox"]["type"] != "dropbox":
        raise ValueError("expected Drive and Dropbox remotes")
    remote_config = root / "reposafe-rclone.conf"
    with remote_config.open("xb") as output:
        output.write(content)
    template = Path("reposafe.example.toml").read_text()
    config = root / "reposafe.toml"
    with config.open("x") as output:
        output.write(template.replace("REPLACE_WITH_AGE_PUBLIC_RECIPIENT", recipient))
    return config, remote_config


if __name__ == "__main__":
    try:
        prepare(os.environ)
    except (OSError, ValueError, KeyError, configparser.Error):
        raise SystemExit("runtime configuration unavailable or invalid; check setup instructions") from None

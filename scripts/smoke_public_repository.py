"""Read-only public smoke test; all identities and destinations are temporary."""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reposafe.common import command, sha256
from reposafe.config import Config, Destination
from reposafe.delivery import deliver_all, delivery_succeeded
from reposafe.restore import restore
from reposafe.snapshot import capture


class PublicRepository:
    token = "unused-public-smoke-fixture"

    def inventory(self, config):
        return [{"id": 1422882442, "full_name": "neophilism/RepoSafe"}]


def main():
    with tempfile.TemporaryDirectory(prefix="reposafe-public-smoke-") as raw:
        root = Path(raw)
        identity = root / "throwaway-identity"
        command(["age-keygen", "-o", identity])
        recipient = command(["age-keygen", "-y", identity]).decode().strip()
        result = capture(Config(("neophilism",), (recipient,)), PublicRepository(), root / "output")
        if not result.complete:
            raise SystemExit("public GitHub mirror/LFS smoke capture failed")
        destinations = tuple(Destination(name, str(root / name)) for name in ("drive-fixture", "dropbox-fixture"))
        if not delivery_succeeded(deliver_all(result.directory, destinations)):
            raise SystemExit("local transport smoke failed")
        output = root / "restored"
        restore(result.directory, identity, output,
                trusted_sha256=sha256(result.directory / "snapshot.tar.gz.age"))
        mirror = output / "snapshot/repositories/1422882442/mirror.git"
        command(["git", "-C", mirror, "fsck", "--full", "--strict"])
        if b"RepoSafe" not in command(["git", "-C", mirror, "show", "HEAD:README.md"]):
            raise SystemExit("restored public repository content mismatch")
        print("public GitHub mirror, LFS command, encryption, local delivery and offline restore passed")


if __name__ == "__main__":
    main()

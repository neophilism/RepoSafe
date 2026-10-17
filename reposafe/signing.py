"""Standard Ed25519 signatures over domain-separated SHA-256 document digests."""

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .common import BackupError, sha256, write_json

PURPOSES = {"collector-receipt", "writer-catalog", "witness-event", "coverage-registry", "recovery-kit", "offline-media", "offline-copy", "production-acceptance"}


def crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return serialization, ed25519
    except ImportError:
        raise BackupError("signatures require the cryptography optional dependency") from None


def read_regular(path, maximum, *, private=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or (private and info.st_mode & 0o077):
                raise ValueError
            value = source.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError
        return value
    except (OSError, ValueError):
        raise BackupError("invalid signature, document or key file") from None


def public_key(path):
    serialization, ed25519 = crypto()
    try:
        key = serialization.load_pem_public_key(read_regular(path, 65536))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError
        return key
    except (ValueError, TypeError):
        raise BackupError("expected a pinned Ed25519 public key") from None


def key_id(key):
    serialization, _ = crypto()
    return hashlib.sha256(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def message(purpose, digest):
    return ("RepoSafe signature v1\x00" + purpose + "\x00" + digest).encode("ascii")


def envelope_shape(envelope, digest, purpose):
    try:
        expected = {"schema_version", "algorithm", "purpose", "key_id", "sha256", "signature"}
        if set(envelope) != expected or envelope["schema_version"] != 1 or envelope["algorithm"] != "Ed25519":
            raise ValueError
        if purpose not in PURPOSES or envelope["purpose"] != purpose or envelope["sha256"] != digest:
            raise ValueError
        if not re.fullmatch(r"[0-9a-f]{64}", envelope["key_id"]) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        return signature
    except (ValueError, TypeError, KeyError):
        raise BackupError("signature envelope or document digest mismatch") from None


def sign_file(document, private_key, output, purpose):
    serialization, ed25519 = crypto()
    try:
        key = serialization.load_pem_private_key(read_regular(private_key, 65536, private=True), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey) or purpose not in PURPOSES:
            raise ValueError
        digest = hashlib.sha256(read_regular(document, 16 * 1024 ** 2)).hexdigest()
        envelope = {"schema_version": 1, "algorithm": "Ed25519", "purpose": purpose,
                    "key_id": key_id(key.public_key()), "sha256": digest,
                    "signature": base64.b64encode(key.sign(message(purpose, digest))).decode()}
        write_json(output, envelope)
        return envelope
    except (ValueError, TypeError):
        raise BackupError("invalid private Ed25519 signing key or purpose") from None


def verify_bytes(content, envelope, pinned_key, purpose):
    digest = hashlib.sha256(content).hexdigest()
    signature = envelope_shape(envelope, digest, purpose)
    _, ed25519 = crypto()
    if isinstance(pinned_key, ed25519.Ed25519PublicKey):
        key = pinned_key
    elif Path(pinned_key).is_dir() and not Path(pinned_key).is_symlink():
        paths = sorted(Path(pinned_key).glob("*.pem"))
        if not 1 <= len(paths) <= 32:
            raise BackupError("invalid pinned key ring")
        matches = [candidate for path in paths if key_id(candidate := public_key(path)) == envelope["key_id"]]
        if len(matches) != 1:
            raise BackupError("signature key is not in the independently pinned key ring")
        key = matches[0]
    else:
        key = public_key(pinned_key)
    if envelope["key_id"] != key_id(key):
        raise BackupError("signature public key does not match its independent pin")
    try:
        key.verify(signature, message(purpose, digest))
    except Exception:
        raise BackupError("document signature verification failed") from None
    return digest


def private_public_key(path):
    serialization, ed25519 = crypto()
    try:
        key = serialization.load_pem_private_key(read_regular(path, 65536, private=True), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError
        return key.public_key()
    except (TypeError, ValueError):
        raise BackupError("expected a private Ed25519 signing key") from None


def verify_file(document, signature, pinned_key, purpose):
    try:
        envelope = json.loads(read_regular(signature, 4096))
    except (ValueError, TypeError, RecursionError):
        raise BackupError("invalid signature JSON") from None
    return verify_bytes(read_regular(document, 16 * 1024 ** 2), envelope, pinned_key, purpose)


def generate_keys(output):
    serialization, ed25519 = crypto()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        raise BackupError("signing key output must be a new private directory")
    output.mkdir(mode=0o700)
    key = ed25519.Ed25519PrivateKey.generate()
    for name, value in (("private.pem", key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            ("public.pem", key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))):
        path = output / name
        with path.open("xb") as target:
            path.chmod(0o600)
            target.write(value)
            target.flush()
            os.fsync(target.fileno())
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return key_id(key.public_key())

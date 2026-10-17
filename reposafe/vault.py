"""Native, version-aware S3/B2 writes with mandatory compliance retention checks."""

import base64
import hashlib
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone

from .common import BackupError, sha256
from .github import NoRedirect


def credentials(destination):
    prefix = destination.credential_prefix
    key, secret = os.environ.get(prefix + "_ACCESS_KEY_ID"), os.environ.get(prefix + "_SECRET_ACCESS_KEY")
    if not key or not secret:
        raise BackupError("destination-specific vault credentials are required")
    return {"aws_access_key_id": key, "aws_secret_access_key": secret,
            "aws_session_token": os.environ.get(prefix + "_SESSION_TOKEN")}


def authorize_b2(destination, values, *, opener=None, read_only=False):
    opener = opener or urllib.request.build_opener(NoRedirect())
    credential = values["aws_access_key_id"] + ":" + values["aws_secret_access_key"]
    request = urllib.request.Request("https://api.backblazeb2.com/b2api/v4/b2_authorize_account", headers={
        "Authorization": "Basic " + base64.b64encode(credential.encode()).decode()})
    try:
        with opener.open(request, timeout=60) as response:
            raw = response.read(2 * 1024 ** 2 + 1)
        if len(raw) > 2 * 1024 ** 2:
            raise ValueError
        result = json.loads(raw)
        check_b2_capabilities(destination, result, read_only=read_only)
        return result
    except (OSError, ValueError, KeyError, TypeError):
        raise BackupError("B2 identity/capability verification unavailable") from None


def check_b2_capabilities(destination, result, *, read_only=False):
    try:
        storage = result["apiInfo"]["storageApi"]
        allowed = storage["allowed"]
        buckets, caps = allowed["buckets"], set(allowed["capabilities"])
        required = {"listBuckets", "listFiles", "readFiles",
                    "readBucketRetentions", "readFileRetentions"}
        if not read_only:
            required.add("writeFiles")
        safe = required | {"readFileLegalHolds", "readBucketEncryption", "readBuckets"}
        if (result["accountId"] != destination.expected_account or len(buckets) != 1 or
            buckets[0]["name"] != destination.bucket or allowed["namePrefix"] != destination.prefix + "/" or
            not required <= caps or not caps <= safe or storage["s3ApiUrl"].rstrip("/") != destination.endpoint.rstrip("/")):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BackupError("B2 key must match the account/bucket/prefix and have read/write-only capabilities") from None


def connect(destination, *, read_only=False):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise BackupError("native vaults require the boto3 optional dependency") from None
    values = credentials(destination)
    options = Config(signature_version="s3v4", retries={"mode": "standard", "max_attempts": 5},
                     connect_timeout=30, read_timeout=120,
                     request_checksum_calculation="when_required", response_checksum_validation="when_required")
    if destination.kind == "b2":
        authorize_b2(destination, values, read_only=read_only)
        endpoint, account = destination.endpoint, destination.expected_account
    else:
        endpoint = f"https://s3.{destination.region}.amazonaws.com"
        try:
            account = boto3.client("sts", region_name=destination.region,
                endpoint_url=f"https://sts.{destination.region}.amazonaws.com", config=options, **values).get_caller_identity()["Account"]
        except Exception:
            raise BackupError("AWS destination identity verification failed") from None
    try:
        return boto3.client("s3", region_name=destination.region, endpoint_url=endpoint,
                            config=options, verify=True, **values), account
    except Exception:
        raise BackupError("vault SDK configuration failed") from None


def error_status(error):
    try:
        return int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
    except (AttributeError, TypeError, ValueError):
        return 0


class ObjectVault:
    def __init__(self, destination, *, client=None, identity_account=None, clock=None, read_only=False):
        self.destination = destination
        if client is None:
            client, identity_account = connect(destination, read_only=read_only)
        if identity_account != destination.expected_account:
            raise BackupError("vault identity does not match the configured account")
        self.client = client
        self.read_only = read_only
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.retention_anchor = self.clock()
        self.owner = {"ExpectedBucketOwner": destination.expected_account} if destination.kind == "s3" else {}

    def inspect(self):
        try:
            kwargs = {"Bucket": self.destination.bucket, **self.owner}
            if self.client.get_bucket_versioning(**kwargs).get("Status") != "Enabled":
                raise BackupError("vault versioning is not enabled")
            if self.destination.kind == "s3":
                public = self.client.get_public_access_block(**kwargs)["PublicAccessBlockConfiguration"]
                if not all(public.get(key) is True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                    raise BackupError("vault public access is not fully blocked")
            else:
                acl = self.client.get_bucket_acl(**kwargs)
                if any(grant.get("Grantee", {}).get("URI") in (
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") for grant in acl["Grants"]):
                    raise BackupError("B2 vault must be private")
            config = self.client.get_object_lock_configuration(**kwargs)["ObjectLockConfiguration"]
            retention = config["Rule"]["DefaultRetention"]
            days = retention.get("Days", retention.get("Years", 0) * 365)
            if config["ObjectLockEnabled"] != "Enabled" or retention["Mode"] != "COMPLIANCE" or days < self.destination.retention_days:
                raise BackupError("vault default compliance retention does not meet policy")
        except BackupError:
            raise
        except Exception:
            raise BackupError("vault versioning/retention inspection failed") from None

    def retention(self, key, version):
        value = self.client.get_object_retention(Bucket=self.destination.bucket, Key=key,
                                                 VersionId=version, **self.owner)["Retention"]
        until = value["RetainUntilDate"]
        # One minute permits elapsed transfer time; expiry must still cover the policy horizon.
        minimum = self.retention_anchor + timedelta(days=self.destination.retention_days) - timedelta(minutes=1)
        if value["Mode"] != "COMPLIANCE" or until.tzinfo is None or until < minimum or until <= self.clock() + timedelta(minutes=1):
            raise BackupError("uploaded object version has insufficient compliance retention")
        return until.astimezone(timezone.utc).isoformat()

    def verify_version(self, key, version, expected_hash, expected_size):
        if not isinstance(version, str) or not version or version == "null":
            raise BackupError("vault returned no durable object version ID")
        response = self.client.get_object(Bucket=self.destination.bucket, Key=key, VersionId=version, **self.owner)
        if response.get("VersionId", version) != version or response.get("ContentLength") != expected_size:
            response["Body"].close()
            raise BackupError("vault read-back version/size mismatch")
        body, digest, total = response["Body"], hashlib.sha256(), 0
        try:
            while chunk := body.read(1024 * 1024):
                total += len(chunk)
                if total > expected_size:
                    raise BackupError("vault read-back exceeded expected size")
                digest.update(chunk)
        finally:
            body.close()
        if total != expected_size or digest.hexdigest() != expected_hash:
            raise BackupError("vault read-back content mismatch")
        until = self.retention(key, version)
        return {"key": key, "version_id": version, "sha256": expected_hash, "bytes": expected_size,
                "retention_mode": "COMPLIANCE", "retain_until": until}

    def audit_version(self, record):
        """Read-only maintenance evidence, including expired locks and legal holds."""
        try:
            version, key = record["version_id"], record["key"]
            if not version or version == "null":
                raise ValueError
            kwargs = {"Bucket": self.destination.bucket, "Key": key, "VersionId": version, **self.owner}
            head = self.client.head_object(**kwargs)
            if head.get("VersionId") != version or head["ContentLength"] != record["bytes"]:
                raise ValueError
            retention = self.client.get_object_retention(**kwargs)["Retention"]
            hold = self.client.get_object_legal_hold(**kwargs)["LegalHold"]["Status"]
            until = retention["RetainUntilDate"]
            if retention["Mode"] != "COMPLIANCE" or until.tzinfo is None or hold not in ("ON", "OFF"):
                raise ValueError
            return {"mode": "COMPLIANCE", "retain_until": until.astimezone(timezone.utc).isoformat(), "legal_hold": hold}
        except Exception:
            raise BackupError("maintenance version/retention/legal-hold read could not be verified") from None

    def store(self, path, run_id, *, expected_hash, expected_size):
        if self.read_only:
            raise BackupError("recovery identity cannot upload")
        if expected_size > 2 * 1024 ** 3:
            raise BackupError("vault object exceeds 2 GiB; enable bounded snapshot chunks")
        if path.is_symlink() or path.stat().st_size != expected_size or sha256(path) != expected_hash:
            raise BackupError("local ciphertext changed before vault transfer")
        key = f"{self.destination.prefix}/{run_id}/{path.name}"
        kwargs = {"Bucket": self.destination.bucket, "Key": key, **self.owner}
        version = None
        try:
            existing = self.client.head_object(**kwargs)
            version = existing.get("VersionId")
            if not isinstance(version, str) or not version or version == "null":
                raise BackupError("existing vault object has no protected version ID")
        except Exception as error:
            if error_status(error) != 404:
                raise BackupError("vault existing-object inspection failed") from None
        if version is None:
            md5 = hashlib.md5(usedforsecurity=False)
            with path.open("rb") as content:
                for chunk in iter(lambda: content.read(1024 * 1024), b""):
                    md5.update(chunk)
            with path.open("rb") as content:
                # Bucket defaults supply retention; writer never receives retention-update privilege.
                conditional = {"IfNoneMatch": "*"} if self.destination.kind == "s3" else {}
                try:
                    result = self.client.put_object(**kwargs, **conditional, Body=content,
                        ContentMD5=base64.b64encode(md5.digest()).decode(), ContentType="application/octet-stream")
                    version = result.get("VersionId")
                except Exception as error:
                    if error_status(error) != 412:
                        raise BackupError("vault upload failed; retry preserves prior versions") from None
                    version = self.client.head_object(**kwargs).get("VersionId")
        return self.verify_version(key, version, expected_hash, expected_size)

    def deliver(self, directory, destination, run_id):
        from .delivery import verify_snapshot, transfer_files
        receipt = verify_snapshot(directory)
        self.retention_anchor = datetime.strptime(run_id[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        self.inspect()
        objects = []
        try:
            for entry in receipt["files"]:
                objects.append(self.store(directory / entry["name"], run_id,
                                          expected_hash=entry["sha256"], expected_size=entry["bytes"]))
            if "receipt.sig.json" in transfer_files(directory, receipt):
                path = directory / "receipt.sig.json"
                objects.append(self.store(path, run_id, expected_hash=sha256(path), expected_size=path.stat().st_size))
            # Only a completely checked payload can be followed by a completion receipt.
            path = directory / "receipt.json"
            objects.append(self.store(path, run_id, expected_hash=sha256(path), expected_size=path.stat().st_size))
            return {"provider": destination.kind, "bucket": destination.bucket, "objects": objects,
                    "checked_at": self.clock().isoformat()}
        except BackupError:
            raise
        except Exception:
            raise BackupError("vault transfer or per-version retention verification failed") from None

    def retrieve(self, output, receipt, evidence, *, maximum_bytes=100 * 1024 ** 3, minimum_free_bytes=128 * 1024 ** 2):
        """Fetch exact versions from a separately authenticated delivery catalog."""
        from pathlib import Path
        import shutil
        from .delivery import verify_snapshot
        output = Path(output).absolute()
        if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
            raise BackupError("vault recovery output must be new with no symlink ancestors")
        created = False
        try:
            from .delivery import RUN_ID
            if not RUN_ID.fullmatch(receipt["run_id"]) or receipt["schema_version"] not in (2, 3):
                raise BackupError("invalid catalog snapshot receipt")
            files = receipt["files"]
            names = ([f"chunk-{i:06d}.age" for i in range(len(files))]
                     if receipt["schema_version"] == 3 else ["snapshot.tar.gz.age"])
            if not 1 <= len(files) <= 10000 or [entry["name"] for entry in files] != names:
                raise BackupError("invalid catalog snapshot filenames")
            expected = {entry["name"]: entry for entry in receipt["files"]}
            expected["receipt.json"] = None
            records = evidence["objects"]
            if (not isinstance(records, list) or not all(isinstance(r, dict) and type(r.get("bytes")) is int and
                    r["bytes"] > 0 for r in records) or sum(r["bytes"] for r in records) > maximum_bytes):
                raise BackupError("catalog recovery exceeds its byte budget")
            if shutil.disk_usage(output.parent).free < sum(r["bytes"] for r in records) + minimum_free_bytes:
                raise BackupError("insufficient disk space for vault recovery")
            if any(r["key"].endswith("/receipt.sig.json") for r in records):
                expected["receipt.sig.json"] = None
            if evidence["bucket"] != self.destination.bucket or len(records) != len(expected):
                raise BackupError("catalog does not match destination or file set")
            output.mkdir(mode=0o700)
            created = True
            seen = set()
            for record in records:
                prefix = f"{self.destination.prefix}/{receipt['run_id']}/"
                key, version = record["key"], record["version_id"]
                if not key.startswith(prefix):
                    raise BackupError("catalog object outside configured snapshot prefix")
                name = key[len(prefix):]
                if name not in expected or name in seen or not version or version == "null":
                    raise BackupError("invalid catalog file or version")
                seen.add(name)
                response = self.client.get_object(Bucket=self.destination.bucket, Key=key, VersionId=version, **self.owner)
                if response.get("VersionId", version) != version:
                    response["Body"].close()
                    raise BackupError("vault returned the wrong recovery version")
                body, total, digest = response["Body"], 0, hashlib.sha256()
                try:
                    with (output / name).open("xb") as target:
                        os.chmod(output / name, 0o600)
                        while chunk := body.read(1024 * 1024):
                            total += len(chunk)
                            if total > record["bytes"]:
                                raise BackupError("recovery object exceeds catalog size")
                            target.write(chunk)
                            digest.update(chunk)
                finally:
                    body.close()
                if total != record["bytes"] or digest.hexdigest() != record["sha256"]:
                    raise BackupError("version-specific recovery content mismatch")
            if verify_snapshot(output) != receipt:
                raise BackupError("recovered receipt disagrees with signed catalog")
            return output
        except Exception as error:
            if created:
                shutil.rmtree(output)
            if isinstance(error, BackupError):
                raise
            raise BackupError("version-specific vault recovery failed") from None

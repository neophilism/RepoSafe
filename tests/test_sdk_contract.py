import importlib.util
import io
import unittest


@unittest.skipUnless(importlib.util.find_spec("boto3"), "boto3 optional dependency required")
class SDKContractTests(unittest.TestCase):
    def test_vault_request_fields_match_the_installed_sdk(self):
        import boto3
        from botocore.validate import validate_parameters
        client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="fixture",
                              aws_secret_access_key="fixture")
        owner = {"ExpectedBucketOwner": "123456789012"}
        examples = {
            "GetBucketVersioning": {"Bucket": "fixture-bucket", **owner},
            "GetPublicAccessBlock": {"Bucket": "fixture-bucket", **owner},
            "GetObjectLockConfiguration": {"Bucket": "fixture-bucket", **owner},
            "HeadObject": {"Bucket": "fixture-bucket", "Key": "key", "VersionId": "version", **owner},
            "PutObject": {"Bucket": "fixture-bucket", "Key": "key", "IfNoneMatch": "*",
                          "Body": io.BytesIO(b"data"), "ContentMD5": "fixture", **owner},
            "GetObject": {"Bucket": "fixture-bucket", "Key": "key", "VersionId": "version", **owner},
            "GetObjectRetention": {"Bucket": "fixture-bucket", "Key": "key", "VersionId": "version", **owner},
            "GetObjectLegalHold": {"Bucket": "fixture-bucket", "Key": "key", "VersionId": "version", **owner},
        }
        for operation, values in examples.items():
            with self.subTest(operation=operation):
                validate_parameters(values, client.meta.service_model.operation_model(operation).input_shape)

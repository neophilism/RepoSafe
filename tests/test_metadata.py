import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from reposafe.common import BackupError
from reposafe.metadata import Budget, connections, download, export_repository


class FixtureAPI:
    token = "never-forward-this"

    def pages(self, path, key=None):
        if path.endswith("/issues?state=all"):
            return iter([{"number": 1, "title": "issue"}, {"number": 2, "pull_request": {}}])
        if path.endswith("/pulls?state=all"):
            return iter([{"number": 2}])
        if path.endswith("/comments"):
            return iter([{"id": 3, "body": "comment"}])
        return iter([])

    def get(self, path):
        return {"number": 2, "body": "pull request"}

    def graphql(self, query, variables):
        return {"repository": {"pullRequest": {"reviewThreads": {"nodes": [{"id": "thread", "isResolved": True}],
                "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}


class MetadataTests(unittest.TestCase):
    def test_issue_pr_comments_reviews_and_thread_exports_are_explicit(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "metadata"
            export_repository(FixtureAPI(), {"full_name": "owner/repo"}, target, ("collaboration", "releases"), maximum_bytes=100000)
            issues = [json.loads(line) for line in (target / "issues.jsonl").read_text().splitlines()]
            self.assertEqual(1, len(issues))
            pulls = json.loads((target / "pulls.jsonl").read_text())
            self.assertEqual(1, pulls["exported_review_threads"]["count"])
            self.assertTrue((target / "pull-2-conversation.jsonl").exists())
            self.assertTrue(all(r["status"] == "complete" for r in json.loads((target / "coverage.json").read_text())["resources"]))

    def test_metadata_budget_failure_is_recorded_and_fails_capture(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "metadata"
            with self.assertRaises(BackupError):
                export_repository(FixtureAPI(), {"full_name": "owner/repo"}, target, ("collaboration",), maximum_bytes=1)
            self.assertEqual("failed", json.loads((target / "coverage.json").read_text())["resources"][0]["status"])

    def test_graphql_repeated_cursor_does_not_loop(self):
        def repeated(cursor):
            return {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": "same"}}
        with self.assertRaises(BackupError):
            list(connections(repeated))

    def test_asset_redirect_strips_auth_and_verifies_content(self):
        requests = []
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://release-assets.githubusercontent.com/file?token=fixture"}, None)
                return io.BytesIO(b"asset")
        api = FixtureAPI()
        api.opener = Opener()
        with tempfile.TemporaryDirectory() as raw:
            result = download(api, "/repos/owner/repo/releases/assets/1", Path(raw) / "asset", Budget(100), expected_size=5)
        self.assertEqual(5, result["bytes"])
        self.assertEqual("Bearer never-forward-this", requests[0].get_header("Authorization"))
        self.assertIsNone(requests[1].get_header("Authorization"))

    def test_external_redirect_and_truncated_assets_are_rejected(self):
        class BadRedirect:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://attacker.example/file"}, None)
        api = FixtureAPI()
        api.opener = BadRedirect()
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(BackupError):
            download(api, "/repos/a/b/releases/assets/1", Path(raw) / "asset", Budget(100))
        class Truncated:
            def open(self, request, timeout):
                return io.BytesIO(b"x")
        api.opener = Truncated()
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(BackupError):
            download(api, "/repos/a/b/releases/assets/1", Path(raw) / "asset", Budget(100), expected_size=5)

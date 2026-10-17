import io
import json
import unittest
import urllib.error

from reposafe.common import BackupError
from reposafe.config import Config
from reposafe.github import GitHub, NoRedirect


def repo(n, owner="neophilism", private=False):
    return {"id": n, "full_name": f"{owner}/repo-{n}", "owner": {"login": owner}, "private": private}


class Opener:
    def __init__(self, pages):
        self.values = iter(pages)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return io.BytesIO(json.dumps(value).encode())


class InventoryTests(unittest.TestCase):
    def test_paginates_public_private_archived_and_forks(self):
        first = [repo(n, private=n % 2 == 0) for n in range(1, 101)]
        first[0].update(archived=True, fork=True)
        opener = Opener([first, [repo(101), repo(102, "someone-else")]])
        result = GitHub("secret", opener=opener).inventory(Config(("neophilism",), ()))
        self.assertEqual(101, len(result))
        self.assertIn("page=2", opener.requests[1].full_url)
        self.assertEqual("Bearer secret", opener.requests[0].get_header("Authorization"))

    def test_empty_or_required_repository_missing_fails_closed(self):
        for values in ([], [repo(1)]):
            with self.subTest(values=values), self.assertRaises(BackupError):
                GitHub("secret", opener=Opener([values])).inventory(
                    Config(("neophilism",), (), required_repositories=("neophilism/required",)))

    def test_retries_rate_limit_without_leaking_response(self):
        error = urllib.error.HTTPError("https://api.github.com", 429, "secret", {"Retry-After": "1"}, None)
        sleep = []
        github = GitHub("secret", opener=Opener([error, []]), sleep=sleep.append)
        self.assertEqual([], github.get("/user/repos"))
        self.assertEqual([1], sleep)

    def test_auth_failure_is_not_empty_inventory(self):
        error = urllib.error.HTTPError("https://api.github.com", 401, "sensitive", {}, None)
        with self.assertRaisesRegex(BackupError, "401") as caught:
            GitHub("secret", opener=Opener([error])).get("/user/repos")
        self.assertNotIn("sensitive", str(caught.exception))

    def test_redirects_and_external_api_paths_rejected(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))
        with self.assertRaises(BackupError):
            GitHub("secret").get("//evil.example")

    def test_untrusted_repository_name_rejected(self):
        value = repo(1)
        value["full_name"] = "neophilism/../../escape"
        with self.assertRaises(BackupError):
            GitHub("secret", opener=Opener([[value]])).inventory(Config(("neophilism",), ()))

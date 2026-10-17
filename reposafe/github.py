"""Paginated authenticated inventory; credential-bearing redirects are forbidden."""

import json
import time
import urllib.error
import urllib.request

from .common import BackupError
from .config import FULL_NAME


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, *, opener=None, sleep=time.sleep):
        if not token or "\n" in token or "\r" in token:
            raise BackupError("GITHUB_BACKUP_TOKEN is required")
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.sleep = sleep

    def get(self, path):
        if not path.startswith("/") or path.startswith("//"):
            raise BackupError("invalid GitHub API path")
        request = urllib.request.Request("https://api.github.com" + path, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "RepoSafe/0.1",
        })
        for attempt in range(5):
            try:
                with self.opener.open(request, timeout=60) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                retryable = error.code in (429, 500, 502, 503, 504) or (error.code == 403 and error.headers.get("Retry-After"))
                if retryable and attempt < 4:
                    try:
                        delay = min(60, max(1, int(error.headers.get("Retry-After", 2 ** attempt))))
                    except ValueError:
                        delay = 2 ** attempt
                    self.sleep(delay)
                    continue
                raise BackupError(f"GitHub API failed (HTTP {error.code}); no complete inventory") from None
            except (OSError, ValueError):
                if attempt < 4:
                    self.sleep(2 ** attempt)
                    continue
                raise BackupError("GitHub API unavailable or invalid response") from None
        raise BackupError("GitHub retry limit reached")

    def pages(self, path):
        separator = "&" if "?" in path else "?"
        for page in range(1, 10001):
            values = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(values, list):
                raise BackupError("GitHub pagination returned an invalid response")
            yield from values
            if len(values) < 100:
                return
        raise BackupError("GitHub pagination limit reached; inventory incomplete")

    def inventory(self, config):
        owners = {o.lower() for o in config.owners}
        repositories = {}
        for repo in self.pages("/user/repos?visibility=all&affiliation=owner,organization_member"):
            try:
                if repo["owner"]["login"].lower() not in owners:
                    continue
                name = repo["full_name"]
                if (not FULL_NAME.fullmatch(name) or name.rsplit("/", 1)[1] in (".", "..") or
                    name.split("/", 1)[0].lower() != repo["owner"]["login"].lower()):
                    raise ValueError
                if type(repo["id"]) is not int or repo["id"] < 1:
                    raise ValueError
                repositories[repo["id"]] = repo
            except (KeyError, TypeError, AttributeError, ValueError):
                raise BackupError("invalid GitHub repository metadata") from None
        names = {r["full_name"].lower() for r in repositories.values()}
        if len(repositories) < config.minimum_repositories or any(r.lower() not in names for r in config.required_repositories):
            raise BackupError("repository coverage guard failed; check token permissions")
        return sorted(repositories.values(), key=lambda r: r["id"])

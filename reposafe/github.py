"""Paginated authenticated inventory; credential-bearing redirects are forbidden."""

import json
import time
import urllib.error
import urllib.request

from .common import BackupError
from .config import FULL_NAME


class APIError(BackupError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"GitHub API failed (HTTP {status}); no complete inventory/export")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, *, opener=None, sleep=time.sleep, auth=None):
        if not token or "\n" in token or "\r" in token:
            raise BackupError("GITHUB_BACKUP_TOKEN is required")
        self._token = token
        self.auth = auth
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.sleep = sleep

    @property
    def token(self):
        return self._token

    def for_repository(self, repo):
        return GitHub(self.auth.token_for(repo), sleep=self.sleep) if self.auth else self

    def request(self, path, *, method="GET", data=None):
        if not path.startswith("/") or path.startswith("//"):
            raise BackupError("invalid GitHub API path")
        request = urllib.request.Request("https://api.github.com" + path, method=method,
                                        data=json.dumps(data).encode() if data is not None else None, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "RepoSafe/0.1",
            "Content-Type": "application/json",
        })
        for attempt in range(5):
            try:
                with self.opener.open(request, timeout=60) as response:
                    raw = response.read(16 * 1024 ** 2 + 1)
                    if len(raw) > 16 * 1024 ** 2:
                        raise BackupError("GitHub JSON response exceeded its byte limit")
                    return json.loads(raw)
            except urllib.error.HTTPError as error:
                retryable = error.code in (429, 500, 502, 503, 504) or (error.code == 403 and error.headers.get("Retry-After"))
                if retryable and attempt < 4:
                    try:
                        delay = min(60, max(1, int(error.headers.get("Retry-After", 2 ** attempt))))
                    except ValueError:
                        delay = 2 ** attempt
                    self.sleep(delay)
                    continue
                raise APIError(error.code) from None
            except (OSError, ValueError):
                if attempt < 4:
                    self.sleep(2 ** attempt)
                    continue
                raise BackupError("GitHub API unavailable or invalid response") from None
        raise BackupError("GitHub retry limit reached")

    def get(self, path):
        return self.request(path)

    def graphql(self, query, variables):
        if "mutation" in query.lower():
            raise BackupError("source adapter accepts read-only GraphQL queries")
        result = self.request("/graphql", method="POST", data={"query": query, "variables": variables})
        if not isinstance(result, dict) or result.get("errors") or "data" not in result:
            raise BackupError("GitHub GraphQL export incomplete")
        return result["data"]

    def pages(self, path, *, key=None):
        separator = "&" if "?" in path else "?"
        for page in range(1, 10001):
            values = self.get(f"{path}{separator}per_page=100&page={page}")
            if key:
                values = values.get(key) if isinstance(values, dict) else None
            if not isinstance(values, list):
                raise BackupError("GitHub pagination returned an invalid response")
            yield from values
            if len(values) < 100:
                return
        raise BackupError("GitHub pagination limit reached; inventory incomplete")

    def inventory(self, config):
        owners = {o.lower() for o in config.owners}
        repositories = {}
        values = (self.auth.repositories(config) if self.auth else
                  self.pages("/user/repos?visibility=all&affiliation=owner,organization_member"))
        for repo in values:
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

"""Bounded, explicit GitHub JSON and binary exports; no source execution."""

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError, write_json
from .github import APIError

CDN_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com",
             "github-production-release-asset-2e65be.s3.amazonaws.com"}


class Budget:
    def __init__(self, maximum):
        self.maximum, self.used = maximum, 0

    def take(self, count):
        self.used += count
        if self.used > self.maximum:
            raise BackupError("metadata export exceeded its byte budget")


def save_lines(path, values, budget):
    count = 0
    with Path(path).open("x", encoding="utf-8") as target:
        os.chmod(path, 0o600)
        for value in values:
            line = json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n"
            budget.take(len(line.encode()))
            target.write(line)
            count += 1
    return count


def positive_id(value):
    if type(value) is not int or value < 1:
        raise BackupError("invalid API item identifier")
    return value


def download(client, api_path, destination, budget, *, expected_size=None, expected_digest=None):
    if not api_path.startswith("/repos/") or "\r" in api_path or "\n" in api_path:
        raise BackupError("invalid asset API path")
    url, authorized = "https://api.github.com" + api_path, True
    try:
        for _ in range(4):
            headers = {"Accept": "application/octet-stream", "User-Agent": "RepoSafe/0.2"}
            if authorized:
                headers["Authorization"] = "Bearer " + client.token
            request = urllib.request.Request(url, headers=headers)
            try:
                response = client.opener.open(request, timeout=60)
                break
            except urllib.error.HTTPError as error:
                if error.code not in (301, 302, 303, 307, 308):
                    raise APIError(error.code) from None
                redirect = urllib.parse.urljoin(url, error.headers.get("Location", ""))
                parsed = urllib.parse.urlsplit(redirect)
                if (parsed.scheme != "https" or parsed.hostname not in CDN_HOSTS or
                    parsed.username or parsed.password or parsed.port not in (None, 443)):
                    raise BackupError("asset redirect outside the approved credential-free CDN hosts")
                url, authorized = redirect, False  # Never forward source authorization to a CDN.
        else:
            raise BackupError("asset redirect limit reached")
        digest, count = hashlib.sha256(), 0
        with response, Path(destination).open("xb") as output:
            os.chmod(destination, 0o600)
            while chunk := response.read(1024 * 1024):
                budget.take(len(chunk))
                count += len(chunk)
                if expected_size is not None and count > expected_size:
                    raise BackupError("asset larger than its API size")
                digest.update(chunk)
                output.write(chunk)
        if expected_size is not None and count != expected_size:
            raise BackupError("asset truncated relative to API size")
        if expected_digest and expected_digest != "sha256:" + digest.hexdigest():
            raise BackupError("asset checksum mismatch")
        return {"bytes": count, "sha256": digest.hexdigest()}
    except (OSError, ValueError):
        raise BackupError("asset download unavailable") from None


def connections(fetch):
    cursor, seen = None, set()
    for _ in range(10000):
        connection = fetch(cursor)
        if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
            raise BackupError("invalid GraphQL connection")
        yield from connection["nodes"]
        page = connection["pageInfo"]
        if not page["hasNextPage"]:
            return
        cursor = page["endCursor"]
        if not cursor or cursor in seen:
            raise BackupError("GraphQL cursor repeated or missing")
        seen.add(cursor)
    raise BackupError("GraphQL page limit exceeded")


FIELDS = "id body createdAt updatedAt author { login }"


def discussions(client, owner, name):
    query = "query($owner:String!,$name:String!,$after:String){repository(owner:$owner,name:$name){discussions(first:100,after:$after){nodes{id number title body url createdAt updatedAt author{login}}pageInfo{hasNextPage endCursor}}}}"
    for discussion in connections(lambda cursor: client.graphql(query, {"owner": owner, "name": name, "after": cursor})["repository"]["discussions"]):
        yield {"kind": "discussion", **discussion}
        comment_query = "query($id:ID!,$after:String){node(id:$id){... on Discussion{comments(first:100,after:$after){nodes{" + FIELDS + "}pageInfo{hasNextPage endCursor}}}}}"
        for comment in connections(lambda cursor: client.graphql(comment_query, {"id": discussion["id"], "after": cursor})["node"]["comments"]):
            yield {"kind": "comment", "discussion_id": discussion["id"], **comment}
            reply_query = "query($id:ID!,$after:String){node(id:$id){... on DiscussionComment{replies(first:100,after:$after){nodes{" + FIELDS + "}pageInfo{hasNextPage endCursor}}}}}"
            for reply in connections(lambda cursor: client.graphql(reply_query, {"id": comment["id"], "after": cursor})["node"]["replies"]):
                yield {"kind": "reply", "discussion_id": discussion["id"], "comment_id": comment["id"], **reply}


def export_repository(client, repo, directory, groups, *, maximum_bytes):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    base = "/repos/" + repo["full_name"]
    budget, coverage = Budget(maximum_bytes), []
    started = datetime.now(timezone.utc).isoformat()

    def lines(name, endpoint, *, key=None):
        return save_lines(directory / (name + ".jsonl"), client.pages(base + endpoint, key=key), budget)

    def collaboration():
        if repo.get("has_issues", True):
            def issues():
                for issue in client.pages(base + "/issues?state=all"):
                    if "pull_request" not in issue:
                        number = positive_id(issue["number"])
                        file = f"issue-{number}-comments.jsonl"
                        count = save_lines(directory / file, client.pages(base + f"/issues/{number}/comments"), budget)
                        issue["exported_comments"] = {"file": file, "count": count}
                        yield issue
            save_lines(directory / "issues.jsonl", issues(), budget)
        for label, route in (("labels", "/labels"), ("milestones", "/milestones?state=all")):
            try:
                lines(label, route)
            except APIError as error:
                if error.status != 410 or repo.get("has_issues", True):
                    raise
                coverage.append({"resource": label, "status": "feature_disabled"})
        def pulls():
            for pull in client.pages(base + "/pulls?state=all"):
                number = positive_id(pull["number"])
                detail = client.get(base + f"/pulls/{number}")
                for field, suffix in (("reviews", "reviews"), ("review_comments", "comments"), ("commits", "commits"), ("files", "files")):
                    file = f"pull-{number}-{field}.jsonl"
                    count = save_lines(directory / file, client.pages(base + f"/pulls/{number}/{suffix}"), budget)
                    detail["exported_" + field] = {"file": file, "count": count}
                file = f"pull-{number}-conversation.jsonl"
                count = save_lines(directory / file, client.pages(base + f"/issues/{number}/comments"), budget)
                detail["exported_conversation"] = {"file": file, "count": count}
                owner, name = repo["full_name"].split("/")
                query = "query($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$after){nodes{id isResolved isOutdated path line originalLine}pageInfo{hasNextPage endCursor}}}}}"
                file = f"pull-{number}-threads.jsonl"
                count = save_lines(directory / file, connections(lambda cursor: client.graphql(query, {"owner": owner, "name": name, "number": number, "after": cursor})["repository"]["pullRequest"]["reviewThreads"]), budget)
                detail["exported_review_threads"] = {"file": file, "count": count}
                yield detail
        save_lines(directory / "pulls.jsonl", pulls(), budget)

    def releases():
        def values():
            for release in client.pages(base + "/releases"):
                identifier = positive_id(release["id"])
                def assets():
                    for asset in client.pages(base + f"/releases/{identifier}/assets"):
                        aid = positive_id(asset["id"])
                        assets_dir = directory / "release-assets"
                        assets_dir.mkdir(exist_ok=True, mode=0o700)
                        result = download(client, base + f"/releases/assets/{aid}", assets_dir / str(aid), budget,
                                          expected_size=asset["size"], expected_digest=asset.get("digest"))
                        yield {**asset, "exported_content": result}
                file = f"release-{identifier}-assets.jsonl"
                release["exported_assets"] = {"file": file, "count": save_lines(directory / file, assets(), budget)}
                yield release
        save_lines(directory / "releases.jsonl", values(), budget)

    def actions():
        def values():
            for artifact in client.pages(base + "/actions/artifacts", key="artifacts"):
                identifier = positive_id(artifact["id"])
                if artifact.get("expired"):
                    artifact["export_status"] = "already_expired_upstream"
                else:
                    target = directory / "actions-artifacts"
                    target.mkdir(exist_ok=True, mode=0o700)
                    artifact["exported_content"] = download(client, base + f"/actions/artifacts/{identifier}/zip", target / (str(identifier) + ".zip"), budget)
                yield artifact
        save_lines(directory / "actions-artifacts.jsonl", values(), budget)
        def runs():
            for run in client.pages(base + "/actions/runs", key="workflow_runs"):
                identifier = positive_id(run["id"])
                if run.get("status") == "completed":
                    target = directory / "actions-logs"
                    target.mkdir(exist_ok=True, mode=0o700)
                    try:
                        run["exported_logs"] = download(client, base + f"/actions/runs/{identifier}/logs", target / (str(identifier) + ".zip"), budget)
                    except APIError as error:
                        if error.status != 404:
                            raise
                        run["exported_logs"] = {"status": "unavailable_upstream"}
                else:
                    run["exported_logs"] = {"status": "not_finished"}
                yield run
        save_lines(directory / "actions-runs.jsonl", runs(), budget)

    def settings():
        def rulesets():
            for rule in client.pages(base + "/rulesets"):
                yield client.get(base + f"/rulesets/{positive_id(rule['id'])}")
        save_lines(directory / "rulesets.jsonl", rulesets(), budget)
        def branches():
            for branch in client.pages(base + "/branches"):
                if branch.get("protected"):
                    name = urllib.parse.quote(branch["name"], safe="")
                    branch["exported_protection"] = client.get(base + f"/branches/{name}/protection")
                yield branch
        save_lines(directory / "branches.jsonl", branches(), budget)
        for label, route in (("collaborators", "/collaborators?affiliation=all"),
                             ("environments", "/environments")):
            lines(label, route, key="environments" if label == "environments" else None)

    operations = {"collaboration": collaboration, "releases": releases, "actions": actions,
                  "settings": settings, "discussions": lambda: save_lines(directory / "discussions.jsonl",
                      discussions(client, *repo["full_name"].split("/")), budget) if repo.get("has_discussions", True) else None}
    failed = False
    for group in groups:
        try:
            operations[group]()
            coverage.append({"resource": group, "status": "complete"})
        except (BackupError, KeyError, TypeError, ValueError, OSError):
            coverage.append({"resource": group, "status": "failed"})
            failed = True
    write_json(directory / "coverage.json", {"schema_version": 1, "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(), "resources": coverage,
        "consistency": "API collection interval; concurrent edits may span different instants"})
    if failed:
        raise BackupError("one or more configured metadata exports failed")

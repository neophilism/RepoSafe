# GitHub source coverage

Token authentication remains supported. A dedicated GitHub App is also supported:
install the `security` extra and set `GITHUB_APP_ID` plus
`GITHUB_APP_PRIVATE_KEY_FILE` (0600) on the source collector. The App discovers
configured owners' installations, rejects missing/suspended installations and
selected-repository grants by default, and mints explicitly read-only installation
tokens. Tokens are cached and refreshed before expiry; each repo uses its owner's
installation. Destination agents must not receive this key or any source token.

Base permissions: Metadata and Contents read. Collaboration adds Issues and Pull
requests read; discussions adds Discussions read; actions adds Actions read;
settings adds Administration read. The runtime token is narrowed even if the App
installation grants broader privileges. Owner-wide coverage still requires a real
comparison against the owner's expected repository inventory.

Optional `[github]` configuration:

```toml
metadata = ["collaboration", "releases", "discussions", "settings", "actions"]
metadata_maximum_bytes = 2147483648
wiki = false
allow_selected_repositories = false
# registry = "/etc/reposafe/coverage.json"
# registry_sha256 = "<independently reviewed 64-character SHA-256>"
```

Groups are opt-in for compatibility with Contents-only credentials. Every configured
group is mandatory for full status; permission/pagination/export failures make the
capture partial. Exports are bounded streaming JSONL with coverage records:

| Group | Contents |
| --- | --- |
| collaboration | Issues/comments; PR details/conversation, reviews/comments, thread resolution, files/commits; labels/milestones |
| releases | Release/asset metadata and available binary assets with size/digest checks |
| discussions | Fully paginated discussions/comments/replies and parent identifiers |
| settings | Ruleset details, branch protection, collaborators and environment metadata |
| actions | Artifact metadata/available ZIPs; run metadata and available completed-run logs |

Already-expired artifacts and unavailable/unfinished logs are recorded explicitly;
GitHub cannot supply bytes it discarded before capture. Secret values and package
registries are not implicitly exportable. Binary redirects use a fixed approved
HTTPS CDN list and never receive source Authorization. API JSON and export bytes
are bounded. Collection spans an interval; concurrent changes are not a transaction.
Metadata IDs/timestamps are preserved as records, not promised as recreatable IDs.

Mirrors record exact refs and HEAD, hash-check each discovered LFS object, and record
current branch gitlinks without fetching submodules or interpreting `.gitmodules`.
Target repositories require separate enrollment. Wiki capture is optional; an
unavailable required wiki fails that repository. GitHub can report uncreated wikis
as unavailable, so enable the option only when wiki history is required.

A hash-pinned private registry has `schema_version: 1`, `repository_ids` (positive
stable IDs), and optional `retired` records containing `id`, `reason`, `retired_at`.
Missing expected/observed IDs fail full coverage. Explicit retirement changes the
expected source inventory without deleting historical backups. Keep the registry
and digest pin outside the mutable source account. Signed witnessing adds a
separate provenance layer; local state alone is not an independent witness.

# Backup coverage

| Data | Initial implementation | Recovery boundary |
| --- | --- | --- |
| Public and private repository Git history | All refs advertised to an authenticated mirror clone | Only repositories visible to the configured token; owner filters apply |
| Branches, tags, reachable objects | Bare mirror, checked with `git fsck --full --strict` | Deleted or unreachable upstream history predating the first backup cannot be recovered |
| Empty repositories | Bare mirror and repository metadata | Git bundle is deliberately not used because empty repositories need support |
| Git LFS | `git lfs fetch --all origin` by default | Disabling LFS creates a code-only backup; unavailable LFS fails that repository |
| Repository metadata | Repository list API response per repository | JSON, not automatic recreation of GitHub settings |
| Submodules | Pointer commits in parent repository | Targets must themselves be accessible and included repositories |
| Issues, PRs, reviews, discussions, wikis, release assets, Actions artifacts | Opt-in bounded exporters and wiki mirrors | Selected groups fail completion if unavailable; JSON/asset export, not automatic GitHub re-import |
| GitHub secrets and environment secret values | Not exportable through GitHub APIs | Recover from an independently managed password manager or secret escrow |
| Explicit local files/directories | Regular-file collector with exclusions, mutation checks and byte limits | POSIX roots only; links/special files fail; no cross-file transaction or ACL/mode restoration |
| SQLite / PostgreSQL | Online SQLite backup / custom-format PostgreSQL logical dump | Enrolled data only; role secrets and PITR require independent escrow/export chains |
| Object/document services | Explicit read-only rclone sources with inventories and byte checks | Current objects/exported formats; no implicit provider version/ACL history |

Every run records coverage and failures inside the encrypted archive. A partial run
preserves useful copies but is never reported as complete. A successful inventory
only proves visibility to that token: set a minimum count and required repositories,
and reconcile the expected inventory independently. A selected-repositories token
cannot discover private repositories it cannot see.

Repositories are untrusted data: RepoSafe does not check out branches, execute
hooks, initialize submodules, or run project code. LFS endpoints are forced to
GitHub instead of accepting repository-provided endpoints.

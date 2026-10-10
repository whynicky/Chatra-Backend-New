# Safe Git-history cleanup procedure

Do not run this procedure automatically. Rewriting shared history changes commit IDs, invalidates open work, and does not rotate credentials or erase existing clones/backups. The repository owner must schedule and supervise it.

## Before rewriting

1. Complete the incident and credential-rotation checklist first. Treat all copied data as already disclosed.
2. Identify every affected path, branch, tag, fork, deployment mirror, release artifact, cache, and backup without printing file contents.
3. Announce a freeze, merge or archive open work, and require contributors to stop pushing.
4. Create an access-controlled, offline recovery mirror according to the organization's retention policy.
5. Install and verify `git-filter-repo` from its official source. Do not substitute an unreviewed script.

## Rehearsal

1. Make a disposable mirror clone in an access-controlled location.
2. Remove only the exact approved paths with `git filter-repo --path <path> --invert-paths` (repeat `--path` for every reviewed target).
3. Inspect all rewritten branches and tags. Search object/path listings and run the repository secret scanner; do not display removed object contents.
4. Build and test all supported clients from the rewritten default branch.
5. Have a second reviewer compare the approved target list with the rewrite report.

## Coordinated cutover

1. Protect the remote from writes, then force-update the reviewed branches and tags during the announced window.
2. Ask the Git hosting provider to purge cached views where its documented process requires support.
3. Recreate release artifacts and invalidate deployment caches that embedded old commit objects.
4. Require fresh clones. Do not let contributors merge old branches or push old tags back into the cleaned remote.
5. Re-run path/object scans on the remote and every protected mirror.

## Rollback and limitations

The access-controlled recovery mirror is the rollback source until acceptance. A rewrite cannot remove data from third-party clones, forks, screenshots, logs, or previously downloaded artifacts. Keep AUD-001 blocked until credential/data response and remote cleanup are independently verified.

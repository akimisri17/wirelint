# PR mode

```bash
wirelint --pr [--base <ref>] [--comment-file <path>] [workspace-dir]
```

On a pull request, ask the question while the author still remembers the
answer. For every git repository among the services (each sibling repo, or
the monorepo once), wirelint diffs `base...HEAD` and keeps only the variables
the diff adds: new env reads on added source lines and new names in
`.env.example`. An edited or moved line does not count. For each one it says
which deploy targets and environments do not set it yet (nothing for an
`optional` variable, and an environment that sets another member of the same
fallback chain counts as set), then prints the usual findings filtered to
those variables.

```
NEW IN THIS DIFF (1)
  orders-api  REFUNDS_SIGNING_KEY  added in orders-api/src/refunds.ts:1 (+1 more)
    not yet set in: orders-api/copilot/orders-api/manifest.yml (dev, prod)
```

The base is `--base`, else `origin/$GITHUB_BASE_REF` when that is set, else
`origin/main`, else `main`. Nothing is fetched: the ref must already be in the
checkout. A repository that cannot be diffed (no resolvable base, no merge
base in a shallow clone, git missing, not a git checkout, or a git error such
as dubious ownership) is skipped, and the output and the comment headline say
the run was **not fully checked**, with the reason and the fix. Exit codes are
the same as a full run, except that when every repository was skipped nothing
was checked and the exit code is `2`.

If `--comment-file` cannot be written, that is reported on stderr and the
exit code is `2` unless findings already made it `1`. A `$GITHUB_STEP_SUMMARY`
that cannot be written is only a warning. In the comment body, names, paths
and anything else read from the repository are put in code spans or escaped,
so they cannot render as HTML or mention anyone.

With `--comment-file` it also writes a Markdown comment body, and appends the
same body to `$GITHUB_STEP_SUMMARY` when that is set. wirelint never posts
anything; post the file with your own step:

```yaml
on: pull_request
jobs:
  wirelint:
    runs-on: ubuntu-latest
    permissions: { contents: read, pull-requests: write }
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx wirelint --pr --comment-file wirelint-comment.md .
      - if: always()
        run: gh pr comment ${{ github.event.pull_request.number }} --body-file wirelint-comment.md --edit-last || gh pr comment ${{ github.event.pull_request.number }} --body-file wirelint-comment.md
        env: { GH_TOKEN: "${{ github.token }}" }
```

`fetch-depth: 0` matters: without history, `origin/<base>` is not in the
checkout and the repository is skipped.

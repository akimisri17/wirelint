# wirelint

Catch cross-service environment-variable mistakes before they deploy.

One command, no config file, no cloud credentials, no network. It reads the
code and the config files already in your repos, works out which variables each
service needs, and checks that they are declared, shaped correctly and set in
every deploy environment.

```bash
npx wirelint ../my-workspace
```

> **Status: v1 (0.2.0), private, not yet on npm.** Until it is published, run it from a
> clone: `npm install && npm run build && node dist/cli.js <workspace-dir>`.

## Who it is for

A team of 5 to 15 engineers with several services, no platform team, and
config typed by hand into more than one hosting platform. If you already run
Kubernetes with a secret operator, you have better tools.

## The kind of bug it catches

A service base URL was set to a full endpoint path. Every client appended its
own path on top, so every request 404'd on a doubled path. Nothing crashed, so
nobody noticed for months.

```
SERVICE     VARIABLE                     WHERE                       PROBLEM                                      FIX
----------  ---------------------------  --------------------------  -------------------------------------------  ------------------------------
storefront  NEXT_PUBLIC_BILLING_API_URL  storefront/.env.example:3   "http://localhost:4002/v1/invoices" has the  set NEXT_PUBLIC_BILLING_API_
                                                                     resource path "/v1/invoices" after the       URL=http://localhost:4002/v1
                                                                     origin; clients append their own path to a
                                                                     base URL, so requests hit a doubled or
                                                                     malformed path
```

The fix is the one in the last column: keep the origin and the version prefix,
drop the resource path.

A second one, from a deploy manifest. The code needs a key to call another
service; the manifest sets it for `dev` and not for `prod`:

```
orders-api  INTERNAL_SERVICE_KEY  orders-api/copilot/orders-api/manifest.yml
            read in orders-api/src/config.ts:9 (required) but not set for environment prod
            fix: add INTERNAL_SERVICE_KEY to environments.prod.secrets
```

## What v0 does

It treats every child directory with a `package.json` (or its own `.git`) as a
service, so it works on a monorepo and on a folder of sibling repos.

**It infers what each service reads** from source: `process.env.X`,
`process.env['X']`, destructuring, `import.meta.env.X`, NestJS
`configService.get('X')` and `getOrThrow('X')`, and the keys of zod, Joi and
envalid schemas. Tests, build output and one-off scripts are skipped.

**It collects what each service declares**, from files only: `.env.example`,
other `.env.*` files, `docker-compose*.yml`, AWS Copilot
`copilot/*/manifest.yml` (`variables`, `secrets`, per-environment overrides,
`env_file`), `vercel.json` and `Dockerfile` `ENV`.

**It runs five checks.**

| Check | Fails when |
| --- | --- |
| `missing-from-example` | code reads a variable that `.env.example` does not list |
| `missing-from-deploy` | code needs a variable that a deploy manifest does not set, named per environment |
| `url-shape` | a `*_URL` base is not an origin plus an optional `/api`, `/v1` or `/api/v1`: resource path, trailing slash, query or fragment |
| `prod-points-at-nonprod` | a production file or environment points at `localhost`, a dev, staging or preview host, a tunnel, or a Vercel preview deployment |
| `shared-secret` | never. It suggests that a same-named secret in two services, or one example value under two names, is probably one shared value |

It also prints the service-to-service links it inferred from local ports, so
you can see who calls whom.

v1 adds checks that only run when you annotate a variable (see below):

| Check | Fails when |
| --- | --- |
| `annotation-invalid` | a `# wirelint:` annotation has an unknown word, a `same-as` without a target, or is not attached to a variable |
| `same-as-unknown-service` | `same-as <service>` names a service that was not discovered |
| `same-as-undeclared` | the other service no longer declares the variable in its `.env.example` or any deploy manifest |
| `same-as-not-deployed` | the other service sets the variable for a deploy environment that this service does not |
| `missing-from-build` | a `build-time` variable is in none of the visible build configurations (a suggestion when none is visible) |

**How strictly a missing variable is treated depends on how the code reads it.**

| The code does this | In `.env.example` check | In deploy-manifest check |
| --- | --- | --- |
| guards it: `getOrThrow`, schema-required, `!`, `if (!x) throw` | failure | failure |
| falls back to a localhost literal: `?? 'http://localhost:4000'` | failure | failure (it would silently point at localhost once deployed) |
| reads it bare, with nothing handling an unset value | failure | failure if `.env.example` lists it, otherwise a suggestion |
| has a default, compares it, or checks it before use | suggestion | not reported |

A validation schema wins when reads disagree, because it decides what the
running process actually sees.

**Exemptions built in.** Connection strings (`DATABASE_URL`, `REDIS_URL`, any
non-http scheme), single-endpoint variables (`*_WEBHOOK_URL`,
`*_CALLBACK_URL`, `*_REDIRECT_URI` and similar), templated or placeholder
values (`${HOST}`, `<your-url>`, `your-domain`), and platform variables
(`NODE_ENV`, `PORT`, `CI`, `GITHUB_*`, `VERCEL_*`, `AWS_REGION`, ...).

## What v0 does not do

- **It does not read live cloud config.** Nothing is fetched from AWS SSM,
  Secrets Manager or the Vercel API. A variable set only in a dashboard is
  invisible to it. For a service deployed on Vercel that means the
  deploy-manifest check does not run at all.
- **It does not compare secrets against live stores.** It cannot tell you that
  two services hold different values for a shared secret. It can only tell you
  that they probably should hold the same one.
- **It does not know what is actually deployed.** It checks the files in the
  checkout, on the branch you are on.
- No Kubernetes or Helm, no dashboards, no hosted service, no secret syncing,
  no auto-fixing.
- Inference is pattern-based, not a type checker. Known gap: a guard that
  returns early before a second variable is read can make that second
  variable look required.
- Computed reads such as `process.env[name]` cannot be analysed. They are
  listed once per service and never fail the run.

## Annotations: say what inference cannot guess

Optional. An annotation sits in the service's own `.env.example`, next to the
variable it describes, either at the end of the line or on the line directly
above it. Several are separated by commas. Anything after ` -- ` is a note
for humans and is ignored. There is no central contract file.

```bash
JWT_SECRET=           # wirelint: same-as identity-api
INTERNAL_SERVICE_KEY= # wirelint: same-as billing-api.ORDERS_SERVICE_KEY
SENTRY_DSN=           # wirelint: optional -- only reported in prod

# wirelint: build-time
NEXT_PUBLIC_API_URL=http://localhost:4000
```

| Annotation | Effect |
| --- | --- |
| `same-as <service>` | this variable must hold the same value as the same-named one in `<service>`. It replaces the `shared-secret` guess with a declared relation (listed under `DECLARED RELATIONS` and in `--json` as `relations`), and fails when `<service>` does not exist, stops declaring the variable, or sets it for a deploy environment this service does not. `same-as <service>.<NAME>` covers a differently named variable. Values are not compared. |
| `optional` | the variable may be absent from every deploy target; no `missing-from-deploy` finding |
| `build-time` | checked against build configuration (Dockerfile `ARG`/`ENV`, compose `build.args`, `vercel.json` `build.env`) instead of runtime manifests. Fails only when the service has a container deploy target (a Copilot manifest or a production compose file) and none of its visible build configurations sets it; otherwise a suggestion |

A typo is a failure, not a silent no-op:

```
web  FEATURE_FLAGS  web/.env.example:3  unknown wirelint annotation "optinal", so it is not honoured
                                        fix: write "optional" instead of "optinal"; put any explanation after " -- ",
                                             e.g. "# wirelint: optional -- only used in prod"
```

An explanation on its own comment line between the annotation and the
variable detaches the annotation, which is also a failure; put it after ` -- `
on the annotation's line instead.

## Fallback chains

A chain of env reads is one requirement, satisfied when any member is set:

```ts
const identity = process.env.IDENTITY_URL ?? process.env.IDENTITY_API_URL ?? 'http://localhost:4100';
```

Each member on its own is optional, so neither is reported alone. When a
deploy environment sets none of them, the chain is reported once:

```
gateway  IDENTITY_URL | IDENTITY_API_URL  gateway/copilot/gateway/manifest.yml
         fallback chain IDENTITY_URL -> IDENTITY_API_URL read in gateway/src/main.ts:1 (falls back to a
         localhost default), but none of them is set for environment prod; once deployed it silently
         points at localhost
         fix: add IDENTITY_URL to environments.prod.variables; any one of IDENTITY_URL, IDENTITY_API_URL
         satisfies the chain
```

The chain is graded like a single read: a localhost or missing fallback is
checked, a real default is not. `||` chains work the same way.

## PR mode

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

## Secrets

Values are kept only for example files. For every other file the value is
reduced at read time to a few facts (is it a URL, is its shape wrong, what kind
of host does it point at) and then dropped, so there is nothing to leak later.
Findings from those files describe the problem without quoting the value.

## Output

```bash
wirelint [workspace-dir]            # table: service, variable, where, problem, fix
wirelint --json [workspace-dir]     # the same report as JSON
wirelint --no-hints [workspace-dir] # hide suggestions
wirelint --pr [workspace-dir]       # only what this branch adds (see PR mode)
```

Exit code `1` when there are failures, `0` when there are only suggestions,
`2` for a usage error. When `GITHUB_ACTIONS` is set it also emits
`::error file=...,line=...` annotations, so findings land on the right line of
a pull request:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 22 }
- run: npx wirelint .
```

## Adopting it without fixing everything first

```bash
wirelint baseline [workspace-dir]
```

writes the current findings to `.wirelint-baseline.json` (names and paths,
no values). Commit it. From then on only new findings fail. Delete entries as
you fix them.

To accept one variable permanently, say why in that service's `.env.example`.
The reason is mandatory; a marker without one is itself a failure.

```bash
CATALOG_URL=https://catalog.example.test/v1/items.xml  # wirelint-ignore: third-party catalog, the full path is intended

# wirelint-ignore: vendor requires the trailing slash
VENDOR_URL=https://vendor.example.test/

# wirelint-ignore HARNESS_TOKEN: injected by the test harness, never configured by hand
```

## Development

```bash
npm install
npm test      # builds, then runs the Vitest suite against synthetic fixtures
node dist/cli.js test/fixtures/shop
```

TypeScript, Node 22 or newer, no runtime dependencies. See
[ROADMAP.md](ROADMAP.md) for what comes next.

## License

MIT

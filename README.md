# wirelint

Catch cross-service environment-variable mistakes before they deploy.

One command, no config file, no cloud credentials, no network. It reads the
code and the config files already in your repos, works out which variables each
service needs, and checks that they are declared, shaped correctly and set in
every deploy environment.

```bash
npx wirelint ../my-workspace
```

> **Status: v0, private, not yet on npm.** Until it is published, run it from a
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
- Inference is pattern-based, not a type checker. Known gaps: a fallback chain
  across several variables (`A ?? B ?? 'http://localhost'`) is treated as
  optional for each member, and a guard that returns early before a second
  variable is read can make that second variable look required.
- Computed reads such as `process.env[name]` cannot be analysed. They are
  listed once per service and never fail the run.

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

# wirelint

Catch cross-service environment-variable mistakes before they deploy.

```bash
npx @akhil-misri/wirelint .
```

One command, no config file, no cloud credentials, no network. wirelint reads
the code and config files already in your repos, works out which variables
each service needs, and checks that they are declared, shaped correctly and
set in every deploy environment.

- [What it catches](#what-it-catches)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Checks](#checks)
- [Annotations](#annotations)
- [PR mode](#pr-mode)
- [Live checks](#live-checks-opt-in)
- [Output and exit codes](#output-and-exit-codes)
- [Adopting it on an existing codebase](#adopting-it-on-an-existing-codebase)
- [Limits](#limits)

## Who it is for

A team of 5 to 15 engineers with several services, no platform team, and
config typed by hand into more than one hosting platform. If you already run
Kubernetes with a secret operator, you have better tools.

## What it catches

**A base URL that is really an endpoint.** A service base URL was set to a
full endpoint path. Every client appended its own path on top, so every
request 404'd on a doubled path. Nothing crashed, so nobody noticed for
months.

```
SERVICE     VARIABLE                     WHERE                       PROBLEM                                      FIX
----------  ---------------------------  --------------------------  -------------------------------------------  ------------------------------
storefront  NEXT_PUBLIC_BILLING_API_URL  storefront/.env.example:3   "http://localhost:4002/v1/invoices" has the  set NEXT_PUBLIC_BILLING_API_
                                                                     resource path "/v1/invoices" after the       URL=http://localhost:4002/v1
                                                                     origin; clients append their own path to a
                                                                     base URL, so requests hit a doubled or
                                                                     malformed path
```

**A variable set for `dev` and forgotten for `prod`.** The code needs a key to
call another service; the deploy manifest sets it in one environment only.

```
orders-api  INTERNAL_SERVICE_KEY  orders-api/copilot/orders-api/manifest.yml
            read in orders-api/src/config.ts:9 (required) but not set for environment prod
            fix: add INTERNAL_SERVICE_KEY to environments.prod.secrets
```

Every finding names the service, the variable, the file, the problem and the
exact fix.

## Quick start

Requires Node 22 or newer.

```bash
npx @akhil-misri/wirelint .                 # a monorepo
npx @akhil-misri/wirelint ../my-workspace   # a folder of sibling repos
```

The package is `@akhil-misri/wirelint`; the command it installs is `wirelint`.
To use the short name, add it to your project:

```bash
npm install --save-dev @akhil-misri/wirelint
npx wirelint .
```

The rest of this README writes `wirelint` for short.

In CI, findings land on the right line of the pull request:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 22 }
- run: npx @akhil-misri/wirelint .
```

Too many findings on day one? See
[Adopting it on an existing codebase](#adopting-it-on-an-existing-codebase).

## How it works

Every child directory with a `package.json` (or its own `.git`) is a service,
so it works on a monorepo and on a folder of sibling repos.

**It infers what each service reads** from source: `process.env.X`,
`process.env['X']`, destructuring, `import.meta.env.X`, NestJS
`configService.get('X')` and `getOrThrow('X')`, and the keys of zod, Joi and
envalid schemas. Tests, build output and one-off scripts are skipped.

**It collects what each service declares**, from files only: `.env.example`,
other `.env.*` files, `docker-compose*.yml`, AWS Copilot
`copilot/*/manifest.yml` (`variables`, `secrets`, per-environment overrides,
`env_file`), `vercel.json` and `Dockerfile` `ENV`.

**It compares the two**, and prints the service-to-service links it inferred
from local ports, so you can see who calls whom.

## Checks

These run on every invocation, with no setup.

| Check | Fails when |
| --- | --- |
| `missing-from-example` | code reads a variable that `.env.example` does not list |
| `missing-from-deploy` | code needs a variable that a deploy manifest does not set, named per environment |
| `url-shape` | a `*_URL` base is not an origin plus an optional `/api`, `/v1` or `/api/v1`: resource path, trailing slash, query or fragment |
| `prod-points-at-nonprod` | a production file or environment points at `localhost`, a dev, staging or preview host, a tunnel, or a Vercel preview deployment |
| `shared-secret` | never. It suggests that a same-named secret in two services, or one example value under two names, is probably one shared value |

**How strictly a missing variable is treated depends on how the code reads it.**

| The code does this | In `.env.example` check | In deploy-manifest check |
| --- | --- | --- |
| guards it: `getOrThrow`, schema-required, `!`, `if (!x) throw` | failure | failure |
| falls back to a localhost literal: `?? 'http://localhost:4000'` | failure | failure (it would silently point at localhost once deployed) |
| reads it bare, with nothing handling an unset value | failure | failure if `.env.example` lists it, otherwise a suggestion |
| has a default, compares it, or checks it before use | suggestion | not reported |

A validation schema wins when reads disagree, because it decides what the
running process actually sees.

**Fallback chains** count as one requirement, satisfied when any member is
set. `||` chains work the same way.

```ts
const identity = process.env.IDENTITY_URL ?? process.env.IDENTITY_API_URL ?? 'http://localhost:4100';
```

Neither variable is reported alone. When a deploy environment sets none of
them, the chain is reported once, as `IDENTITY_URL | IDENTITY_API_URL`.

**Exemptions built in.** Connection strings (`DATABASE_URL`, `REDIS_URL`, any
non-http scheme), single-endpoint variables (`*_WEBHOOK_URL`,
`*_CALLBACK_URL`, `*_REDIRECT_URI` and similar), templated or placeholder
values (`${HOST}`, `<your-url>`, `your-domain`), and platform variables
(`NODE_ENV`, `PORT`, `CI`, `GITHUB_*`, `VERCEL_*`, `AWS_REGION`, ...).

## Annotations

Optional. When inference cannot know something, say it in the service's own
`.env.example`, next to the variable: at the end of the line, or on the line
directly above. There is no central contract file.

```bash
JWT_SECRET=           # wirelint: same-as identity-api
INTERNAL_SERVICE_KEY= # wirelint: same-as billing-api.ORDERS_SERVICE_KEY
SENTRY_DSN=           # wirelint: optional -- only reported in prod

# wirelint: build-time
NEXT_PUBLIC_API_URL=http://localhost:4000
```

| Annotation | Effect |
| --- | --- |
| `same-as <service>` | this variable must hold the same value as the same-named one in `<service>` (`<service>.<NAME>` for a different name). Fails when `<service>` does not exist, stops declaring the variable, or sets it for a deploy environment this service does not. Values themselves are compared only with [`--compare`](#live-checks-opt-in). |
| `optional` | the variable may be absent from every deploy target |
| `build-time` | checked against build configuration (Dockerfile `ARG`/`ENV`, compose `build.args`, `vercel.json` `build.env`) instead of runtime manifests |

Several annotations are separated by commas. Anything after ` -- ` is a note
for humans and is ignored.

Annotations add these checks:

| Check | Fails when |
| --- | --- |
| `annotation-invalid` | an annotation has an unknown word, a `same-as` without a target, or is not attached to a variable |
| `same-as-unknown-service` | `same-as <service>` names a service that was not discovered |
| `same-as-undeclared` | the other service no longer declares the variable |
| `same-as-not-deployed` | the other service sets the variable for a deploy environment that this service does not |
| `missing-from-build` | a `build-time` variable is in none of the visible build configurations, and the service has a container deploy target (otherwise a suggestion) |

A typo is a failure, not a silent no-op:

```
web  FEATURE_FLAGS  web/.env.example:3  unknown wirelint annotation "optinal", so it is not honoured
                                        fix: write "optional" instead of "optinal"; put any explanation after " -- ",
                                             e.g. "# wirelint: optional -- only used in prod"
```

## PR mode

```bash
wirelint --pr [--base <ref>] [--comment-file <path>] [workspace-dir]
```

On a pull request, wirelint looks only at the variables the diff adds, and
says which deploy targets and environments do not set each one yet. The point
is to ask while the author still remembers the answer.

```
NEW IN THIS DIFF (1)
  orders-api  REFUNDS_SIGNING_KEY  added in orders-api/src/refunds.ts:1 (+1 more)
    not yet set in: orders-api/copilot/orders-api/manifest.yml (dev, prod)
```

`--comment-file` writes a Markdown comment body. wirelint never posts
anything itself; your own CI step does. The checkout needs history
(`fetch-depth: 0`), otherwise the run reports that it was not fully checked.

Workflow example, base-ref resolution and edge cases:
[docs/pr-mode.md](docs/pr-mode.md).

## Live checks (opt-in)

Everything above reads files only. These flags look at what is actually
deployed. They are off unless you pass them, and read-only: list, describe and
get calls, and GET requests for probes. Credentials come from the environment
only and are not stored.

```bash
wirelint --live ssm [--env prod] [--region eu-west-1] .   # SSM parameters the Copilot manifests reference exist
wirelint --live vercel [--vercel-project web=prj_123] .   # required variables are set in the Vercel project
wirelint --live ssm,vercel --compare .                    # same-as values are equal
wirelint --probe [--probe-path /health] .                 # each inferred link answers in production
```

| Flag | What it does | Needs |
| --- | --- | --- |
| `--live ssm` | checks that every SSM parameter a Copilot manifest references exists, per environment, without reading values | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, a region; `ssm:DescribeParameters` |
| `--live vercel` | checks that required variables are set for `production` in the Vercel project | `VERCEL_TOKEN`, a linked project |
| `--compare` | checks that both sides of a `same-as` relation hold the same deployed value | `--live`; `ssm:GetParameters` and `kms:Decrypt` for SSM |
| `--probe` | sends `GET /health` to each inferred link's production base URL and reports what answers | nothing |

**How values are compared.** Each value is reduced on arrival to an
HMAC-SHA256 digest under a random key that exists only for that run, and the
plaintext is dropped. Digests are compared in memory and never printed or
written, so nothing comparable outlives the run.

**Probes refuse private addresses** (loopback, RFC 1918, link-local and cloud
metadata) unless you pass `--probe-allow-private`, because the URL comes from
repo config. Probe results are suggestions unless you pass `--probe-strict`.

**A live check that cannot run is never a pass.** Missing credentials, access
denied, or nothing to check exits `2` and says why.

> **Status.** The live adapters were built against the documented AWS SSM and
> Vercel REST APIs and tested with simulated responses only. They have not yet
> been run against a real account by this project. Please report what you see.

IAM policies, token scopes, every rule and example failures:
[docs/live-checks.md](docs/live-checks.md).

## Secrets

wirelint never prints a secret. Values are kept only for example files. For
every other file the value is reduced at read time to a few facts (is it a
URL, is its shape wrong, what kind of host does it point at) and then
dropped. Findings from those files describe the problem without quoting the
value. Live values are handled as described above.

## Output and exit codes

```bash
wirelint [workspace-dir]            # table: service, variable, where, problem, fix
wirelint --json [workspace-dir]     # the same report as JSON
wirelint --no-hints [workspace-dir] # hide suggestions
wirelint --no-baseline [workspace-dir] # ignore the baseline file
wirelint --help
```

| Exit code | Meaning |
| --- | --- |
| `0` | no failures (there may be suggestions) |
| `1` | at least one failure |
| `2` | usage error, or a requested PR or live check that could not run |

When `GITHUB_ACTIONS` is set it also emits `::error file=...,line=...`
annotations.

## Adopting it on an existing codebase

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

## Limits

- **Without `--live`, it checks files, not what is deployed.** A variable set
  only in a dashboard is invisible, and for a service deployed on Vercel the
  deploy-manifest check does not run at all.
- **JavaScript and TypeScript services only.**
- **Deploy targets it understands:** AWS Copilot manifests, production compose
  files and Vercel. No Kubernetes or Helm.
- **Secrets Manager is never read.** Those references are listed as not
  checked.
- **Inference is pattern-based, not a type checker.** Known gap: a guard that
  returns early before a second variable is read can make that second variable
  look required.
- **Computed reads** such as `process.env[name]` cannot be analysed. They are
  listed once per service and never fail the run.
- No dashboards, no hosted service, no secret syncing, no auto-fixing.

## Development

```bash
npm install
npm test      # builds, then runs the Vitest suite against synthetic fixtures
node dist/cli.js test/fixtures/shop
```

TypeScript, Node 22 or newer, no runtime dependencies. See
[ROADMAP.md](ROADMAP.md) for what is shipped and what is not planned.

## License

MIT

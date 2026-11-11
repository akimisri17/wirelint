# Live checks (opt-in)

Off unless you ask, per run. Every flag is read-only: wirelint makes only
list, describe and get calls, and GET requests for probes. It never creates,
updates or deletes anything. Credentials are read from the environment only,
used for the request and not stored.

```bash
wirelint --live ssm [--env prod] [--region eu-west-1] .      # SSM parameters the Copilot manifests reference exist
wirelint --live vercel [--vercel-project web=prj_123] .      # required variables are set in the Vercel project
wirelint --live ssm,vercel --compare .                       # same-as values are equal, compared as keyed digests
wirelint --probe [--probe-path /health] [--probe-strict] [--probe-allow-private] .  # each inferred link answers in production
```

The adapters were built against the documented AWS SSM and Vercel REST APIs
and tested with simulated responses only (a fake `fetch` that answers in the
documented shapes, including pagination, throttling and errors). They have not
been run against a real account by this project yet.

## `--live ssm`

Reads `secrets:` in each Copilot manifest, top-level and per
environment, with `${COPILOT_ENVIRONMENT_NAME}` and
`${COPILOT_APPLICATION_NAME}` (from `copilot/.workspace`) filled in, and SSM
parameter ARNs. Environments come from the manifest's `environments:` block
and `copilot/environments/`; `--env` restricts them. It asks
`DescribeParameters` with a name filter, which returns names and metadata and
never values. Credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and,
for temporary credentials, `AWS_SESSION_TOKEN`; region from `--region`, else
`AWS_REGION`, else `AWS_DEFAULT_REGION` (an ARN's own region wins for that
parameter). Secrets Manager references (`secretsmanager:` or an ARN) and
anything it cannot resolve are listed as not checked, never failed. So is an
SSM ARN that names an account: wirelint does not ask which account the
credentials belong to, so "not found" there would prove nothing (an ARN with an
empty account field is checked).

Copilot environments often live in different accounts or regions. When a
manifest has several environments and the run has no `--env`, a parameter the
credentials do not find is a suggestion whose fix is to re-run with
`--env <name>` and that environment's credentials and region. With `--env`, or
when the manifest has exactly one environment, it fails. A manifest with no
`environments:` block is treated as production only.

### IAM policy

The minimum IAM policy for existence checks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ssm:DescribeParameters", "Resource": "*" }
  ]
}
```

`--compare` additionally needs to read values, so scope it to the parameters
and the key that encrypts them:

```json
{ "Effect": "Allow", "Action": "ssm:GetParameters", "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/copilot/<app>/*" },
{ "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "<arn of the KMS key the parameters use>" }
```

## `--live vercel`

Applies to services with a `vercel.json`, a
`.vercel/project.json` (written by `vercel link`) or a `--vercel-project
<service>=<projectId>`. It lists the project's variables with
`GET /v10/projects/{id}/env`: keys, targets and types, not decrypted; any value
in the answer is dropped when it is parsed. The documented answer is either
`{ envs, pagination: { count, next, prev } }`, where `next` is a timestamp for
the next page or null, or `{ envs, hiddenProductionEnvCount }`. The docs name
no query parameter for that timestamp; wirelint sends it as `until`. Listing
stops when `next` is absent or null. A page that adds no new variable while
`next` is still set, more than 50 pages, or a non-zero
`hiddenProductionEnvCount` makes the check incomplete (exit `2`), never a
pass.

A required variable (graded exactly like `missing-from-deploy`, plus `build-time` variables, because one
Vercel store serves both) that is not set for `production` fails; gaps in
`preview` and `development` are suggestions. Token: `VERCEL_TOKEN`. Team:
`--vercel-team`, else the `orgId` in `.vercel/project.json`, else
`VERCEL_TEAM_ID`. Create the token under Account Settings > Tokens, scoped to
the team that owns the projects. Vercel tokens cannot be made read-only, so
keep it in your CI secrets even though wirelint only sends GET requests. A
Vercel service with no linked project is a note with the fix, not a failure;
but if no Vercel service could be checked at all, the check is incomplete.

## `--compare`

Needs `--live`. Compares both sides of every `same-as`
relation, and of every `shared-secret` suggestion, in each environment both
sides have (a Copilot production environment meets the Vercel `production`
target). Each value is reduced on arrival to an HMAC-SHA256 digest under a
random 32-byte key that is generated once per run and kept only in memory, and
the plaintext is dropped. The digests are compared in constant time and never
printed or written, and because the key dies with the run, nothing comparable
outlives it. A difference fails for a declared `same-as` and is a suggestion
for an inferred pair. Vercel `sensitive` variables cannot be read back by
design, so for them only existence is reported. In `--json`, a relation's
`compared` becomes `value` or `unreadable`. A declared `same-as` that could not
be compared in any environment (one side is in no store the run read, or the
sides share no environment) makes the run incomplete and names the relation
and why, and so does any value that could not be fetched. When two values
differ, wirelint also compares digests with one trailing `\n` or `\r\n`
removed; if those match, the finding says the values differ only by a trailing
newline. Nothing else about the values is ever told.

## `--probe`

Works with or without `--live`. Takes, for each inferred link,
the base URL the calling service uses in production (a deploy target's
production environment, else `vercel.json`, else a production `.env` file,
never a local or example one) and sends `GET <base><--probe-path>`,
default `/health`. http and https only, a timeout (`--probe-timeout`,
default 5 seconds), no redirects followed, no cookies, credentials or custom
headers, only `User-Agent: wirelint`. Results name the variable, never the
URL or host. A probe from a laptop that cannot reach a service proves nothing
(private DNS, a VPC, an allowlist), so results are suggestions;
`--probe-strict` makes DNS failure, connection refused and 5xx answers fail,
for a runner that sits inside the network.

### Address guard

Because the URL comes from repo config, a probe could otherwise aim a CI
runner at its own metadata service or internal network. Before sending, wirelint
resolves the host (every A and AAAA answer) and refuses the probe if any answer,
or an IP literal in the URL, is not a public address: loopback, private (RFC
1918, unique local), link-local (including `169.254.169.254` and
`fd00:ec2::254`), CGNAT, `0.0.0.0` and other reserved ranges, and IPv6 forms
that embed such an IPv4 address (mapped, compatible, NAT64, 6to4). Decimal,
hex and octal hosts such as `http://2130706433/` are checked as the URL parser
normalises them. A refused link is `probe-not-checked` with the reason
"private address"; the address is never printed. `--probe-allow-private`
turns the guard off, for a runner inside the network that should reach
private services. `--probe-path` must be a plain path: it starts with `/`, has
no scheme, host, query, fragment or `.`/`..` segment.

Known limit: the check resolves the name, then `fetch` resolves it again to
connect. A DNS server that answers differently the second time (DNS
rebinding) can still steer one probe to a private address. The probe sends
only a GET with no credentials and reads only the status code, but if that
matters, run probes from a runner with no access to anything private.

## When a check cannot run

wirelint says so at the top of the report
(`LIVE CHECK INCOMPLETE`), on stderr and as a GitHub warning, and exits `2`:
missing or rejected credentials, access denied, an unreachable endpoint,
throttling that did not stop after bounded retries, an answer in a shape the
docs do not describe (`MalformedResponse`), or nothing to check at all (an
adapter that found no reference or project it could check). Failures still
exit `1`. Upstream error messages are never quoted, only an error code such
as `AccessDeniedException`, because they can contain account ids and ARNs. An
unexpected internal error prints a fixed message, never its text or stack.

## Example failures and fixes

```
orders  JWT_SECRET  orders/copilot/orders/manifest.yml  (live-missing, env dev, with --env dev)
        secrets.JWT_SECRET references an SSM parameter that does not exist in eu-west-1 for
        environment dev; tasks that need it fail to start
        fix: create the parameter that secrets.JWT_SECRET in orders/copilot/orders/manifest.yml
             names, in eu-west-1 (copilot secret init --name JWT_SECRET creates and tags it), or
             correct the reference

web     NEXT_PUBLIC_SITE_NAME  web/.vercel/project.json  (live-missing, env production)
        read in web/src/api.ts:3 (no default) but the Vercel project does not set it for production
        fix: in web, run "vercel env add NEXT_PUBLIC_SITE_NAME production" (or add it under
             Settings > Environment Variables)

orders  JWT_SECRET  orders/.env.example:2  (live-mismatch, env prod)
        declared same-as identity.JWT_SECRET, but the deployed values differ for prod (orders: the
        SSM parameter secrets.JWT_SECRET in orders/copilot/orders/manifest.yml names; identity: the
        SSM parameter secrets.JWT_SECRET in identity/copilot/identity/manifest.yml names)
        fix: copy the prod value of identity.JWT_SECRET into orders.JWT_SECRET, or point both at one
             parameter; wirelint compared keyed digests and shows neither value

web     ORDERS_API_URL  web/.env.production  (probe-unreachable, with --probe-strict)
        GET /health on the production ORDERS_API_URL (web/.env.production, prod) refused the connection
        fix: check that ORDERS_API_URL in web/.env.production names the production host and port of
             orders; if orders is reachable only inside its network, run the probe from there
```

| Check | With | Fails when |
| --- | --- | --- |
| `live-missing` | `--live ssm` | a manifest references an SSM parameter that does not exist for an environment |
| `live-missing` | `--live vercel` | a required variable is not set for `production` in the Vercel project (other targets: suggestion) |
| `live-mismatch` | `--compare` | a declared `same-as` pair holds different deployed values (an inferred pair: suggestion) |
| `probe-unreachable` | `--probe` | never, unless `--probe-strict` and DNS fails or the connection is refused |
| `probe-status` | `--probe` | never, unless `--probe-strict` and the answer is a 5xx |
| `live-not-checked`, `probe-not-checked` | | never; a note saying what was not checked and why |

## JSON and PR mode

`--json` gains a `live` section (adapters with `complete`, `requests`,
`problem` and `fix`; per-variable `checks`; `comparisons` with `equal`,
`different`, `unreadable` or `not-checked`) and a `probe` section (per link:
variable, status class and HTTP code). Neither ever holds a value, a digest,
a token, a parameter name or an address. With `--pr`, live and probe findings
are filtered to the variables the diff adds, like every other finding, and
appear in the comment body.

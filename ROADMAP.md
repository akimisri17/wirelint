# Roadmap

v0 is inference only: it reads code and config files and needs nothing from
you. Each later step is opt-in and adds only what inference cannot know.

## Shipped

### v1 (0.2.0): say what inference cannot guess

**Annotations in each service's own `.env.example`.** No central contract
file. The annotation sits next to the variable it describes, in the repo that
owns it.

```bash
JWT_SECRET=           # wirelint: same-as identity-api
SENTRY_DSN=           # wirelint: optional
NEXT_PUBLIC_API_URL=  # wirelint: build-time
```

| Annotation | Effect |
| --- | --- |
| `same-as <service>` | turns the shared-secret suggestion into a declared relation, and a failure when one side stops declaring it |
| `optional` | the variable may be absent from any deploy target |
| `build-time` | checked against build configuration instead of runtime configuration |

**PR mode.** On a pull request, look only at variables the diff adds, and
say which deploy targets and environments each one is not yet set in. The
comment body is written to a file; posting it is left to the user's CI step.

**Fallback chains** across several variables are resolved, so
`A ?? B ?? 'http://localhost'` fails only when none of them is set.

Value equality for `same-as` is not checked in v1. The relation is kept in
the JSON report (`relations`, with `compared: "existence"`) for v2.

### v2 (0.3.0): look at what is actually deployed, opt-in

Off by default, enabled per run, read-only, with credentials supplied by the
caller through the environment.

**Live adapters for AWS SSM and Vercel** (`--live ssm`, `--live vercel`).

- Existence checks by default: does every SSM parameter a Copilot manifest
  references exist for each environment (`DescribeParameters`, names only),
  and is every required variable set for production in the Vercel project
  (keys and targets, not decrypted).
- Value comparison only on request (`--compare`), only in memory, and only as
  a per-run keyed HMAC. Two services' values are compared by digest; the key
  is random per run and discarded, so nothing comparable is ever written or
  printed. Vercel sensitive variables cannot be read back, so existence is
  the most an adapter reports for them.

**Probe mode** (`--probe`). Calls each inferred dependency's health URL from
the resolved production base URL and reports what answers, by variable name
and status class only. It tests the wiring end to end without reading a
single secret. Results are suggestions unless `--probe-strict`.

Built against the documented APIs and tested with simulated responses.

## Not planned

Kubernetes and Helm, a hosted dashboard, secret syncing, and auto-fixing. Other
tools do these well, and each would turn a checker into a platform.

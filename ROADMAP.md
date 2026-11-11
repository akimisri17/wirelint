# Roadmap

v0 is inference only: it reads code and config files and needs nothing from
you. Each later step is opt-in and adds only what inference cannot know.

## v1: say what inference cannot guess

**Optional annotations in each service's own `.env.example`.** No central
contract file. The annotation sits next to the variable it describes, in the
repo that owns it.

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
comment which deploy targets and environments each one is not yet set in. The
point is to ask the question while the author still remembers the answer.

Also in v1: resolve fallback chains across several variables, so
`A ?? B ?? 'http://localhost'` fails only when none of them is set.

## v2: look at what is actually deployed, opt-in

**Live adapters for AWS SSM and Vercel.** Off by default, enabled per run,
read-only credentials supplied by the caller.

- Existence checks by default: is the parameter there, for this environment.
- Value comparison only on request, only in memory, and only as a per-run
  keyed HMAC. Two services' values are compared by digest; the key is random
  per run and discarded, so nothing comparable is ever written or printed.

**Probe mode.** Vercel sensitive variables cannot be read back, so existence
is the most an adapter can report for them. Probe mode instead calls each
inferred dependency's health URL from the resolved base URL and reports what
answers. It tests the wiring end to end without reading a single secret.

## Not planned

Kubernetes and Helm, a hosted dashboard, secret syncing, and auto-fixing. Other
tools do these well, and each would turn a checker into a platform.

import { createHash } from 'node:crypto';
import path from 'node:path';
import { collectCompose, collectCopilot, collectDockerfile, collectEnvFiles, collectPackagePorts, collectVercel } from './collect.js';
import { discoverServices } from './discover.js';
import { readText, rel, walkSources } from './fsutil.js';
import { isBaseUrlVar, isListVar, isLocationVar, isPlatformVar, isProdName, isProvidedByTarget, isSecretLooking, isVendorVar } from './names.js';
import { scanSource } from './reads.js';
import type { Annotation, AnnotationKind, BuildConfig, DeclaredVar, DeployTarget, Edge, EnvRead, FallbackChain, Finding, ReadKind, Relation, Service, Severity, ShapeCode } from './types.js';
import { isPlaceholder, redact } from './url.js';

export interface Analysis {
  workspace: string;
  services: Service[];
  edges: Edge[];
  annotations: Annotation[];
  relations: Relation[];
  findings: Finding[];
  suppressed: number;
  /** Shared-secret suggestions as pairs, for an opt-in value comparison. In memory only. */
  candidates: SecretPair[];
}

/** Two variables a shared-secret suggestion says probably hold one value. */
export interface SecretPair {
  a: { service: string; variable: string };
  b: { service: string; variable: string };
}

const KIND_NOTE: Record<ReadKind, string> = {
  required: 'required',
  localdefault: 'falls back to a localhost default',
  plain: 'no default',
  flag: 'optional',
  default: 'has a code default',
};

interface VarUse {
  name: string;
  kind: ReadKind;
  first: EnvRead;
}

function loadServices(workspace: string): Service[] {
  const locations = discoverServices(workspace);
  const allDirs = new Set(locations.map((l) => l.dir));
  const services: Service[] = [];
  const sourcePorts = new Map<Service, Set<number>>();
  for (const loc of locations) {
    const svc: Service = {
      ...loc,
      reads: [],
      dynamicReads: [],
      envFiles: [],
      targets: [],
      baked: new Set(),
      ports: new Set(),
      composePorts: new Set(),
      scriptPorts: new Set(),
      aliases: new Set(),
      suppress: new Map(),
      badSuppressions: [],
      annotations: [],
      badAnnotations: [],
      chains: [],
      build: [],
      filesScanned: 0,
    };
    collectEnvFiles(workspace, svc);
    collectCopilot(workspace, svc);
    collectVercel(workspace, svc);
    collectDockerfile(workspace, svc);
    collectPackagePorts(svc);

    const exclude = new Set([...allDirs].filter((d) => d !== svc.dir));
    const fromSource = new Set<number>();
    for (const abs of walkSources(svc.dir, exclude)) {
      const text = readText(abs, 600_000);
      if (text === null) continue;
      svc.filesScanned++;
      const scan = scanSource(text);
      const file = rel(workspace, abs);
      for (const r of scan.reads) svc.reads.push({ ...r, file });
      for (const c of scan.chains) svc.chains.push({ ...c, file });
      for (const line of scan.dynamic) svc.dynamicReads.push({ file, line });
      for (const p of scan.ports) fromSource.add(p);
    }
    sourcePorts.set(svc, fromSource);
    services.push(svc);
  }
  collectCompose(workspace, services);

  // A service's local port, from the most to the least authoritative source.
  for (const svc of services) {
    const portIn = (example: boolean): number[] =>
      svc.envFiles
        .filter((f) => f.isExample === example && (f.envName === 'local' || f.envName === 'dev'))
        .map((f) => f.vars.get('PORT')?.facts?.port)
        .filter((p): p is number => !!p);
    const tiers = [portIn(false), portIn(true), [...svc.composePorts], [...svc.scriptPorts], [...(sourcePorts.get(svc) ?? [])]];
    for (const p of tiers.find((t) => t.length > 0) ?? []) svc.ports.add(p);
  }
  return services;
}

/**
 * One verdict per variable. A validation schema is authoritative; otherwise an
 * explicit guard wins, then a localhost fallback, then any sign that the code
 * copes with the variable being unset.
 */
function usesOf(svc: Service): Map<string, VarUse> {
  const byName = new Map<string, EnvRead[]>();
  for (const r of svc.reads) {
    if (isPlatformVar(r.name)) continue;
    if (!byName.has(r.name)) byName.set(r.name, []);
    byName.get(r.name)!.push(r);
  }
  const uses = new Map<string, VarUse>();
  for (const [name, all] of byName) {
    const schema = all.filter((r) => r.schema);
    const pool = schema.length ? schema : all;
    const pick = (k: ReadKind) => pool.find((r) => r.kind === k);
    const first = pick('required') ?? pick('localdefault') ?? pick('default') ?? pick('flag') ?? pool[0]!;
    uses.set(name, { name, kind: first.kind, first });
  }
  return uses;
}

/** One verdict per distinct chain, picked the same way as for a single variable. */
function chainsOf(svc: Service): FallbackChain[] {
  const byKey = new Map<string, FallbackChain[]>();
  for (const c of svc.chains) {
    const key = c.names.join('|');
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key)!.push(c);
  }
  return [...byKey.values()]
    .map((all) => {
      const pick = (k: ReadKind) => all.find((c) => c.kind === k);
      return pick('required') ?? pick('localdefault') ?? pick('default') ?? pick('flag') ?? all[0]!;
    })
    .sort((a, b) => a.names.join('|').localeCompare(b.names.join('|')));
}

/** Annotation words per variable. */
export function annotationsOf(svc: Service): Map<string, Set<AnnotationKind>> {
  const out = new Map<string, Set<AnnotationKind>>();
  for (const a of svc.annotations) {
    if (!out.has(a.variable)) out.set(a.variable, new Set());
    out.get(a.variable)!.add(a.kind);
  }
  return out;
}

/**
 * The deploy targets a service's runtime variables are checked against:
 * its workload manifests, plus any production compose file.
 */
export function deployTargetsOf(svc: Service): DeployTarget[] {
  return [...manifestsFor(svc).use, ...svc.targets.filter((t) => t.kind === 'compose' && t.envs.some((e) => isProdName(e.name)))];
}

/** A variable, or a fallback chain, that a deploy environment must set. */
export interface Requirement {
  /** One name, or the members of a fallback chain (any one satisfies it). */
  names: string[];
  kind: ReadKind;
  file: string;
  line: number;
  /** Graded like missing-from-deploy: true when its absence is a failure, false for a suggestion. */
  hard: boolean;
}

/**
 * What a deploy environment must set for this service, graded exactly like
 * missing-from-deploy: reads with a real default, optional annotations,
 * platform variables, Dockerfile ENV and suppressed names are left out.
 * `buildTime` keeps build-time variables, for platforms whose one variable
 * store serves both the build and the runtime (Vercel).
 */
export function requirementsOf(svc: Service, opts: { buildTime: boolean }): Requirement[] {
  const uses = usesOf(svc);
  const ann = annotationsOf(svc);
  const has = (name: string, kind: AnnotationKind) => ann.get(name)?.has(kind) ?? false;
  const exempt = (name: string) => has(name, 'optional') || (!opts.buildTime && has(name, 'build-time')) || svc.suppress.has(name) || svc.baked.has(name);
  const inExample = new Set(svc.envFiles.filter((f) => f.isExample).flatMap((f) => [...f.vars.keys()]));
  const individually = (name: string) => {
    const u = uses.get(name);
    return !!u && u.kind !== 'default' && u.kind !== 'flag' && !exempt(name);
  };
  const out: Requirement[] = [];
  for (const u of [...uses.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    if (u.kind === 'default' || u.kind === 'flag' || exempt(u.name)) continue;
    out.push({ names: [u.name], kind: u.kind, file: u.first.file, line: u.first.line, hard: u.kind !== 'plain' || inExample.has(u.name) });
  }
  for (const c of chainsOf(svc)) {
    if (c.kind === 'default' || c.kind === 'flag') continue;
    if (c.names.some((n) => isPlatformVar(n) || individually(n) || exempt(n))) continue;
    out.push({ names: c.names, kind: c.kind, file: c.file, line: c.line, hard: c.kind !== 'plain' || c.names.some((n) => inExample.has(n)) });
  }
  // Build-time names are annotated, not necessarily read in code.
  if (opts.buildTime) {
    for (const a of svc.annotations) {
      if (a.kind !== 'build-time' || exempt(a.variable) || isPlatformVar(a.variable) || out.some((r) => r.names.includes(a.variable))) continue;
      out.push({ names: [a.variable], kind: 'required', file: a.file, line: a.line, hard: true });
    }
  }
  return out;
}

/**
 * Resolve a same-as target: an exact service name, or a unique directory
 * basename (`api` for `apps/api`), optionally followed by `.<VARIABLE>`.
 */
function resolveTarget(services: Service[], raw: string, variable: string): { svc: Service; variable: string } | null {
  const byName = (name: string): Service | undefined => {
    const exact = services.find((s) => s.name === name);
    if (exact) return exact;
    const base = services.filter((s) => path.basename(s.dir) === name);
    return base.length === 1 ? base[0] : undefined;
  };
  const whole = byName(raw);
  if (whole) return { svc: whole, variable };
  const m = /^(.+)\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(raw);
  const svc = m ? byName(m[1]!) : undefined;
  return svc ? { svc, variable: m![2]! } : null;
}

/**
 * When a repo carries several workload manifests and exactly one is named
 * after the service, the others are treated as strays (copied or retired).
 */
function manifestsFor(svc: Service): { use: DeployTarget[]; skipped: DeployTarget[] } {
  const copilot = svc.targets.filter((t) => t.kind === 'copilot');
  if (copilot.length < 2) return { use: copilot, skipped: [] };
  const norm = (x: string) => x.toLowerCase().replace(/[^a-z0-9]/g, '');
  const dirName = norm(path.basename(svc.dir));
  const matching = copilot.filter((t) => dirName.includes(norm(t.name)) || norm(t.name).includes(dirName));
  return matching.length === 1 ? { use: matching, skipped: copilot.filter((t) => t !== matching[0]) } : { use: copilot, skipped: [] };
}

const SHAPE_PHRASE: Record<ShapeCode, string> = {
  'resource-path': 'has a resource path after the origin',
  'trailing-slash': 'ends with a trailing slash',
  query: 'carries a query string',
  fragment: 'carries a fragment',
};

export function analyze(workspaceArg: string): Analysis {
  const workspace = path.resolve(workspaceArg);
  const services = loadServices(workspace);
  const findings: Finding[] = [];
  const relations: Relation[] = [];
  let suppressed = 0;

  const push = (
    svc: Service | null,
    f: { check: string; severity: Severity; service?: string; variable: string; file: string; line?: number; env?: string; anchor?: string; problem: string; fix: string },
  ): void => {
    if (svc?.suppress.has(f.variable)) {
      suppressed++;
      return;
    }
    const service = f.service ?? svc?.name ?? '';
    const fingerprint = createHash('sha256')
      .update([f.check, service, f.variable, f.anchor ?? f.file, f.env ?? ''].join('|'))
      .digest('hex')
      .slice(0, 16);
    findings.push({
      fingerprint,
      check: f.check,
      severity: f.severity,
      service,
      variable: f.variable,
      file: f.file,
      line: f.line,
      env: f.env,
      problem: f.problem,
      fix: f.fix,
    });
  };

  for (const svc of services) {
    const uses = usesOf(svc);

    // --- suppression markers without a reason are themselves a failure
    for (const bad of svc.badSuppressions) {
      push(null, {
        check: 'suppression-without-reason',
        severity: 'error',
        service: svc.name,
        variable: bad.name ?? '(marker)',
        file: bad.file,
        line: bad.line,
        problem: 'wirelint-ignore marker has no reason, so it is not honoured',
        fix: 'write "# wirelint-ignore: <why this is safe to ignore>"',
      });
    }

    // --- annotations that cannot be honoured are themselves a failure
    for (const bad of svc.badAnnotations) {
      push(null, {
        check: 'annotation-invalid',
        severity: 'error',
        service: svc.name,
        variable: bad.name ?? '(annotation)',
        file: bad.file,
        line: bad.line,
        problem: `${bad.problem}, so it is not honoured`,
        fix: bad.fix,
      });
    }
    const ann = annotationsOf(svc);
    const has = (name: string, kind: AnnotationKind) => ann.get(name)?.has(kind) ?? false;
    /** Annotated as not checked against runtime deploy targets. */
    const runtimeExempt = (name: string) => has(name, 'optional') || has(name, 'build-time');

    // --- (a) read in code, absent from .env.example
    const examples = svc.envFiles.filter((f) => f.isExample);
    const inExample = new Set(examples.flatMap((f) => [...f.vars.keys()]));
    const svcRel = rel(workspace, svc.dir);
    const ownExample = examples.find((f) => path.posix.dirname(f.file) === svcRel) ?? examples[0];
    const active = [...uses.values()].sort((a, b) => a.name.localeCompare(b.name));
    if (examples.length === 0) {
      if (active.length > 0) {
        const names = active.map((u) => u.name);
        const shown = names.slice(0, 8).join(', ') + (names.length > 8 ? `, +${names.length - 8} more` : '');
        const target = svcRel === '.' ? '.env.example' : `${svcRel}/.env.example`;
        push(svc, {
          check: 'no-example-file',
          severity: 'error',
          variable: `(${names.length} variable${names.length === 1 ? '' : 's'})`,
          file: active[0]!.first.file,
          line: active[0]!.first.line,
          anchor: target,
          problem: `code reads ${names.length} variable${names.length === 1 ? '' : 's'} but the service has no .env.example: ${shown}`,
          fix: `create ${target} listing each name with a safe placeholder value`,
        });
      }
    } else {
      for (const u of active) {
        if (inExample.has(u.name)) continue;
        // A variable the code visibly copes without is worth documenting, not worth failing on.
        const optional = u.kind === 'default' || u.kind === 'flag';
        push(svc, {
          check: 'missing-from-example',
          severity: optional ? 'hint' : 'error',
          variable: u.name,
          file: u.first.file,
          line: u.first.line,
          anchor: ownExample!.file,
          problem: `read in code (${KIND_NOTE[u.kind]}) but not listed in ${ownExample!.file}`,
          fix: `add "${u.name}=<placeholder>" to ${ownExample!.file}`,
        });
      }
    }

    // --- (b) read in code, absent from a deploy manifest, per environment
    const { use: manifests, skipped } = manifestsFor(svc);
    for (const stray of skipped) {
      push(null, {
        check: 'manifest-skipped',
        severity: 'info',
        service: svc.name,
        variable: '(manifest)',
        file: stray.file,
        problem: `deploy manifest "${stray.name}" is not named after this service, so it was not checked: ${stray.file}`,
        fix: 'delete it if it is a stray copy',
      });
    }
    const deployTargets = deployTargetsOf(svc);
    /** `name|file|env` already reported missing, so a later check does not repeat it. */
    const reported = new Set<string>();
    const individually = (name: string) => {
      const u = uses.get(name);
      return !!u && u.kind !== 'default' && u.kind !== 'flag' && !runtimeExempt(name);
    };
    for (const target of deployTargets) {
      for (const u of active) {
        if (u.kind === 'default' || u.kind === 'flag' || runtimeExempt(u.name)) continue;
        if (svc.baked.has(u.name) || isProvidedByTarget(target.kind, u.name)) continue;
        const checkable = target.envs.filter((e) => !e.opaque);
        const missing = checkable.filter((e) => !e.vars.has(u.name)).map((e) => e.name);
        if (missing.length === 0) continue;
        const everywhere = missing.length === checkable.length;
        const envLabel =
          missing[0] === '*' ? 'any environment'
          : everywhere && missing.length > 1 ? `any environment (${missing.join(', ')})`
          : `environment${missing.length > 1 ? 's' : ''} ${missing.join(', ')}`;
        // An unguarded read only fails the run when the team has declared the
        // variable in .env.example; an undocumented one is reported by check (a).
        const hard = u.kind !== 'plain' || inExample.has(u.name);
        for (const env of missing) reported.add(`${u.name}|${target.file}|${env}`);
        push(svc, {
          check: 'missing-from-deploy',
          severity: hard ? 'error' : 'hint',
          variable: u.name,
          file: target.file,
          env: missing.join(','),
          problem:
            `read in ${u.first.file}:${u.first.line} (${KIND_NOTE[u.kind]}) but not set for ${envLabel}` +
            (u.kind === 'localdefault' ? '; once deployed it silently points at localhost' : ''),
          fix: fixForTarget(target, u.name, everywhere ? null : missing),
        });
      }

      // A fallback chain is satisfied when any member is set. Members that are
      // checked on their own (read somewhere without a fallback) are covered above.
      for (const c of chainsOf(svc)) {
        if (c.kind === 'default' || c.kind === 'flag') continue;
        if (c.names.some((n) => isPlatformVar(n) || individually(n) || runtimeExempt(n) || svc.suppress.has(n))) continue;
        const set = (n: string, vars: Map<string, DeclaredVar>) => vars.has(n) || svc.baked.has(n) || isProvidedByTarget(target.kind, n);
        const checkable = target.envs.filter((e) => !e.opaque);
        const missing = checkable.filter((e) => !c.names.some((n) => set(n, e.vars))).map((e) => e.name);
        if (missing.length === 0) continue;
        const everywhere = missing.length === checkable.length;
        const envLabel =
          missing[0] === '*' ? 'any environment'
          : everywhere && missing.length > 1 ? `any environment (${missing.join(', ')})`
          : `environment${missing.length > 1 ? 's' : ''} ${missing.join(', ')}`;
        const hard = c.kind !== 'plain' || c.names.some((n) => inExample.has(n));
        push(svc, {
          check: 'missing-from-deploy',
          severity: hard ? 'error' : 'hint',
          variable: c.names.join(' | '),
          file: target.file,
          env: missing.join(','),
          problem:
            `fallback chain ${c.names.join(' -> ')} read in ${c.file}:${c.line} (${KIND_NOTE[c.kind]}), but none of them is set for ${envLabel}` +
            (c.kind === 'localdefault' ? '; once deployed it silently points at localhost' : ''),
          fix: `${fixForTarget(target, c.names[0]!, everywhere ? null : missing)}; any one of ${c.names.join(', ')} satisfies the chain`,
        });
      }
    }

    // --- build-time variables are checked against build configuration instead
    const buildTime = [...ann].filter(([n, kinds]) => kinds.has('build-time') && !kinds.has('optional') && !isPlatformVar(n)).map(([n]) => n).sort();
    for (const name of buildTime) {
      const where = svc.annotations.find((a) => a.variable === name && a.kind === 'build-time')!;
      if (svc.build.length === 0) {
        push(svc, {
          check: 'missing-from-build',
          severity: 'hint',
          variable: name,
          file: where.file,
          line: where.line,
          problem: 'annotated build-time, but no build configuration (Dockerfile ARG/ENV, compose build.args, vercel.json build.env) is visible for this service',
          fix: `make sure ${name} is set where the build runs (the CI job or the hosting platform's build settings)`,
        });
        continue;
      }
      if (svc.build.some((b) => b.names.has(name))) continue;
      // Only a container deploy target shows that these build files are what
      // produces the deployed artifact; otherwise the build may happen elsewhere.
      const container = deployTargets.some((t) => t.kind === 'copilot' || t.kind === 'compose');
      push(svc, {
        check: 'missing-from-build',
        severity: container ? 'error' : 'hint',
        variable: name,
        file: svc.build[0]!.file,
        problem:
          `annotated build-time in ${where.file}:${where.line}, but not set in any build configuration: ${svc.build.map((b) => b.file).join(', ')}` +
          (container ? '' : '; no container deploy target is visible, so the deployed build may not use these files'),
        fix: svc.build.map((b) => fixForBuild(b, name)).join(', or ') + (container ? '' : `, or make sure ${name} is set where the deployed build runs`),
      });
    }

    // --- declared same-as relations
    for (const a of svc.annotations) {
      if (a.kind !== 'same-as' || !a.target) continue;
      const resolved = resolveTarget(services, a.target, a.variable);
      if (!resolved) {
        const others = services.filter((s) => s !== svc).map((s) => s.name);
        const shown = others.slice(0, 8).join(', ') + (others.length > 8 ? `, +${others.length - 8} more` : '');
        push(svc, {
          check: 'same-as-unknown-service',
          severity: 'error',
          variable: a.variable,
          file: a.file,
          line: a.line,
          problem: `same-as names "${a.target}", which is not a discovered service${others.length ? ` (found: ${shown})` : ''}`,
          fix: others.length ? `change it to "same-as <service>" with one of: ${shown}, or remove the annotation` : 'remove the annotation; no other service was found',
        });
        continue;
      }
      const { svc: other, variable: otherName } = resolved;
      if (other === svc && otherName === a.variable) {
        push(svc, {
          check: 'annotation-invalid',
          severity: 'error',
          variable: a.variable,
          file: a.file,
          line: a.line,
          problem: `same-as points at the variable itself (${svc.name}.${a.variable}), so it is not honoured`,
          fix: 'name the other service that must hold the same value',
        });
        continue;
      }
      relations.push({ kind: 'same-as', service: svc.name, variable: a.variable, file: a.file, line: a.line, target: { service: other.name, variable: otherName }, compared: 'existence' });

      const otherDeploy = deployTargetsOf(other);
      const declared =
        other.envFiles.some((f) => f.isExample && f.vars.has(otherName)) || other.targets.some((t) => t.envs.some((e) => e.vars.has(otherName)));
      if (!declared) {
        const otherRel = rel(workspace, other.dir);
        const otherExample = other.envFiles.find((f) => f.isExample && path.posix.dirname(f.file) === otherRel)?.file ?? (otherRel === '.' ? '.env.example' : `${otherRel}/.env.example`);
        push(svc, {
          check: 'same-as-undeclared',
          severity: 'error',
          variable: a.variable,
          file: a.file,
          line: a.line,
          problem: `declared same-as ${other.name}.${otherName}, but ${other.name} no longer declares ${otherName} in its .env.example or any deploy manifest`,
          fix: `add ${otherName} back to ${otherExample}, or remove the same-as annotation if ${svc.name} no longer shares it`,
        });
        continue;
      }
      if (runtimeExempt(a.variable) || svc.baked.has(a.variable)) continue;
      const otherHas = (env: string) =>
        otherDeploy.some((t) => t.envs.some((e) => (e.name === env || e.name === '*' || env === '*') && e.vars.has(otherName)));
      for (const target of deployTargets) {
        if (isProvidedByTarget(target.kind, a.variable)) continue;
        const checkable = target.envs.filter((e) => !e.opaque);
        const missing = checkable
          .filter((e) => !e.vars.has(a.variable) && otherHas(e.name) && !reported.has(`${a.variable}|${target.file}|${e.name}`))
          .map((e) => e.name);
        if (missing.length === 0) continue;
        const everywhere = missing.length === checkable.length;
        const envLabel = missing[0] === '*' ? 'its deploy target' : `environment${missing.length > 1 ? 's' : ''} ${missing.join(', ')}`;
        push(svc, {
          check: 'same-as-not-deployed',
          severity: 'error',
          variable: a.variable,
          file: target.file,
          env: missing.join(','),
          problem: `declared same-as ${other.name}.${otherName} in ${a.file}:${a.line}; ${other.name} sets it for ${envLabel}, but this deploy target does not set ${a.variable}`,
          fix: fixForTarget(target, a.variable, everywhere ? null : missing),
        });
      }
    }

    // --- (c) URL shape and (d) production pointing at non-production
    const seen = new Set<DeclaredVar>();
    // An env file is only the source of truth for production when no manifest ships it.
    const manifestShipsProd = manifests.some((t) => t.envs.some((e) => isProdName(e.name)));
    const sources: { file: string; env: string; prod: boolean; printable: boolean; isFile: boolean; vars: Iterable<DeclaredVar> }[] = [
      ...svc.envFiles.map((f) => ({ file: f.file, env: f.envName, prod: f.envName === 'prod' && !f.isExample, printable: f.isExample, isFile: true, vars: f.vars.values() })),
      ...svc.targets.flatMap((t) => t.envs.map((e) => ({ file: t.file, env: e.name, prod: isProdName(e.name), printable: false, isFile: false, vars: e.vars.values() }))),
    ];
    for (const src of sources) {
      for (const v of src.vars) {
        const facts = v.facts;
        if (!facts || facts.placeholder) continue;
        if (facts.shape && isBaseUrlVar(v.name) && !seen.has(v)) {
          seen.add(v);
          const phrases = facts.shape.codes.map((c) =>
            c === 'resource-path' && src.printable ? `has the resource path "${facts.shape!.path}" after the origin` : SHAPE_PHRASE[c],
          );
          const subject = src.printable && v.value !== undefined ? `"${redact(v.value)}" ` : 'value ';
          push(svc, {
            check: 'url-shape',
            severity: 'error',
            variable: v.name,
            file: src.file,
            line: v.line,
            problem: `${subject}${phrases.join(' and ')}; clients append their own path to a base URL, so requests hit a doubled or malformed path`,
            fix: src.printable
              ? `set ${v.name}=${redact(facts.shape.suggested)}`
              : `trim ${v.name} to scheme://host[:port] plus at most a version prefix (/api, /v1, /api/v1), no trailing slash`,
          });
        }
        if (src.prod && isLocationVar(v.name)) {
          const bad = facts.hosts.find((h) => h.klass !== 'ok');
          if (!bad) continue;
          const what =
            bad.klass === 'local' ? 'points at localhost'
            : bad.klass === 'tunnel' ? 'points at a temporary tunnel host'
            : bad.klass === 'vercel-preview' ? 'points at a Vercel preview deployment (*.vercel.app)'
            : bad.klass === 'vercel-default' ? 'points at a *.vercel.app default domain; confirm it is the production alias and not a preview'
            : `points at a host labelled "${bad.token}"`;
          push(svc, {
            check: 'prod-points-at-nonprod',
            severity: bad.klass === 'vercel-default' || isListVar(v.name) || (src.isFile && manifestShipsProd) ? 'hint' : 'error',
            variable: v.name,
            file: src.file,
            line: v.line,
            env: src.env,
            problem:
              `production config (${src.env}) ${what}${isListVar(v.name) ? ' in a list of origins' : ''}` +
              (src.isFile && manifestShipsProd ? '; this service also has a deploy manifest, so this file may not be what ships' : ''),
            fix: `set ${v.name} to the production host${isListVar(v.name) ? ', or remove the non-production entry' : ''}`,
          });
        }
      }
    }

    // --- dynamic reads: reported once, never a failure
    if (svc.dynamicReads.length > 0) {
      const d = svc.dynamicReads;
      const where = d.slice(0, 3).map((x) => `${x.file}:${x.line}`).join(', ') + (d.length > 3 ? `, +${d.length - 3} more` : '');
      push(null, {
        check: 'dynamic-read',
        severity: 'info',
        service: svc.name,
        variable: '(dynamic)',
        file: d[0]!.file,
        line: d[0]!.line,
        anchor: svc.name,
        problem: `${d.length} computed env read${d.length === 1 ? '' : 's'} cannot be analysed: ${where}`,
        fix: 'nothing to fix; these reads are simply not covered',
      });
    }
  }

  const edges = inferEdges(services);
  const candidates = sharedSecretHints(services, edges, relations, push);

  const rank: Record<Severity, number> = { error: 0, hint: 1, info: 2 };
  findings.sort(
    (a, b) => rank[a.severity] - rank[b.severity] || a.service.localeCompare(b.service) || a.check.localeCompare(b.check) || a.variable.localeCompare(b.variable),
  );
  const annotations = services.flatMap((s) => s.annotations);
  return { workspace, services, edges, annotations, relations, findings, suppressed, candidates };
}

function fixForBuild(b: BuildConfig, name: string): string {
  if (b.kind === 'dockerfile') return `add "ARG ${name}" to ${b.file}`;
  if (b.kind === 'compose') return `add ${name} to services.${b.name}.build.args in ${b.file}`;
  return `add ${name} to "build.env" in ${b.file}`;
}

function fixForTarget(target: DeployTarget, name: string, envs: string[] | null): string {
  if (target.kind === 'compose') return `add ${name} to services.${target.name}.environment (or its env_file)`;
  if (target.kind === 'vercel') return `add ${name} to "env" in ${target.file}, or set it in the Vercel project and drop the env block`;
  const block = isSecretLooking(name) ? 'secrets' : 'variables';
  const where = envs && envs[0] !== '*' ? envs.map((e) => `environments.${e}.${block}`).join(' and ') : `the top-level "${block}:" block`;
  return `add ${name} to ${where}`;
}

/** Edge A -> B when one of A's local URLs targets a port (or compose hostname) that belongs to B. */
function inferEdges(services: Service[]): Edge[] {
  const edges = new Map<string, Edge>();
  for (const svc of services) {
    const sources: { file: string; printable: boolean; vars: Iterable<DeclaredVar> }[] = [
      ...svc.envFiles.filter((f) => f.isExample || f.envName === 'local' || f.envName === 'dev').map((f) => ({ file: f.file, printable: f.isExample, vars: f.vars.values() })),
      ...svc.targets.filter((t) => t.kind === 'compose').flatMap((t) => t.envs.filter((e) => !isProdName(e.name)).map((e) => ({ file: t.file, printable: false, vars: e.vars.values() }))),
    ];
    for (const src of sources) {
      for (const v of src.vars) {
        if (!v.facts || !isLocationVar(v.name)) continue;
        for (const h of v.facts.hosts) {
          let targets: Service[] = [];
          if (h.klass === 'local' && h.port) targets = services.filter((s) => s !== svc && s.ports.has(h.port!));
          else if (h.klass !== 'local') targets = services.filter((s) => s !== svc && s.aliases.has(h.host));
          if (targets.length !== 1) continue;
          const key = `${svc.name}>${targets[0]!.name}>${v.name}`;
          const existing = edges.get(key);
          if (existing && (existing.port !== undefined || !src.printable)) continue;
          edges.set(key, { from: svc.name, to: targets[0]!.name, variable: v.name, file: src.file, port: src.printable ? h.port : undefined });
        }
      }
    }
  }
  return [...edges.values()].sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to) || a.variable.localeCompare(b.variable));
}

type Push = (svc: Service | null, f: { check: string; severity: Severity; service?: string; variable: string; file: string; line?: number; env?: string; anchor?: string; problem: string; fix: string }) => void;

/** Suggestions only: secrets that two services probably need to agree on. */
function sharedSecretHints(services: Service[], edges: Edge[], relations: Relation[], push: Push): SecretPair[] {
  const pairs: SecretPair[] = [];
  const related = (a: Service, an: string, b: Service, bn: string) =>
    relations.some(
      (r) =>
        (r.service === a.name && r.variable === an && r.target.service === b.name && r.target.variable === bn) ||
        (r.service === b.name && r.variable === bn && r.target.service === a.name && r.target.variable === an),
    );
  const holders = new Map<string, Set<Service>>();
  const note = (name: string, svc: Service): void => {
    if (!isSecretLooking(name) || isPlatformVar(name) || isVendorVar(name) || svc.suppress.has(name)) return;
    if (!holders.has(name)) holders.set(name, new Set());
    holders.get(name)!.add(svc);
  };
  for (const svc of services) {
    for (const r of svc.reads) note(r.name, svc);
    for (const f of svc.envFiles) for (const name of f.vars.keys()) note(name, svc);
    for (const t of svc.targets) for (const e of t.envs) for (const name of e.vars.keys()) note(name, svc);
  }
  const connected = (a: Service, b: Service) => edges.some((e) => (e.from === a.name && e.to === b.name) || (e.from === b.name && e.to === a.name));

  for (const [name, set] of [...holders].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (set.size < 2) continue;
    const list = [...set].sort((a, b) => a.name.localeCompare(b.name));
    // A declared same-as relation replaces the guess when it links every holder.
    const reached = new Set([list[0]!]);
    for (let grew = true; grew; ) {
      grew = false;
      for (const s of list) if (!reached.has(s) && [...reached].some((r) => related(r, name, s, name))) grew = reached.add(s).size > 0;
    }
    if (reached.size === list.length) continue;
    for (const s of list.slice(1)) if (!related(list[0]!, name, s, name)) pairs.push({ a: { service: list[0]!.name, variable: name }, b: { service: s.name, variable: name } });
    const notes: string[] = [];
    if (list.some((a) => list.some((b) => a !== b && connected(a, b)))) notes.push('at least two of them call each other');
    const exampleValues = list
      .map((s) => s.envFiles.find((f) => f.isExample && f.vars.get(name)?.value !== undefined)?.vars.get(name)?.value)
      .filter((v): v is string => v !== undefined && !isPlaceholder(v));
    if (exampleValues.length >= 2 && new Set(exampleValues).size > 1) notes.push('their example values already differ');
    const refs = new Set(
      list.flatMap((s) => s.targets.flatMap((t) => t.envs.map((e) => e.vars.get(name)?.ref).filter((r): r is string => !!r))),
    );
    if (refs.size > 1) notes.push('their deploy manifests reference different secret-store entries, so the values can drift');
    const declaredIn = list.flatMap((s) => s.envFiles.filter((f) => f.isExample && f.vars.has(name)))[0];
    push(null, {
      check: 'shared-secret',
      severity: 'hint',
      service: list.map((s) => s.name).join(' + '),
      variable: name,
      file: declaredIn?.file ?? '',
      line: declaredIn?.vars.get(name)?.line,
      anchor: '',
      problem: `same-named secret in ${list.length} services; it is probably meant to hold one shared value${notes.length ? ` (${notes.join('; ')})` : ''}`,
      fix: `confirm every listed service resolves ${name} to the same value in each environment; v0 reads files only and cannot compare live stores`,
    });
  }

  // Same example value under different names (example files only).
  const byValue = new Map<string, { svc: Service; name: string; file: string; line: number }[]>();
  for (const svc of services) {
    for (const f of svc.envFiles) {
      if (!f.isExample) continue;
      for (const v of f.vars.values()) {
        if (v.value === undefined || v.value.length < 8 || isPlaceholder(v.value) || !isSecretLooking(v.name) || svc.suppress.has(v.name)) continue;
        if (!byValue.has(v.value)) byValue.set(v.value, []);
        byValue.get(v.value)!.push({ svc, name: v.name, file: f.file, line: v.line });
      }
    }
  }
  for (const group of byValue.values()) {
    const first = group[0]!;
    const other = group.find((g) => g.svc !== first.svc && g.name !== first.name && !related(first.svc, first.name, g.svc, g.name));
    if (!other) continue;
    pairs.push({ a: { service: first.svc.name, variable: first.name }, b: { service: other.svc.name, variable: other.name } });
    push(null, {
      check: 'shared-secret',
      severity: 'hint',
      service: `${first.svc.name} + ${other.svc.name}`,
      variable: `${first.name} / ${other.name}`,
      file: first.file,
      line: first.line,
      anchor: '',
      problem: `${first.name} (${first.svc.name}) and ${other.name} (${other.svc.name}) have the same example value; they are probably one secret under two names`,
      fix: 'confirm both resolve to the same value in each environment, and consider giving them one name',
    });
  }
  return pairs;
}

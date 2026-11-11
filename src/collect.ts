import path from 'node:path';
import { parseEnv } from './dotenv.js';
import { childDirs, isDir, listDir, readJson, readText, rel } from './fsutil.js';
import { isLocationVar } from './names.js';
import type { DeclaredVar, DeployTarget, EnvFile, EnvName, Service, TargetEnv } from './types.js';
import { factsOf } from './url.js';
import { asList, asMap, asString, parseYaml, type Yaml } from './yaml.js';

const ENV_FILE_RE = /^\.env(\.[\w.-]+)?$|^(?:[\w-]+\.)?env\.(?:example|sample|template)$/;
const BACKUP_RE = /\.(bak|backup|orig|old|save|swp|tmp|vault|enc|gpg)(\.|$)|~$/i;
const EXAMPLE_RE = /(^|\.)(example|sample|template|dist|defaults)(\.|$)/i;

function envNameOf(file: string): EnvName {
  const tokens = file.toLowerCase().split(/[.\-_]/);
  const has = (...names: string[]) => names.some((n) => tokens.includes(n));
  if (has('production', 'prod', 'prd', 'live')) return 'prod';
  if (has('staging', 'stage', 'stg', 'preview')) return 'staging';
  if (has('test', 'testing', 'ci')) return 'test';
  if (has('development', 'dev')) return 'dev';
  return 'local';
}

/**
 * The single place a raw value becomes a DeclaredVar. Values are kept only for
 * example files; everywhere else they are reduced to derived facts and dropped.
 */
export function declare(name: string, raw: string | null, line: number, printable: boolean): DeclaredVar {
  const v: DeclaredVar = { name, line };
  if (raw === null) return v;
  if (printable) v.value = raw;
  if (isLocationVar(name) || name === 'PORT') v.facts = factsOf(name, raw);
  return v;
}

function lineOfKey(text: string, name: string): number {
  const m = new RegExp(`^[ \\t]*(?:-[ \\t]*)?["']?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?[ \\t]*[:=]`, 'm').exec(text);
  return m ? text.slice(0, m.index).split('\n').length : 1;
}

export function collectEnvFiles(workspace: string, svc: Service): void {
  const dirs = svc.parentDir ? [svc.dir, svc.parentDir] : [svc.dir];
  for (const dir of dirs) {
    for (const e of listDir(dir)) {
      if (!e.isFile() || !ENV_FILE_RE.test(e.name) || BACKUP_RE.test(e.name) || e.name === '.envrc') continue;
      const abs = path.join(dir, e.name);
      const text = readText(abs);
      if (text === null) continue;
      const isExample = EXAMPLE_RE.test(e.name);
      const file = rel(workspace, abs);
      const parsed = parseEnv(text);
      const vars = new Map<string, DeclaredVar>();
      for (const entry of parsed.entries) {
        // Disabled entries document a variable only in example files.
        if (entry.commented && !isExample) continue;
        if (vars.has(entry.name) && entry.commented) continue;
        const v = declare(entry.name, entry.commented ? null : entry.value, entry.line, isExample);
        if (entry.commented) v.commented = true;
        vars.set(entry.name, v);
      }
      svc.envFiles.push({ file, isExample, envName: envNameOf(e.name), vars });
      if (isExample) {
        for (const ig of parsed.ignores) svc.suppress.set(ig.name, { reason: ig.reason, file, line: ig.line });
        for (const bad of parsed.badIgnores) svc.badSuppressions.push({ file, line: bad.line, name: bad.name });
      }
    }
  }
  svc.envFiles.sort((a, b) => a.file.localeCompare(b.file));
}

/** Names declared by an env file on disk, or null when the file is not there. */
function namesInEnvFile(abs: string, into: Map<string, DeclaredVar>): boolean {
  const text = readText(abs);
  if (text === null) return false;
  for (const entry of parseEnv(text).entries) {
    if (!entry.commented && !into.has(entry.name)) into.set(entry.name, declare(entry.name, entry.value, entry.line, false));
  }
  return true;
}

function varsFromYaml(node: Yaml | undefined, text: string, into: Map<string, DeclaredVar>, asRef: boolean): void {
  const map = asMap(node);
  if (map) {
    for (const [name, value] of Object.entries(map)) {
      const literal = asString(value);
      const v = declare(name, asRef ? null : literal, lineOfKey(text, name), false);
      if (asRef) v.ref = literal ?? JSON.stringify(value);
      into.set(name, v);
    }
    return;
  }
  // docker-compose list form: `- KEY=value` or `- KEY`
  for (const item of asList(node)) {
    const s = asString(item);
    if (!s) continue;
    const eq = s.indexOf('=');
    const name = (eq === -1 ? s : s.slice(0, eq)).trim();
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) into.set(name, declare(name, eq === -1 ? null : s.slice(eq + 1), lineOfKey(text, name), false));
  }
}

function envFileRefs(node: Yaml | undefined): string[] {
  if (asString(node)) return [asString(node)!];
  return asList(node)
    .map((item) => asString(item) ?? asString(asMap(item)?.['path']))
    .filter((s): s is string => !!s);
}

/** AWS Copilot workload manifests: copilot/<workload>/manifest.yml */
export function collectCopilot(workspace: string, svc: Service): void {
  const root = path.join(svc.dir, 'copilot');
  if (!isDir(root)) return;
  const knownEnvs = childDirs(path.join(root, 'environments')).map((d) => path.basename(d));
  for (const dir of childDirs(root)) {
    const base = path.basename(dir);
    if (base === 'environments' || base === 'pipelines') continue;
    const abs = path.join(dir, 'manifest.yml');
    const text = readText(abs);
    const doc = text === null ? null : asMap(parseYaml(text));
    if (!text || !doc || /environment|pipeline/i.test(asString(doc['type']) ?? '')) continue;

    const common = new Map<string, DeclaredVar>();
    varsFromYaml(doc['variables'], text, common, false);
    varsFromYaml(doc['secrets'], text, common, true);
    let opaque: string | undefined;
    for (const ref of envFileRefs(doc['env_file'])) {
      if (!namesInEnvFile(path.resolve(svc.dir, ref), common)) opaque = `env_file "${ref}" is not in the checkout`;
    }
    // Sidecars share the task; add-on stack outputs are injected as variables.
    for (const out of addonOutputs(path.join(dir, 'addons'))) svc.baked.add(out);

    const overrides = asMap(doc['environments']) ?? {};
    const envNames = [...new Set([...Object.keys(overrides), ...knownEnvs])];
    const envs: TargetEnv[] = (envNames.length ? envNames : ['*']).map((name) => {
      const vars = new Map(common);
      const ov = asMap(overrides[name]);
      let envOpaque = opaque;
      if (ov) {
        varsFromYaml(ov['variables'], text, vars, false);
        varsFromYaml(ov['secrets'], text, vars, true);
        for (const ref of envFileRefs(ov['env_file'])) {
          if (!namesInEnvFile(path.resolve(svc.dir, ref), vars)) envOpaque = `env_file "${ref}" is not in the checkout`;
        }
      }
      return { name, vars, opaque: envOpaque };
    });
    svc.targets.push({ kind: 'copilot', file: rel(workspace, abs), name: asString(doc['name']) ?? base, envs });
  }
}

function addonOutputs(dir: string): string[] {
  const out: string[] = [];
  for (const e of listDir(dir)) {
    if (!e.isFile() || !/\.ya?ml$/.test(e.name)) continue;
    const text = readText(path.join(dir, e.name));
    const outputs = text ? asMap(asMap(parseYaml(text))?.['Outputs']) : null;
    // Copilot injects each output as SCREAMING_SNAKE_CASE.
    for (const key of Object.keys(outputs ?? {})) out.push(key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toUpperCase());
  }
  return out;
}

/** vercel.json only counts as a deploy target when it declares an env block. */
export function collectVercel(workspace: string, svc: Service): void {
  const abs = path.join(svc.dir, 'vercel.json');
  const doc = readJson(abs);
  if (!doc) return;
  const text = readText(abs) ?? '';
  const vars = new Map<string, DeclaredVar>();
  const take = (obj: unknown): void => {
    if (!obj || typeof obj !== 'object') return;
    for (const [name, value] of Object.entries(obj as Record<string, unknown>)) {
      vars.set(name, declare(name, typeof value === 'string' ? value : null, lineOfKey(text, name), false));
    }
  };
  take(doc['env']);
  take((doc['build'] as { env?: unknown } | undefined)?.env);
  if (vars.size > 0) svc.targets.push({ kind: 'vercel', file: rel(workspace, abs), name: 'vercel', envs: [{ name: '*', vars }] });
}

export function collectDockerfile(svc: Service): void {
  for (const e of listDir(svc.dir)) {
    if (!e.isFile() || !/^Dockerfile(\..+)?$/.test(e.name)) continue;
    const text = readText(path.join(svc.dir, e.name));
    if (!text) continue;
    for (const m of text.replace(/\\\r?\n/g, ' ').matchAll(/^[ \t]*ENV[ \t]+(.+)$/gim)) {
      const body = m[1]!;
      if (body.includes('=')) for (const kv of body.matchAll(/([A-Za-z_][A-Za-z0-9_]*)=/g)) svc.baked.add(kv[1]!);
      else svc.baked.add(body.trim().split(/\s+/)[0]!);
    }
  }
}

const COMPOSE_RE = /^(docker-)?compose([.\-][\w.-]+)?\.ya?ml$/;

/**
 * docker-compose files in the workspace root, a monorepo root or a service
 * directory. Each compose service is matched to a discovered service by its
 * build context, falling back to its name.
 */
export function collectCompose(workspace: string, services: Service[]): void {
  const dirs = new Set<string>([workspace]);
  for (const s of services) {
    dirs.add(s.dir);
    if (s.parentDir) dirs.add(s.parentDir);
  }
  const byDir = new Map(services.map((s) => [s.dir, s]));
  for (const dir of dirs) {
    for (const e of listDir(dir)) {
      if (!e.isFile() || !COMPOSE_RE.test(e.name)) continue;
      const abs = path.join(dir, e.name);
      const text = readText(abs);
      const doc = text ? asMap(parseYaml(text)) : null;
      const composeServices = asMap(doc?.['services']);
      if (!text || !composeServices) continue;
      const envName = envNameOf(e.name);
      for (const [name, raw] of Object.entries(composeServices)) {
        const def = asMap(raw);
        if (!def) continue;
        const build = def['build'];
        const context = asString(build) ?? asString(asMap(build)?.['context']);
        // Match by build context first, then by directory name. Image-only
        // services (databases, caches) are infrastructure, not ours.
        let svc = context ? byDir.get(path.resolve(dir, context)) : undefined;
        if (!svc && (build !== undefined || !def['image'])) svc = services.find((s) => path.basename(s.dir) === name);
        if (!svc) continue;

        svc.aliases.add(name);
        const containerName = asString(def['container_name']);
        if (containerName) svc.aliases.add(containerName);
        for (const p of asList(def['ports'])) {
          const published = asString(asMap(p)?.['published']);
          const spec = asString(p);
          const m = spec ? /^(?:[\d.]+:)?(\d{2,5}):\d+/.exec(spec.replace(/\$\{[^}:]+:-(\d+)\}/g, '$1')) : null;
          const port = Number(published ?? m?.[1]);
          if (port > 0) svc.composePorts.add(port);
        }

        const vars = new Map<string, DeclaredVar>();
        let opaque: string | undefined;
        for (const ref of envFileRefs(def['env_file'])) {
          if (!namesInEnvFile(path.resolve(dir, ref), vars)) opaque = `env_file "${ref}" is not in the checkout`;
        }
        const own = new Map<string, DeclaredVar>();
        varsFromYaml(def['environment'], text, own, false);
        for (const [k, v] of own) vars.set(k, v);
        if (vars.size === 0 && !opaque) continue;
        const target: DeployTarget = {
          kind: 'compose',
          file: rel(workspace, abs),
          name,
          envs: [{ name: envName === 'local' ? 'compose' : envName, vars, opaque }],
        };
        svc.targets.push(target);
      }
    }
  }
}

export function collectPackagePorts(svc: Service): void {
  const pkg = readJson(path.join(svc.dir, 'package.json'));
  const scripts = pkg?.['scripts'];
  if (!scripts || typeof scripts !== 'object') return;
  for (const name of ['dev', 'start', 'start:dev', 'serve', 'preview']) {
    const cmd = (scripts as Record<string, unknown>)[name];
    if (typeof cmd !== 'string') continue;
    for (const m of cmd.matchAll(/(?:\s-p|--port|\bPORT)[ =](\d{2,5})\b/g)) svc.scriptPorts.add(Number(m[1]));
  }
}


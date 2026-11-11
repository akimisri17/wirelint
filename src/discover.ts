import path from 'node:path';
import { childDirs, isDir, isFile, readJson, readText, rel } from './fsutil.js';
import { asList, asMap, asString, parseYaml } from './yaml.js';

export interface ServiceLocation {
  name: string;
  dir: string;
  parentDir?: string;
}

const hasPkg = (dir: string) => isFile(path.join(dir, 'package.json'));
const isRepo = (dir: string) => isDir(path.join(dir, '.git')) || isFile(path.join(dir, '.git'));

/** Packages of a monorepo rooted at `dir`, from its workspace config or the usual layout. */
function workspaceMembers(dir: string): string[] {
  const patterns: string[] = [];
  const pkg = readJson(path.join(dir, 'package.json'));
  const ws = pkg?.['workspaces'];
  const list = Array.isArray(ws) ? ws : Array.isArray((ws as { packages?: unknown })?.packages) ? (ws as { packages: unknown[] }).packages : [];
  for (const p of list) if (typeof p === 'string') patterns.push(p);
  const pnpm = readText(path.join(dir, 'pnpm-workspace.yaml'));
  if (pnpm) for (const p of asList(asMap(parseYaml(pnpm))?.['packages'])) if (asString(p)) patterns.push(asString(p)!);
  if (patterns.length === 0) patterns.push('apps/*', 'packages/*', 'services/*');

  const found = new Set<string>();
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) continue;
    const star = pattern.indexOf('*');
    if (star === -1) {
      const d = path.join(dir, pattern);
      if (hasPkg(d)) found.add(d);
      continue;
    }
    const base = path.join(dir, pattern.slice(0, star));
    for (const d of childDirs(base)) if (hasPkg(d)) found.add(d);
  }
  return [...found].sort();
}

/**
 * A service is a child directory with a package.json or its own git repo.
 * Works for a folder of sibling repos, a monorepo, and a mix of the two.
 */
export function discoverServices(workspace: string): ServiceLocation[] {
  const out = new Map<string, ServiceLocation>();
  const add = (dir: string, parentDir?: string): void => {
    if (!out.has(dir)) out.set(dir, { name: dir === workspace ? path.basename(workspace) : rel(workspace, dir), dir, parentDir });
  };
  const hasOwnCode = (dir: string) => isDir(path.join(dir, 'src')) || isFile(path.join(dir, '.env.example'));

  const rootMembers = hasPkg(workspace) ? workspaceMembers(workspace) : [];
  for (const m of rootMembers) add(m, workspace);

  for (const kid of childDirs(workspace)) {
    if (!hasPkg(kid) && !isRepo(kid)) continue;
    const members = workspaceMembers(kid);
    for (const m of members) add(m, kid);
    if (members.length === 0 || hasOwnCode(kid)) add(kid);
  }

  if (hasPkg(workspace) && (out.size === 0 || isDir(path.join(workspace, 'src')))) add(workspace);
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

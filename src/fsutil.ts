import fs from 'node:fs';
import path from 'node:path';

export function readText(file: string, maxBytes = 1_000_000): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > maxBytes) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

export function readJson(file: string): Record<string, unknown> | null {
  const text = readText(file);
  if (text === null) return null;
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function isDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

export function listDir(dir: string): fs.Dirent[] {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

export function childDirs(dir: string): string[] {
  return listDir(dir)
    .filter((e) => e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules')
    .map((e) => path.join(dir, e.name))
    .sort();
}

/** POSIX-style path of `file` relative to `root`. */
export function rel(root: string, file: string): string {
  return path.relative(root, file).split(path.sep).join('/') || '.';
}

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', 'out', 'coverage', 'vendor', 'public', 'static', 'tmp', 'temp', 'android', 'ios',
  'storybook-static', 'cdk.out', '__generated__', 'generated', 'target', 'venv', '__pycache__', 'assets',
]);
const TEST_DIRS = new Set(['test', 'tests', '__tests__', '__mocks__', 'e2e', 'cypress', 'playwright', 'spec', 'specs', 'mocks']);
/** One-off tooling, wherever it sits. */
const TOOLING_DIRS = new Set(['seed', 'seeds', 'seeders', 'migrations', 'fixtures', 'benchmark', 'benchmarks']);
/** Tooling only when it sits at the service root (src/prisma/ is runtime code). */
const ROOT_TOOLING_DIRS = new Set(['scripts', 'script', 'tools', 'tooling', 'bin', 'prisma', 'examples', 'docs', 'infra', 'cdk', 'terraform']);
/** Scratch and compiler-output directories under any name: tmp-build, dist-server, tsc-out. */
const OUTPUT_DIR = /^(?:tmp|temp|dist|build|out)[-_.]|[-_.](?:out|dist|build|tmp)$/i;
const SOURCE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const TEST_FILE = /(?:\.(?:test|spec|e2e|e2e-spec|stories|bench)\.[cm]?[jt]sx?$)|(?:^(?:jest|vitest|playwright|cypress|karma|wdio)\.[\w.]*$)|(?:^setupTests\.)|(?:\.d\.[cm]?ts$)|(?:\.min\.js$)/;

const TOOLING_FILE = /^(?:(?:prisma|drizzle|typeorm|mikro-orm|codegen)\.config|knexfile|ormconfig)\.[cm]?[jt]s$/;

/**
 * Runtime source files under `dir`. Tests, build output, one-off scripts,
 * seeds and migration tooling are skipped: they are not what gets deployed.
 */
export function walkSources(dir: string, exclude: Set<string>): string[] {
  const out: string[] = [];
  const visit = (d: string, depth: number): void => {
    if (depth > 14) return;
    for (const e of listDir(d)) {
      const abs = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name.startsWith('.') || SKIP_DIRS.has(e.name) || OUTPUT_DIR.test(e.name) || TEST_DIRS.has(e.name) || TOOLING_DIRS.has(e.name) || exclude.has(abs)) continue;
        if (depth === 0 && ROOT_TOOLING_DIRS.has(e.name)) continue;
        visit(abs, depth + 1);
      } else if (e.isFile() && SOURCE_EXT.test(e.name) && !TEST_FILE.test(e.name) && !TOOLING_FILE.test(e.name)) {
        out.push(abs);
      }
    }
  };
  visit(dir, 0);
  return out;
}

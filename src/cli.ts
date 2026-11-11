#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { BASELINE_FILE, loadBaseline, renderGithub, renderHuman, run, version, writeBaseline } from './index.js';

const HELP = `wirecheck ${version()}
Catch cross-service environment-variable mistakes before deploy. Reads files only:
no cloud credentials, no network, and it never prints a value from a non-example file.

Usage
  wirecheck [workspace-dir]            check a monorepo or a folder of sibling repos
  wirecheck baseline [workspace-dir]   accept current findings into ${BASELINE_FILE}

Options
  --json          machine-readable report on stdout
  --no-hints      hide suggestions in the human report
  --no-baseline   ignore ${BASELINE_FILE}
  -h, --help      show this help
  -v, --version   show the version

Exit codes: 0 no failures (suggestions never fail), 1 failures, 2 usage error.
Suppress one variable in a service's .env.example, reason required:
  LEGACY_CATALOG_URL=https://catalog.example.test/v1/items.xml  # wirecheck-ignore: third-party catalog, full path is intended
`;

function main(argv: string[]): number {
  const flags = new Set(argv.filter((a) => a.startsWith('-')));
  const args = argv.filter((a) => !a.startsWith('-'));
  const known = new Set(['--json', '--no-hints', '--no-baseline', '-h', '--help', '-v', '--version']);
  const unknown = [...flags].find((f) => !known.has(f));
  if (unknown) {
    process.stderr.write(`wirecheck: unknown option ${unknown}\n\n${HELP}`);
    return 2;
  }
  if (flags.has('-h') || flags.has('--help')) {
    process.stdout.write(HELP);
    return 0;
  }
  if (flags.has('-v') || flags.has('--version')) {
    process.stdout.write(version() + '\n');
    return 0;
  }
  const baselineMode = args[0] === 'baseline';
  if (baselineMode) args.shift();
  if (args.length > 1) {
    process.stderr.write(`wirecheck: expected one workspace directory, got ${args.length}\n`);
    return 2;
  }
  const workspace = path.resolve(args[0] ?? '.');
  if (!fs.existsSync(workspace) || !fs.statSync(workspace).isDirectory()) {
    process.stderr.write(`wirecheck: ${workspace} is not a directory\n`);
    return 2;
  }

  if (baselineMode) {
    const { file, count } = writeBaseline(workspace, run(workspace).findings);
    process.stdout.write(`wirecheck: wrote ${count} finding${count === 1 ? '' : 's'} to ${file}\nCommit it. From now on only new findings fail.\n`);
    return 0;
  }

  const report = run(workspace, flags.has('--no-baseline') ? new Set() : loadBaseline(workspace));
  if (report.services.length === 0) {
    process.stderr.write(`wirecheck: no services found under ${workspace} (looked for child directories with a package.json or a .git)\n`);
    return 2;
  }
  if (flags.has('--json')) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderHuman(report, { width: process.stdout.columns, hints: !flags.has('--no-hints') }) + '\n');
    if (process.env.GITHUB_ACTIONS) {
      const annotations = renderGithub(report, process.env.GITHUB_WORKSPACE ?? process.cwd());
      if (annotations) process.stdout.write(annotations + '\n');
    }
  }
  return report.summary.failures > 0 ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));

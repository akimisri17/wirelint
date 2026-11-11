import fs from 'node:fs';
import path from 'node:path';
import type { Finding } from './types.js';

export const BASELINE_FILE = '.wirelint-baseline.json';

interface BaselineDoc {
  version: 1;
  note: string;
  findings: { fingerprint: string; check: string; service: string; variable: string; file: string }[];
}

/** Fingerprints accepted by an earlier `wirelint baseline`, or an empty set. */
export function loadBaseline(workspace: string): Set<string> {
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(workspace, BASELINE_FILE), 'utf8')) as BaselineDoc;
    return new Set((doc.findings ?? []).map((f) => f.fingerprint));
  } catch {
    return new Set();
  }
}

/** Record current failures and suggestions. Names and paths only, never values. */
export function writeBaseline(workspace: string, findings: Finding[]): { file: string; count: number } {
  const kept = findings.filter((f) => f.severity !== 'info');
  const doc: BaselineDoc = {
    version: 1,
    note: 'Findings accepted when wirelint was adopted. Delete entries as you fix them; new findings still fail.',
    findings: kept.map((f) => ({ fingerprint: f.fingerprint, check: f.check, service: f.service, variable: f.variable, file: f.file })),
  };
  const file = path.join(workspace, BASELINE_FILE);
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
  return { file, count: kept.length };
}

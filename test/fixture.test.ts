import { describe, expect, it } from 'vitest';
import { renderGithub, renderHuman, run } from '../src/index.js';
import { find, fixture } from './helpers.js';

describe('fixture: four sibling services', () => {
  const report = run(fixture('shop'));
  const got = report.findings.map((f) => `${f.severity} ${f.check} ${f.service} ${f.variable}`);

  it('discovers every sibling service', () => {
    expect(report.services.map((s) => s.name)).toEqual(['billing-api', 'mailer', 'orders-api', 'storefront']);
    expect(report.services.find((s) => s.name === 'orders-api')!.deployTargets).toEqual([
      { kind: 'copilot', file: 'orders-api/copilot/orders-api/manifest.yml', environments: ['dev', 'prod'] },
    ]);
  });

  it('reports exactly the planted mistakes', () => {
    expect(got.sort()).toEqual(
      [
        'error missing-from-deploy billing-api PAYOUT_ACCOUNT',
        'error missing-from-example billing-api PAYOUT_ACCOUNT',
        'error prod-points-at-nonprod billing-api DOCS_ORIGIN',
        'error suppression-without-reason billing-api OLD_FLAG',
        'error no-example-file mailer (3 variables)',
        'error missing-from-deploy orders-api INTERNAL_SERVICE_KEY',
        'error missing-from-deploy orders-api SEARCH_API_URL',
        'error url-shape orders-api MAILER_URL',
        'error missing-from-example storefront NEXT_PUBLIC_ANALYTICS_ID',
        'error prod-points-at-nonprod storefront NEXT_PUBLIC_BILLING_API_URL',
        'error prod-points-at-nonprod storefront NEXT_PUBLIC_ORDERS_API_URL',
        'error url-shape storefront NEXT_PUBLIC_BILLING_API_URL',
        'error url-shape storefront NEXT_PUBLIC_SITE_URL',
        'hint missing-from-example billing-api TAX_RATE',
        'hint missing-from-example orders-api LOG_FORMAT',
        'hint shared-secret billing-api + orders-api JWT_SECRET',
        'hint shared-secret billing-api + orders-api ORDERS_SERVICE_KEY / INTERNAL_SERVICE_KEY',
        'info dynamic-read storefront (dynamic)',
      ].sort(),
    );
    expect(report.summary).toMatchObject({ failures: 13, suggestions: 4, notes: 1, suppressed: 1 });
  });

  it('names the environment a variable is missing from', () => {
    expect(find(report, 'missing-from-deploy', 'INTERNAL_SERVICE_KEY')[0]).toMatchObject({ env: 'prod', fix: 'add INTERNAL_SERVICE_KEY to environments.prod.secrets' });
    expect(find(report, 'missing-from-deploy', 'SEARCH_API_URL')[0]).toMatchObject({ env: 'dev,prod', fix: 'add SEARCH_API_URL to the top-level "variables:" block' });
  });

  it('infers who calls whom from local ports', () => {
    expect(report.edges.map((e) => `${e.from}>${e.to}`)).toEqual(['orders-api>billing-api', 'orders-api>mailer', 'storefront>billing-api', 'storefront>orders-api']);
  });

  it('never prints a value from a non-example file, in any output', () => {
    const outputs = [JSON.stringify(report), renderHuman(report), renderGithub(report, fixture('shop'))].join('\n');
    for (const secret of ['NEVER-PRINT', 'orders-staging.example.test', 'mailer.example.test', 'billing-preview', 'sentry.example.test', '/copilot/shop', 'smtp.example.test']) {
      expect(outputs, secret).not.toContain(secret);
    }
    // Example-file values are fair game: they are what makes the fix exact.
    expect(outputs).toContain('http://localhost:4002/v1');
  });

  it('renders a human table with the five promised columns', () => {
    const text = renderHuman(report, { width: 160 });
    expect(text).toMatch(/SERVICE\s+VARIABLE\s+WHERE\s+PROBLEM\s+FIX/);
    expect(text).toContain('FAILURES (13)');
    expect(text).toContain('SUGGESTIONS (4)');
    expect(text).toContain('storefront -> orders-api  via NEXT_PUBLIC_ORDERS_API_URL (port 4001)');
    expect(text).toContain('13 failures, 4 suggestions');
    expect(renderHuman(report, { hints: false })).not.toContain('SUGGESTIONS');
  });

  it('emits GitHub annotations with paths relative to the repository root', () => {
    const lines = renderGithub(report, fixture('')).split('\n');
    expect(lines).toContain(
      '::error file=shop/storefront/.env.example,line=4,title=wirecheck url-shape%3A NEXT_PUBLIC_SITE_URL::[storefront] NEXT_PUBLIC_SITE_URL "http://localhost:3000/" ends with a trailing slash; clients append their own path to a base URL, so requests hit a doubled or malformed path. Fix: set NEXT_PUBLIC_SITE_URL=http://localhost:3000',
    );
    expect(lines.filter((l) => l.startsWith('::error '))).toHaveLength(13);
    expect(lines.filter((l) => l.startsWith('::notice '))).toHaveLength(4);
  });
});

describe('fixture: monorepo', () => {
  const report = run(fixture('monorepo'));

  it('discovers workspace packages and lets them inherit the root .env.example', () => {
    expect(report.services.map((s) => s.name)).toEqual(['apps/api', 'apps/web', 'packages/config']);
    expect(report.findings.filter((f) => f.severity === 'error')).toEqual([]);
  });

  it('reads import.meta.env and envalid schemas, skipping Vite built-ins', () => {
    expect(report.services.find((s) => s.name === 'apps/web')!.variablesRead).toBe(1);
    expect(find(report, 'missing-from-example').map((f) => [f.service, f.variable, f.severity])).toEqual([['apps/api', 'REGION', 'hint']]);
  });

  it('links the web app to the api through the port in its dev script', () => {
    expect(report.edges.map((e) => `${e.from}>${e.to}:${e.variable}`)).toContain('apps/web>apps/api:VITE_API_URL');
  });
});

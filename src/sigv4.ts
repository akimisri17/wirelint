import { createHash, createHmac } from 'node:crypto';

/**
 * AWS Signature Version 4, hand-written so wirelint needs no AWS SDK.
 * Only what a JSON-protocol POST and a plain GET need: no chunked payloads,
 * no presigned URLs, no S3 path rules.
 */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SignInput {
  method: string;
  url: URL;
  /** Headers to sign besides host and x-amz-date (names in any case). */
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  now: Date;
}

const sha256hex = (data: string): string => createHash('sha256').update(data, 'utf8').digest('hex');
const hmac = (key: Buffer | string, data: string): Buffer => createHmac('sha256', key).update(data, 'utf8').digest();

/** RFC 3986 percent-encoding, as SigV4 requires (unreserved: A-Z a-z 0-9 - _ . ~). */
export function rfc3986(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** 20150830T123600Z */
export function amzDate(now: Date): string {
  return now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

export function signingKey(secret: string, date: string, region: string, service: string): Buffer {
  return hmac(hmac(hmac(hmac(`AWS4${secret}`, date), region), service), 'aws4_request');
}

export function canonicalRequest(method: string, url: URL, headers: Record<string, string>, body: string): { text: string; signed: string } {
  const segments = url.pathname.split('/').map((s) => rfc3986(decodeURIComponent(s)));
  const pathPart = segments.join('/') || '/';
  const query = [...url.searchParams]
    .map(([k, v]) => [rfc3986(k), rfc3986(v)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const entries = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), v.trim().replace(/\s+/g, ' ')] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const signed = entries.map(([k]) => k).join(';');
  const text = [method, pathPart, query, entries.map(([k, v]) => `${k}:${v}\n`).join(''), signed, sha256hex(body)].join('\n');
  return { text, signed };
}

/**
 * The headers to send: the input headers plus host, x-amz-date, the session
 * token when there is one, and Authorization. The secret key is used only
 * here, to derive the signing key, and is not stored.
 */
export function signV4(input: SignInput, creds: AwsCredentials): Record<string, string> {
  const stamp = amzDate(input.now);
  const date = stamp.slice(0, 8);
  const headers: Record<string, string> = { ...input.headers, host: input.url.host, 'x-amz-date': stamp };
  if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;
  const { text, signed } = canonicalRequest(input.method, input.url, headers, input.body);
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', stamp, scope, sha256hex(text)].join('\n');
  const signature = createHmac('sha256', signingKey(creds.secretAccessKey, date, input.region, input.service)).update(toSign, 'utf8').digest('hex');
  headers['authorization'] = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`;
  return headers;
}

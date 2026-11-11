export const identity = process.env.IDENTITY_URL ?? process.env.IDENTITY_API_URL ?? 'http://localhost:4100';
export const sentry = process.env.SENTRY_DSN;
export const assets = process.env.PUBLIC_ASSET_HOST;
export const internalKey = process.env.GATEWAY_INTERNAL_KEY;
export function verify(token: string): boolean {
  if (process.env.JWT_SECRET) return token.length > 0;
  return false;
}

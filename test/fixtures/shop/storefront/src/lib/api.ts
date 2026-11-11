const orders = process.env.NEXT_PUBLIC_ORDERS_API_URL;
const billing = process.env.NEXT_PUBLIC_BILLING_API_URL;
const analytics = process.env.NEXT_PUBLIC_ANALYTICS_ID;
const isProd = process.env.NODE_ENV === 'production';

// process.env.COMMENTED_OUT_ONLY is mentioned in a comment and must not count.
export function flag(name: string): string | undefined {
  return process.env[`NEXT_PUBLIC_FLAG_${name}`];
}

export const api = { orders, billing, analytics, isProd, session: process.env.SESSION_SECRET };

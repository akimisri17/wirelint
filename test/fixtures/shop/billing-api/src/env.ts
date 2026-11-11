import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(16),
  ORDERS_SERVICE_KEY: z.string(),
  STRIPE_SECRET_KEY: z.string(),
  TAX_RATE: z.coerce.number().default(0.2),
  PAYOUT_ACCOUNT: z
    .string()
    .min(4),
});

export const env = schema.parse(process.env);

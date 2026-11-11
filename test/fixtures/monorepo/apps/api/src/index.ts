import { cleanEnv, str, url } from 'envalid';

export const env = cleanEnv(process.env, {
  API_URL: url(),
  SHARED_TOKEN: str(),
  REGION: str({ default: 'eu-west-1' }),
});

/**
 * Name-based classification. Everything here looks at variable NAMES only.
 */

const IGNORED_EXACT = new Set([
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'CI', 'TZ', 'HOME', 'PATH', 'PWD', 'USER', 'SHELL', 'TERM', 'LANG',
  'LC_ALL', 'TMPDIR', 'TEMP', 'TMP', 'DEBUG', 'NODE_OPTIONS', 'NODE_DEBUG', 'NODE_PATH', 'FORCE_COLOR', 'NO_COLOR',
  'COLORTERM', 'JEST_WORKER_ID', 'VITEST', 'VERCEL', 'NETLIFY', 'DYNO', 'RENDER', 'CODESPACES', 'GITPOD_WORKSPACE_ID',
  'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_EXECUTION_ENV', 'AWS_PROFILE', 'NEXT_RUNTIME', 'NEXT_PHASE', 'TURBOPACK',
  'ANALYZE', 'LOG_LEVEL', 'EDITOR', 'APPDATA', 'USERPROFILE', 'XDG_CONFIG_HOME', 'INIT_CWD', 'PM2_HOME',
  // Vite built-ins on import.meta.env
  'MODE', 'DEV', 'PROD', 'SSR', 'BASE_URL',
]);

const IGNORED_PREFIX = [
  'npm_', 'GITHUB_', 'RUNNER_', 'VERCEL_', 'NEXT_PUBLIC_VERCEL_', 'AWS_LAMBDA_', 'ECS_', 'COPILOT_', 'KUBERNETES_',
  'RAILWAY_', 'FLY_', 'RENDER_', 'NETLIFY_', 'HEROKU_', 'CF_PAGES', 'GITLAB_', 'CIRCLE', 'BUILDKITE', 'VITEST_',
  'JEST_', 'PLAYWRIGHT_', 'CYPRESS_', 'EAS_BUILD', 'TURBO_', 'NX_',
];

/** Variables provided by the platform or the runtime, never by the team's config. */
export function isPlatformVar(name: string): boolean {
  return IGNORED_EXACT.has(name) || IGNORED_PREFIX.some((p) => name.startsWith(p));
}

const SECRET_RE = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|SALT|SIGNING|HMAC|(^|_)KEY(_|$)|APIKEY)/;

export function isSecretLooking(name: string): boolean {
  const n = name.toUpperCase();
  if (/(^|_)PUBLIC(_|$)/.test(n) && !/SECRET|PRIVATE/.test(n)) return false;
  if (/(_ID|_URL|_URI|_NAME|_PATH|_FILE|_TTL|_EXPIRY|_EXPIRES_IN|_EXPIRATION|_ALGORITHM|_HEADER|_PREFIX|_LENGTH|_ROUNDS)$/.test(n)) return false;
  return SECRET_RE.test(n);
}

/**
 * Third-party credentials. Two services holding the same vendor key is normal
 * and says nothing about whether they must match, so no suggestion is made.
 */
const VENDOR_PREFIX = [
  'AWS_', 'STRIPE_', 'SENDGRID_', 'TWILIO_', 'OPENAI_', 'ANTHROPIC_', 'GOOGLE_', 'GCP_', 'FIREBASE_', 'SENTRY_',
  'SUPABASE_', 'RAZORPAY_', 'PAYPAL_', 'SLACK_', 'GITHUB_', 'CLOUDINARY_', 'MAILGUN_', 'RESEND_', 'POSTMARK_',
  'DATADOG_', 'DD_', 'NEW_RELIC_', 'ALGOLIA_', 'MAPBOX_', 'AZURE_', 'CLOUDFLARE_', 'CLERK_', 'AUTH0_', 'OKTA_',
  'NEXTAUTH_', 'GEMINI_', 'MISTRAL_', 'GROQ_', 'COHERE_', 'HUGGINGFACE_', 'ZOHO_', 'META_', 'FACEBOOK_', 'FCM_', 'VAPID_', 'SMTP_', 'S3_', 'R2_', 'DB_', 'DATABASE_', 'POSTGRES_', 'MYSQL_', 'MONGO_', 'REDIS_', 'RABBITMQ_',
];

export function isVendorVar(name: string): boolean {
  const n = name.replace(/^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)/, '');
  return VENDOR_PREFIX.some((p) => n.startsWith(p));
}

/** Names whose value is (or contains) a network location. */
export function isLocationVar(name: string): boolean {
  return /(^|_)(URL|URI|URLS|HOST|ORIGIN|ORIGINS|ENDPOINT|DSN)$/.test(name) || /(^|_)URL_/.test(name);
}

const CONNECTION_RE =
  /(^|_)(DATABASE|DB|REDIS|MONGO|MONGODB|POSTGRES|POSTGRESQL|PG|MYSQL|AMQP|RABBITMQ|KAFKA|NATS|ELASTICSEARCH|CACHE|QUEUE|BROKER|DIRECT|SHADOW_DATABASE)_(URL|URI)/;

/** Connection strings: not HTTP bases, so the URL-shape rules do not apply. */
export function isConnectionVar(name: string): boolean {
  return CONNECTION_RE.test(name) || /_DSN$/.test(name);
}

const ENDPOINT_RE =
  /(^|_)(WEBHOOK|HOOK|CALLBACK|REDIRECT|RETURN|SUCCESS|CANCEL|FAILURE|LOGIN|LOGOUT|SIGNIN|SIGNUP|HEALTH|HEALTHCHECK|JWKS|TOKEN|AUTHORIZE|AUTHORIZATION|ISSUER|METADATA|WSDL|IMAGE|LOGO|AVATAR|ICON|DOCS|FEED|SITEMAP|PRIVACY|TERMS|SUPPORT|INVITE|RESET|VERIFY|VERIFICATION|UNSUBSCRIBE|DOWNLOAD|SYNC)_(URL|URI)$/;

/** Variables that name one specific endpoint or page: a full path is correct. */
export function isEndpointVar(name: string): boolean {
  return ENDPOINT_RE.test(name);
}

/** Service base URLs: the value clients append their own path to. */
export function isBaseUrlVar(name: string): boolean {
  if (!/(^|_)URL$/.test(name) && !/_(BASE|API)_URI$/.test(name)) return false;
  return !isConnectionVar(name) && !isEndpointVar(name);
}

/** Variables that legitimately hold a list of origins. */
export function isListVar(name: string): boolean {
  return /(CORS|ORIGINS|ALLOWED|ALLOWLIST|WHITELIST|TRUSTED|URLS)/.test(name);
}

export function isProdName(env: string): boolean {
  return /(^|[^a-z])(prod|production|prd|live)([^a-z]|$)/i.test(env) && !/non-?prod/i.test(env);
}

/** Supplied by the deploy platform itself, so a manifest need not set them. */
export function isProvidedByTarget(kind: string, name: string): boolean {
  return kind === 'copilot' && /^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name);
}

export type Severity = 'error' | 'hint' | 'info';

/**
 * How the code treats a variable being unset:
 * required     - guarded (getOrThrow, schema-required, non-null assertion, throw)
 * localdefault - falls back to a localhost literal
 * plain        - read with nothing visible that handles it being unset
 * flag/default - the code visibly copes with it being unset
 */
export type ReadKind = 'required' | 'localdefault' | 'plain' | 'flag' | 'default';

export interface EnvRead {
  name: string;
  /** Path relative to the workspace root. */
  file: string;
  line: number;
  kind: ReadKind;
  /** Declared by a validation schema, which is authoritative about defaults. */
  schema: boolean;
}

export type HostClass = 'ok' | 'local' | 'tunnel' | 'vercel-preview' | 'vercel-default' | 'nonprod';

export interface HostFact {
  /** In-memory only. Never rendered for values that come from non-example files. */
  host: string;
  port?: number;
  klass: HostClass;
  /** The token that made the host look non-production (e.g. "staging"). */
  token?: string;
}

export type ShapeCode = 'trailing-slash' | 'query' | 'fragment' | 'resource-path';

export interface ShapeProblem {
  codes: ShapeCode[];
  /** In-memory only; rendered only when the source is an example file. */
  path: string;
  /** In-memory only; rendered only when the source is an example file. */
  suggested: string;
}

/**
 * Facts derived from a value at collection time. For anything that is not an
 * example file the raw value is dropped and only these facts are kept.
 */
export interface VarFacts {
  placeholder: boolean;
  http: boolean;
  shape: ShapeProblem | null;
  hosts: HostFact[];
  port?: number;
}

export interface DeclaredVar {
  name: string;
  line: number;
  /** Raw value. Present ONLY for example files. */
  value?: string;
  facts?: VarFacts;
  /** Secret-store reference (e.g. a parameter path). In-memory, never rendered. */
  ref?: string;
  commented?: boolean;
}

export type EnvName = 'prod' | 'staging' | 'test' | 'dev' | 'local';

export interface EnvFile {
  /** Relative to the workspace root. */
  file: string;
  isExample: boolean;
  envName: EnvName;
  vars: Map<string, DeclaredVar>;
}

export interface TargetEnv {
  name: string;
  vars: Map<string, DeclaredVar>;
  /** Set when part of this environment's config cannot be read from files. */
  opaque?: string;
}

export interface DeployTarget {
  kind: 'copilot' | 'compose' | 'vercel';
  file: string;
  name: string;
  envs: TargetEnv[];
}

export interface Suppression {
  reason: string;
  file: string;
  line: number;
}

export type AnnotationKind = 'same-as' | 'optional' | 'build-time';

/** One `# wirelint: ...` annotation from a service's own .env.example. */
export interface Annotation {
  kind: AnnotationKind;
  /** Service that owns the annotated variable. */
  service: string;
  variable: string;
  file: string;
  line: number;
  /** For same-as: the target exactly as written, `<service>` or `<service>.<NAME>`. */
  target?: string;
}

/**
 * A declared same-value relation: `variable` in `service` must hold the same
 * value as `target.variable` in `target.service`. v1 checks only that both
 * sides still declare it; `compared` says so, so a later version that compares
 * values can tell what has already been checked.
 */
export interface Relation {
  kind: 'same-as';
  service: string;
  variable: string;
  file: string;
  line: number;
  target: { service: string; variable: string };
  compared: 'existence';
}

/** Names visible to a build: Dockerfile ARG/ENV, compose build.args, vercel.json build.env. */
export interface BuildConfig {
  kind: 'dockerfile' | 'compose' | 'vercel';
  file: string;
  /** Compose service name, for the fix text. */
  name?: string;
  names: Set<string>;
}

export interface Service {
  name: string;
  dir: string;
  /** Monorepo root whose env files this service inherits. */
  parentDir?: string;
  reads: EnvRead[];
  dynamicReads: { file: string; line: number }[];
  envFiles: EnvFile[];
  targets: DeployTarget[];
  /** Names set by a Dockerfile ENV or by platform add-ons: present in every target. */
  baked: Set<string>;
  /** Local ports this service listens on, from the most authoritative source available. */
  ports: Set<number>;
  composePorts: Set<number>;
  scriptPorts: Set<number>;
  /** Hostnames this service answers to on a compose network. */
  aliases: Set<string>;
  suppress: Map<string, Suppression>;
  badSuppressions: { file: string; line: number; name?: string }[];
  annotations: Annotation[];
  badAnnotations: { file: string; line: number; name?: string; problem: string; fix: string }[];
  build: BuildConfig[];
  filesScanned: number;
}

export interface Finding {
  fingerprint: string;
  check: string;
  severity: Severity;
  service: string;
  variable: string;
  /** Relative to the workspace root; may be empty for cross-service hints. */
  file: string;
  line?: number;
  env?: string;
  problem: string;
  fix: string;
}

export interface Edge {
  from: string;
  to: string;
  variable: string;
  file: string;
  /** Only present when the value came from an example file. */
  port?: number;
}

export interface Report {
  version: string;
  workspace: string;
  services: {
    name: string;
    variablesRead: number;
    filesScanned: number;
    envFiles: string[];
    deployTargets: { kind: string; file: string; environments: string[] }[];
    ports: number[];
  }[];
  edges: Edge[];
  /** Annotations read from .env.example files, valid or not. */
  annotations: Annotation[];
  /** Resolved same-as relations. */
  relations: Relation[];
  findings: Finding[];
  summary: {
    failures: number;
    suggestions: number;
    notes: number;
    baselined: number;
    suppressed: number;
    durationMs: number;
  };
}

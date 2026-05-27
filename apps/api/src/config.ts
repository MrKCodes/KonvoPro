// Boot-time secret and configuration validation (Requirements 17.6, 19.8).
//
// Loads every environment variable required by the API_Gateway through a zod
// schema. On any missing or invalid value we emit one structured JSON line per
// issue to stderr (no PII; field path + machine-readable code + human message)
// and exit the process with status 1 BEFORE any Fastify listener is opened.
//
// This module is intentionally side-effect free at import time. The bootstrap
// in `server.ts` calls `loadConfig()` as its very first step. Tests construct
// their own `Config` literal and bypass the loader.
//
// Empty environment values (`FOO=`) are treated as "unset" so that fields with
// defaults still receive their default rather than failing min-length checks
// with a confusing message about a zero-length string.

import { z } from 'zod';

/** Coerce common boolean spellings from `process.env` strings. Anything else
 *  is forwarded unchanged so zod surfaces a typed error. */
function preprocessBool(v: unknown): unknown {
  if (typeof v !== 'string') return v;
  if (v === 'true' || v === '1') return true;
  if (v === 'false' || v === '0') return false;
  return v;
}

/** Strip empty strings out of `process.env` so `.default(...)` actually applies. */
function normalizeEnv(env: NodeJS.ProcessEnv): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const key of Object.keys(env)) {
    const value = env[key];
    out[key] = value === '' ? undefined : value;
  }
  return out;
}

/** The full environment contract for `apps/api`. Every field is required at
 *  boot unless it carries a `.default(...)`. */
export const ConfigSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),

    // Auth + token signing.
    JWT_ACCESS_SECRET: z
      .string()
      .min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
    REFRESH_TOKEN_PEPPER: z
      .string()
      .min(32, 'REFRESH_TOKEN_PEPPER must be at least 32 characters'),

    // Argon2id parameters (design.md §8 / Requirement 1.1: m=64 MiB, t=3, p=4).
    ARGON2_M_KIB: z.coerce.number().int().min(16384).default(65536),
    ARGON2_T: z.coerce.number().int().min(1).default(3),
    ARGON2_P: z.coerce.number().int().min(1).default(4),

    // Postgres connection. Production REQUIRES `sslmode=require` per
    // Requirement 19.8 (TLS-only, no fallback). The refinement below enforces
    // this without blocking dev/test which run against local docker-compose
    // with `sslmode=disable`.
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

    REDIS_URL: z
      .string()
      .regex(
        /^rediss?:\/\//,
        'REDIS_URL must start with redis:// or rediss://',
      ),

    // MinIO (E2EE attachment ciphertext store).
    MINIO_ENDPOINT: z.string().min(1, 'MINIO_ENDPOINT is required'),
    MINIO_ACCESS_KEY: z.string().min(1, 'MINIO_ACCESS_KEY is required'),
    MINIO_SECRET_KEY: z
      .string()
      .min(8, 'MINIO_SECRET_KEY must be at least 8 characters'),
    MINIO_BUCKET: z.string().min(1).default('konvo-attachments'),
    MINIO_USE_SSL: z.preprocess(preprocessBool, z.boolean()).default(false),

    // VAPID keys for Web Push (server only carries `{type, sender, conv_id}`).
    // Public keys are base64url P-256 points (≈87 chars); we accept a slightly
    // looser min so legitimate alternate encodings still validate.
    VAPID_PUBLIC_KEY: z
      .string()
      .min(80, 'VAPID_PUBLIC_KEY must be at least 80 characters'),
    VAPID_PRIVATE_KEY: z
      .string()
      .min(40, 'VAPID_PRIVATE_KEY must be at least 40 characters'),
    VAPID_SUBJECT: z
      .string()
      .regex(
        /^(mailto:|https:\/\/)/,
        'VAPID_SUBJECT must start with mailto: or https://',
      ),

    // LiveKit (broadcast SFU only — never used for 1:1 calls).
    LIVEKIT_API_KEY: z.string().min(1, 'LIVEKIT_API_KEY is required'),
    LIVEKIT_API_SECRET: z
      .string()
      .min(32, 'LIVEKIT_API_SECRET must be at least 32 characters'),
    LIVEKIT_URL: z
      .string()
      .regex(
        /^wss?:\/\//,
        'LIVEKIT_URL must start with ws:// or wss://',
      ),

    // coturn REST auth secret (TURN_Credentials are HMAC-derived from this).
    COTURN_REST_SECRET: z
      .string()
      .min(32, 'COTURN_REST_SECRET must be at least 32 characters'),
    COTURN_REALM: z.string().min(1).default('konvo.local'),
  })
  .superRefine((cfg, ctx) => {
    if (
      cfg.NODE_ENV === 'production' &&
      !/sslmode=require/i.test(cfg.DATABASE_URL)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['DATABASE_URL'],
        message: 'DATABASE_URL must include sslmode=require in production',
      });
    }
  });

/** Strongly-typed, validated configuration. */
export type Config = z.infer<typeof ConfigSchema>;

/** Shape of one structured error line emitted on validation failure. */
interface ConfigIssueLog {
  readonly level: 'error';
  readonly msg: 'config validation failed';
  readonly field: string;
  readonly code: string;
  readonly reason: string;
}

/** Load and validate the API_Gateway environment.
 *
 *  On success: returns the fully-typed `Config`.
 *  On failure: writes one JSON line per issue to stderr identifying the field,
 *  zod issue code, and human-readable reason, then exits with status 1. We
 *  exit BEFORE any caller can open a listener (see `server.ts`).
 *
 *  Note: this function never returns on failure — it terminates the process.
 *  The `never` branch is expressed via `process.exit(1)` inside the failure
 *  arm; TypeScript narrows the success path correctly.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = ConfigSchema.safeParse(normalizeEnv(env));
  if (result.success) {
    return result.data;
  }

  for (const issue of result.error.issues) {
    const line: ConfigIssueLog = {
      level: 'error',
      msg: 'config validation failed',
      field: issue.path.length > 0 ? issue.path.join('.') : '<root>',
      code: issue.code,
      reason: issue.message,
    };
    console.error(JSON.stringify(line));
  }

  process.exit(1);
}

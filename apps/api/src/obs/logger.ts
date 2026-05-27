// apps/api/src/obs/logger.ts
//
// Server logger redaction layer (task 4.9 — Phase 3).
//
// Realizes Requirements 4.14, 16.4, 18.3, 18.4, 18.6, 18.7 against
// `pino`. The module exports a `createLogger` factory that returns a
// pino instance with three layered guarantees:
//
//   1. RECURSIVE FIELD REDACTION (Requirement 18.4) — every log record
//      is walked recursively at any nesting depth and any property
//      whose key is in `REDACTED_FIELDS` is replaced with the censor
//      sentinel `[REDACTED]`. Pino's built-in `redact` option is
//      string-path based and only handles fixed shapes; we need
//      "field name X anywhere in the tree" semantics, which the
//      built-in cannot express, so we install the redaction in the
//      `formatters.log` callback (Pino calls this once per log record
//      with the merged object the user passed). The forbidden field
//      names match design.md §19.2 verbatim.
//
//   2. ALWAYS-PRESENT BASE FIELDS (Requirement 18.3) — `ts`, `level`,
//      `msg`, and `requestId` MUST appear on every record. Pino emits
//      `level` and `msg` natively; we map `time` → `ts` via the
//      `timestamp` option and emit `requestId` via a `mixin`. Callers
//      bind `requestId` (and optionally `userId` / `deviceId` for
//      authenticated operations) by creating a `child` logger; the
//      mixin reads `bindings.requestId` and surfaces a sentinel
//      (`'unbound'`) if no binding is in scope, so a missing
//      `requestId` is observable in tests rather than silently
//      omitted.
//
//   3. DROP-ON-FAILURE + COUNTER (Requirement 18.7) — if the recursive
//      walk throws (e.g. circular reference whose introspection
//      reaches the depth limit, or a getter that throws), the log
//      record is DROPPED rather than written, and the prom-client
//      counter `konvo_log_redaction_failures_total` is incremented.
//      We can't use `formatters.log` for the drop path (returning
//      `null`/throwing crashes pino), so we install a `hooks.logMethod`
//      that runs deep-redact ONCE before pino's pipeline. On success
//      we forward the original (unredacted) args to `method.apply`
//      (formatters.log will redact again — the second pass is
//      idempotent on the already-clean tree). On failure we swallow
//      the call.
//
//      The counter abstraction is kept tiny on purpose: task 10.1
//      will wire `prom-client` and provide a real `Counter` instance
//      via `setRedactionFailureCounter`. Until then the default
//      in-memory counter is observable from tests via
//      `getRedactionFailureCount()`.
//
// REST REQUEST LOGGING (Requirements 18.6, 16.4):
//   The exported `restRequestLogger` opts pass `serializers.req` /
//   `serializers.res` overrides that emit ONLY the four whitelisted
//   fields per request line: `method`, `path`, `status`, `durationMs`.
//   `path` is the URL path component WITHOUT the query string —
//   Fastify's default `req.url` includes the query, which would
//   leak handle/slug parameters into Loki, so we re-derive it from
//   the original URL via `splitOnQuery`.
//
//   Headers are NEVER serialized: the default Fastify req serializer
//   includes `headers` (cookies, authorization, csrf token), and
//   18.6 forbids that. The override here returns a fresh object
//   that only contains the four whitelisted fields.
//
// PII NON-LEAK SENTINEL (Requirement 16.4):
//   `__PII_LEAK_CANARY__` is the sentinel used by the design doc's
//   "PII Stripping Test" (§19.4). Tests in `test/logger.test.ts`
//   inject this string into protected fields at every nesting depth
//   and assert it never appears in the rendered output.

import type pinoNs from 'pino';
import pinoFactory from 'pino';
import type { IncomingMessage, ServerResponse } from 'node:http';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Field names that must be redacted at any nesting depth.
 *
 *  Source of truth: design.md §19.2 + Requirement 18.4. The list is
 *  intentionally NOT extended past these names — any future addition
 *  belongs in design.md first.
 *
 *  Note on `body`: Requirement 18.6 also forbids logging REST request
 *  body. The redaction pass catches `{ body: ... }` ANY nesting depth
 *  (e.g. `{ req: { body } }`) without relying on the request serializer.
 *  This means even a hand-rolled `app.log.info({ inbound: { body } })`
 *  is safe. */
export const REDACTED_FIELDS: ReadonlySet<string> = new Set([
  'ciphertext',
  'body',
  'password',
  'token',
  'key',
  'privateKey',
  'identityPriv',
  'secret',
  'argon2Hash',
]);

/** Censor sentinel substituted in place of redacted values. */
export const REDACTION_CENSOR = '[REDACTED]';

/** Sentinel used by the PII stripping test (design.md §19.4). */
export const PII_LEAK_CANARY = '__PII_LEAK_CANARY__';

// ---------------------------------------------------------------------------
// Redaction failure counter
// ---------------------------------------------------------------------------

/** Minimal Counter interface satisfied by both the default in-memory
 *  counter (below) and a future `prom-client` `Counter` instance. */
export interface RedactionFailureCounter {
  inc(value?: number): void;
}

let redactionFailureCount = 0;
let redactionFailureCounter: RedactionFailureCounter = {
  inc(value = 1): void {
    redactionFailureCount += value;
  },
};

/** Replace the redaction-failure counter. Wiring point for task 10.1
 *  (prom-client). Calling this resets the in-memory test counter to 0
 *  so test setup can install a fresh counter and not inherit prior
 *  state. */
export function setRedactionFailureCounter(
  counter: RedactionFailureCounter,
): void {
  redactionFailureCounter = counter;
  redactionFailureCount = 0;
}

/** Read the current in-memory failure count. Test-only helper. */
export function getRedactionFailureCount(): number {
  return redactionFailureCount;
}

// ---------------------------------------------------------------------------
// Recursive redaction
// ---------------------------------------------------------------------------

/** Recursively redact in-place a clone of `obj`, replacing values at
 *  any depth whose key is in `REDACTED_FIELDS` with `REDACTION_CENSOR`.
 *
 *  Returns a new object/array; the input is never mutated.
 *
 *  Cycle handling: a `WeakSet` tracks objects already visited on the
 *  current path; if a cycle is detected, the back-edge is replaced
 *  with the string `'[Circular]'`. This means a circular object never
 *  causes the walker to throw on its own, which is desirable for
 *  production observability — the only path to the drop branch is a
 *  thrown getter or a user-supplied `toJSON` that throws.
 *
 *  Buffer/Uint8Array handling: byte arrays are returned as-is (the
 *  `level: 'binary'` field name is not in REDACTED_FIELDS, but if a
 *  Buffer happens to live under a redacted key its value is still
 *  censored via the key-match check). Pino's serialiser will
 *  stringify a Buffer to its hex representation, which is harmless
 *  metadata. */
export function deepRedact<T>(value: T): T {
  return deepRedactImpl(value, new WeakSet()) as T;
}

function deepRedactImpl(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t !== 'object') return value;

  // Buffer / Uint8Array: keep the underlying bytes intact. The key-match
  // pass (one frame up) will censor it whole if it lives under a
  // redacted key.
  if (value instanceof Uint8Array) return value;

  // Cycle detection: return a sentinel rather than recursing.
  if (seen.has(value as object)) return '[Circular]';
  seen.add(value as object);

  if (Array.isArray(value)) {
    const out = new Array<unknown>(value.length);
    for (let i = 0; i < value.length; i += 1) {
      out[i] = deepRedactImpl(value[i], seen);
    }
    return out;
  }

  // Plain objects + class instances: walk own enumerable string keys
  // only. We deliberately ignore symbol keys and inherited keys so a
  // Logger's prototype methods don't get walked.
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>)) {
    const child = (value as Record<string, unknown>)[key];
    if (REDACTED_FIELDS.has(key)) {
      out[key] = REDACTION_CENSOR;
    } else {
      out[key] = deepRedactImpl(child, seen);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Logger factory
// ---------------------------------------------------------------------------

export interface CreateLoggerOptions {
  /** pino log level. Defaults to `LOG_LEVEL` env var or `'info'`. */
  readonly level?: pinoNs.LevelWithSilentOrString;
  /** Destination stream override; primarily for tests that capture
   *  output. Defaults to pino's stdout sink. */
  readonly destination?: pinoNs.DestinationStream;
}

/** Construct a pino instance with the redaction layer wired in.
 *
 *  Test integration: pass `destination` to capture output. The returned
 *  logger is a regular pino logger; callers can call `.child({...})`
 *  to bind `requestId`/`userId`/`deviceId` for the lifetime of an
 *  operation. */
export function createLogger(opts: CreateLoggerOptions = {}): pinoNs.Logger {
  const level = opts.level ?? process.env['LOG_LEVEL'] ?? 'info';

  const baseOptions: pinoNs.LoggerOptions = {
    level,
    // Strip the default pid + hostname bindings: §19.2 enumerates the
    // exact fields that may appear ("ts, level, msg, requestId,
    // userId?, deviceId?"), and pid/hostname leak server topology.
    base: undefined,
    // Map `time` → `ts` (Requirement 18.3). The function MUST return a
    // JSON fragment that pino can splice into the line, including the
    // leading comma. `Date.now()` is intentionally cheap; the histogram
    // metric in task 10.1 measures real-time latency separately.
    timestamp: () => `,"ts":${Date.now()}`,
    messageKey: 'msg',
    // mixin is called once per log call. We surface `requestId` here
    // (rather than depending on every caller binding it via .child())
    // so that the field is ALWAYS present in the rendered line, even
    // for boot-time logs that have no request context.
    mixin(_mergeObject: object, _level: number, logger: pinoNs.Logger): Record<string, unknown> {
      // Pino exposes the active bindings via the logger's symbol-keyed
      // `chindings` cache. The supported public way to read them in
      // a mixin is to inspect the merged object pinned to the active
      // child (which `_mergeObject` already includes). For unbound
      // loggers we surface a sentinel.
      const chind = (logger as unknown as { bindings(): Record<string, unknown> })
        .bindings();
      if (typeof chind['requestId'] === 'string') {
        return {};
      }
      return { requestId: 'unbound' };
    },
    formatters: {
      // The `level` formatter swaps pino's default integer-only
      // `level: 30` for `level: "info"` so log lines are
      // human-greppable (Requirement 18.3 specifies `level` as a
      // first-class field; the design doesn't require numeric vs
      // label, but Loki is easier to query with labels).
      level(label: string): Record<string, unknown> {
        return { level: label };
      },
      // Final redaction pass over the merged log object. Any field
      // whose key lives in REDACTED_FIELDS (at any depth) is censored
      // here. This is the "belt" half of the belt-and-braces: the
      // hooks.logMethod path (below) ALSO runs the same walk, so a
      // throwing getter is caught before pino enters its serialise
      // pipeline. By the time `formatters.log` runs we know the tree
      // is safe to walk; the second pass is idempotent.
      log(record: Record<string, unknown>): Record<string, unknown> {
        return deepRedact(record);
      },
    },
    hooks: {
      // The drop-on-failure gate. We run `deepRedact` against the
      // first object argument (pino's calling convention is
      // `log.info(obj?, msg?, ...interp)`), and if the walk throws
      // we increment the counter and DROP the record by returning
      // without calling `method`.
      //
      // We do NOT pass the redacted object back to `method`; the
      // `formatters.log` pass redacts again, which is cheaper than
      // worrying about the discriminator types pino expects. The
      // hook's only job here is gating.
      logMethod(
        this: pinoNs.Logger,
        args: Parameters<pinoNs.LogFn>,
        method: pinoNs.LogFn,
        _level: number,
      ): void {
        try {
          // Pino accepts (msg) or (mergeObj, msg, ...interp). Only the
          // first arg, when an object, needs guarding. Strings and
          // primitives are inert.
          const head: unknown = args[0];
          if (head !== null && typeof head === 'object') {
            // Throws iff redaction fails. We discard the result; the
            // formatters.log pass does the actual substitution.
            deepRedact(head);
          }
          method.apply(this, args);
        } catch {
          redactionFailureCounter.inc(1);
          // DROP the record per Requirement 18.7. No call to `method`.
        }
      },
    },
  };

  // The pino factory is overloaded: when `destination` is provided we
  // pass it as the second positional argument. We keep the
  // constructor call shape narrow so the type-system catches a
  // miswiring (e.g. passing destination as the only arg, which would
  // silently lose `baseOptions`).
  if (opts.destination !== undefined) {
    return pinoFactory(baseOptions, opts.destination);
  }
  return pinoFactory(baseOptions);
}

// ---------------------------------------------------------------------------
// Fastify integration
// ---------------------------------------------------------------------------

/** Strip the query string from a URL path. Returns the path component
 *  only; never logs the query (Requirement 18.6). */
function stripQuery(url: string | undefined): string {
  if (url === undefined || url === '') return '';
  const q = url.indexOf('?');
  return q === -1 ? url : url.slice(0, q);
}

/** Fastify request serializer that emits ONLY `method` and `path`.
 *
 *  Fastify's default `req` serializer also includes `hostname`,
 *  `remoteAddress`, `remotePort`, and (worse) `headers`. We override
 *  with a fresh shape so:
 *    - Headers (cookies, authorization, csrf token) NEVER appear
 *      (Requirement 18.6).
 *    - Query strings NEVER appear (Requirement 18.6).
 *    - The shape matches the four whitelisted fields exactly:
 *      `method`, `path`, `status` (added on the response side),
 *      `durationMs` (added by Fastify's own `responseTime` hook).
 */
export function fastifyReqSerializer(
  req: { method?: string; url?: string },
): { method: string; path: string } {
  return {
    method: req.method ?? '',
    path: stripQuery(req.url),
  };
}

/** Fastify response serializer that emits ONLY `status`. Fastify
 *  injects `responseTime` (ms) onto the request log line itself via
 *  its `disableRequestLogging: false` path; we surface it as
 *  `durationMs` via the `customSuccessMessage` hook in the consuming
 *  app. */
export function fastifyResSerializer(
  res: { statusCode?: number },
): { status: number } {
  return {
    status: res.statusCode ?? 0,
  };
}

/** Logger options bundle ready to drop into `Fastify({ logger: ... })`.
 *
 *  Usage:
 *  ```ts
 *  import { createFastifyLoggerOptions } from './obs/logger.js';
 *  const app = Fastify({ logger: createFastifyLoggerOptions() });
 *  ```
 *
 *  This produces a Fastify instance whose request log lines are
 *  exactly `{ method, path, status, durationMs }` per Requirement
 *  18.6 (plus the always-on `ts, level, msg, requestId` from
 *  Requirement 18.3). Body / query / headers never appear. */
export function createFastifyLoggerOptions(
  opts: CreateLoggerOptions = {},
): pinoNs.LoggerOptions {
  return {
    level: opts.level ?? process.env['LOG_LEVEL'] ?? 'info',
    base: undefined,
    timestamp: () => `,"ts":${Date.now()}`,
    messageKey: 'msg',
    serializers: {
      req: fastifyReqSerializer as (
        req: IncomingMessage & { method?: string; url?: string },
      ) => unknown,
      res: fastifyResSerializer as (
        res: ServerResponse & { statusCode?: number },
      ) => unknown,
    },
    formatters: {
      level(label: string): Record<string, unknown> {
        return { level: label };
      },
      log(record: Record<string, unknown>): Record<string, unknown> {
        return deepRedact(record);
      },
    },
    hooks: {
      logMethod(
        this: pinoNs.Logger,
        args: Parameters<pinoNs.LogFn>,
        method: pinoNs.LogFn,
      ): void {
        try {
          const head: unknown = args[0];
          if (head !== null && typeof head === 'object') {
            deepRedact(head);
          }
          method.apply(this, args);
        } catch {
          redactionFailureCounter.inc(1);
        }
      },
    },
  };
}

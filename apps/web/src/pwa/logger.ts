// apps/web/src/pwa/logger.ts
//
// Tiny structured logger for the PWA layer (task 9.1).
//
// Why this exists separately from the server logger:
//   The server's pino-based logger in `apps/api/src/obs/logger.ts`
//   binds to Node-only sinks (process.stdout) and pulls in pino +
//   prom-client transitively. The Service_Worker context can NOT
//   load Node-only modules, and the PWA bundle deliberately keeps
//   its dependency tree small. We mirror the SAME log-record
//   shape used server-side — `{ts, level, msg, ...}` per
//   Requirement 18.3 — so a future log-shipper that ingests both
//   web and api lines doesn't have to special-case the schema.
//
// Why a single module shared by `register.ts` and `sw.ts`:
//   Both contexts need to surface "service worker registration or
//   precache failed" in the same shape (Requirement 14.8). The
//   SW global scope (`ServiceWorkerGlobalScope`) and the page
//   global scope both expose `console.*`, so a console-backed
//   sink works in both. The sink is injectable so tests assert
//   the emitted records without parsing stdout.

/**
 * Structured log levels. `error` and `warn` route through
 * `console.error` / `console.warn` so DevTools surfaces them with
 * the appropriate icon and the pageinfo→errors panel picks them
 * up. `info` and `debug` route through the corresponding
 * console methods so log-level filtering at the browser level
 * still works.
 */
export type PwaLogLevel = 'error' | 'warn' | 'info' | 'debug';

/** Single log record. The shape mirrors the server pino schema:
 *  - `ts` — milliseconds since the epoch (Number.MAX_SAFE_INTEGER
 *    safe through year 287000). Server uses `Date.now()`; we do
 *    too so log lines from both halves of the system collate
 *    cleanly when shipped to Loki.
 *  - `level` — string label, NOT pino's numeric level, again
 *    matching the server's `formatters.level` configuration.
 *  - `msg` — short summary string. Required.
 *  - Any additional own properties are merged in verbatim. The
 *    PWA layer never logs ciphertext, plaintext, or key material,
 *    so no recursive redaction is required at this layer.
 */
export interface PwaLogRecord {
  readonly ts: number;
  readonly level: PwaLogLevel;
  readonly msg: string;
  readonly [key: string]: unknown;
}

/**
 * A sink consumes finished log records. The default sink dispatches
 * them to `console.*`; tests inject a sink that captures records
 * to an array and asserts on shape.
 */
export type PwaLogSink = (record: PwaLogRecord) => void;

/**
 * Default sink. Routes by level so DevTools shows the right icon
 * AND the browser's per-level filtering works. Each record is
 * stringified once so Loki / log shippers can reuse it directly
 * without re-parsing.
 */
export const consoleSink: PwaLogSink = (record: PwaLogRecord): void => {
  const line = JSON.stringify(record);
  switch (record.level) {
    case 'error':
      // eslint-disable-next-line no-console
      console.error(line);
      return;
    case 'warn':
      // eslint-disable-next-line no-console
      console.warn(line);
      return;
    case 'info':
      // eslint-disable-next-line no-console
      console.info(line);
      return;
    case 'debug':
      // eslint-disable-next-line no-console
      console.debug(line);
      return;
  }
};

let activeSink: PwaLogSink = consoleSink;

/** Replace the active sink. Test seam — pass a capture array's
 *  push method here to assert log emission shape. */
export function setPwaLogSink(sink: PwaLogSink): void {
  activeSink = sink;
}

/** Restore the default console-backed sink. */
export function resetPwaLogSink(): void {
  activeSink = consoleSink;
}

/**
 * Emit a single structured log record. The `extras` object is
 * shallow-merged into the record AFTER the base fields are
 * populated, so callers can include any diagnostic context (event
 * name, attempt count, error code) without wrestling with the
 * record-construction boilerplate.
 *
 * `Error` instances in `extras` are normalized to `{ name,
 * message, stack }` so the log line stays JSON-serializable.
 */
export function pwaLog(
  level: PwaLogLevel,
  msg: string,
  extras: Readonly<Record<string, unknown>> = {},
): void {
  const normalized: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(extras)) {
    normalized[k] = v instanceof Error
      ? { name: v.name, message: v.message, stack: v.stack }
      : v;
  }
  const record: PwaLogRecord = {
    ts: Date.now(),
    level,
    msg,
    ...normalized,
  };
  try {
    activeSink(record);
  } catch {
    // Sink itself threw — nothing useful to do; swallow so a
    // broken sink can't crash the page or the SW.
  }
}

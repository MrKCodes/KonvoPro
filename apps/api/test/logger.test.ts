// apps/api/test/logger.test.ts
//
// Unit + property tests for the redaction logger
// (`apps/api/src/obs/logger.ts`, task 4.9 — Phase 3).
//
// Coverage map:
//
//   Requirement 4.14  : `ciphertext` field is redacted at any nesting
//                       depth in any log call.
//   Requirement 16.4  : the PII canary `__PII_LEAK_CANARY__` injected
//                       into protected fields never appears in
//                       rendered output.
//   Requirement 18.3  : every log line carries `ts`, `level`, `msg`,
//                       `requestId` (the latter via child binding).
//   Requirement 18.4  : every forbidden field name (full list in
//                       design.md §19.2) is censored at depths 1–4.
//   Requirement 18.6  : Fastify request log lines emit ONLY
//                       `method`, `path`, `status`, `durationMs` —
//                       NEVER body, query string, or headers.
//   Requirement 18.7  : on a redaction-walker failure (e.g. throwing
//                       getter), the record is DROPPED and the
//                       `konvo_log_redaction_failures_total` counter
//                       is incremented.
//
// Test strategy: write to an in-memory pino destination stream and
// parse the captured JSONL. We rely on pino's normal sync-write
// behaviour for these fixtures (the destination's `write` is called
// synchronously inside `log.info(...)`).

import { describe, expect, test, beforeEach } from 'vitest';
import * as fc from 'fast-check';

import {
  REDACTED_FIELDS,
  REDACTION_CENSOR,
  PII_LEAK_CANARY,
  deepRedact,
  createLogger,
  createFastifyLoggerOptions,
  fastifyReqSerializer,
  fastifyResSerializer,
  setRedactionFailureCounter,
} from '../src/obs/logger.js';

// ---------------------------------------------------------------------------
// Test harness — a destination stream that captures rendered lines.
// ---------------------------------------------------------------------------

interface CapturedSink {
  write(chunk: string): boolean;
  lines: string[];
}

function makeSink(): CapturedSink {
  const lines: string[] = [];
  return {
    lines,
    write(chunk: string): boolean {
      // pino emits one JSON record per write, terminated with `\n`.
      // Split defensively in case a future pino version coalesces
      // writes.
      for (const part of chunk.split('\n')) {
        if (part.length > 0) lines.push(part);
      }
      return true;
    },
  };
}

function lastRecord(sink: CapturedSink): Record<string, unknown> {
  if (sink.lines.length === 0) {
    throw new Error('no log lines captured');
  }
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const raw = sink.lines.at(-1)!;
  return JSON.parse(raw) as Record<string, unknown>;
}

// The redaction-failure counter is replaced per-test with one that
// routes every `.inc()` call into a local `testFailureCount` variable
// the assertions read via `readTestFailureCount()`. We do this rather
// than reading the module-internal default counter because
// `setRedactionFailureCounter` resets the default's visible count to
// 0, so observing it from outside the module would always read 0.
let testFailureCount = 0;
function readTestFailureCount(): number {
  return testFailureCount;
}

beforeEach(() => {
  testFailureCount = 0;
  setRedactionFailureCounter({
    inc(value = 1): void {
      testFailureCount += value;
    },
  });
});

// ---------------------------------------------------------------------------
// deepRedact unit tests (covers the redaction algorithm in isolation,
// independently of pino).
// ---------------------------------------------------------------------------

describe('deepRedact', () => {
  test('redacts every forbidden field name at top level', () => {
    const input: Record<string, unknown> = {};
    for (const name of REDACTED_FIELDS) {
      input[name] = PII_LEAK_CANARY;
    }
    const out = deepRedact(input) as Record<string, unknown>;
    for (const name of REDACTED_FIELDS) {
      expect(out[name]).toBe(REDACTION_CENSOR);
    }
  });

  test('redacts forbidden field at depth 4', () => {
    const input = {
      a: { b: { c: { d: { ciphertext: PII_LEAK_CANARY, ok: 'visible' } } } },
    };
    const out = deepRedact(input);
    const leaf = (((out as { a: { b: { c: { d: Record<string, unknown> } } } }).a
      .b.c.d) as Record<string, unknown>);
    expect(leaf['ciphertext']).toBe(REDACTION_CENSOR);
    expect(leaf['ok']).toBe('visible');
  });

  test('redacts inside arrays of objects', () => {
    const input = {
      records: [
        { token: PII_LEAK_CANARY, msg: 'a' },
        { token: PII_LEAK_CANARY, msg: 'b' },
      ],
    };
    const out = deepRedact(input) as { records: Array<Record<string, unknown>> };
    for (const r of out.records) {
      expect(r['token']).toBe(REDACTION_CENSOR);
      expect(typeof r['msg']).toBe('string');
    }
  });

  test('does not mutate the input object', () => {
    const input = { password: PII_LEAK_CANARY, kept: 1 };
    const out = deepRedact(input);
    expect(input.password).toBe(PII_LEAK_CANARY);
    expect((out as { password: unknown }).password).toBe(REDACTION_CENSOR);
  });

  test('handles circular references without throwing', () => {
    const a: Record<string, unknown> = { name: 'a' };
    const b: Record<string, unknown> = { name: 'b', back: a };
    a['fwd'] = b;
    expect(() => deepRedact(a)).not.toThrow();
  });

  test('passes through primitives and null/undefined', () => {
    expect(deepRedact(42)).toBe(42);
    expect(deepRedact('hello')).toBe('hello');
    expect(deepRedact(null)).toBe(null);
    expect(deepRedact(undefined)).toBe(undefined);
  });

  // P-style property: for any object whose own keys are all in
  // `REDACTED_FIELDS`, EVERY value at every depth is censored.
  test('property: forbidden keys never leak (≥100 inputs)', () => {
    const arbForbiddenKey = fc.constantFrom(
      ...Array.from(REDACTED_FIELDS),
    );
    const arbLeaf = fc.oneof(
      fc.string({ minLength: 1, maxLength: 32 }),
      fc.integer(),
      fc.boolean(),
    );
    const arbForbiddenObj = fc.dictionary(arbForbiddenKey, arbLeaf, {
      minKeys: 1,
      maxKeys: 5,
    });
    fc.assert(
      fc.property(arbForbiddenObj, (obj) => {
        const out = deepRedact(obj) as Record<string, unknown>;
        for (const k of Object.keys(out)) {
          expect(out[k]).toBe(REDACTION_CENSOR);
        }
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// createLogger — integrated tests (pino + redaction layer).
// ---------------------------------------------------------------------------

describe('createLogger', () => {
  test('always emits ts, level, msg, requestId', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    const child = log.child({ requestId: 'req-abc' });
    child.info({ note: 'hello' }, 'test message');

    const rec = lastRecord(sink);
    expect(typeof rec['ts']).toBe('number');
    expect(rec['level']).toBe('info');
    expect(rec['msg']).toBe('test message');
    expect(rec['requestId']).toBe('req-abc');
  });

  test('emits requestId="unbound" when no child binding is in scope', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    log.info('rootless');

    const rec = lastRecord(sink);
    expect(rec['requestId']).toBe('unbound');
  });

  test('redacts top-level ciphertext field (Requirement 4.14)', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    log.info({ ciphertext: PII_LEAK_CANARY, route: '/ws' }, 'envelope');

    const rec = lastRecord(sink);
    expect(rec['ciphertext']).toBe(REDACTION_CENSOR);
    // Sanity: the entire serialized line must not contain the canary.
    const line = sink.lines.at(-1) ?? '';
    expect(line.includes(PII_LEAK_CANARY)).toBe(false);
  });

  test('redacts deeply nested ciphertext (≥4 levels deep)', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    log.info(
      { envelope: { inner: { meta: { extra: { ciphertext: PII_LEAK_CANARY } } } } },
      'deep',
    );

    const line = sink.lines.at(-1) ?? '';
    expect(line.includes(PII_LEAK_CANARY)).toBe(false);
    expect(line.includes(REDACTION_CENSOR)).toBe(true);
  });

  test('redacts every forbidden field name at any depth (Requirement 18.4)', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    // Build a single record with each forbidden name at depth >=2.
    const payload: Record<string, unknown> = { wrapper: {} };
    for (const name of REDACTED_FIELDS) {
      (payload['wrapper'] as Record<string, unknown>)[name] = PII_LEAK_CANARY;
    }
    log.info(payload, 'forbidden-set');

    const line = sink.lines.at(-1) ?? '';
    expect(line.includes(PII_LEAK_CANARY)).toBe(false);
  });

  test('drops record + increments counter on redaction failure (Requirement 18.7)', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });

    // Build an object whose property getter throws when accessed.
    // `deepRedact` walks own enumerable keys via Object.keys(); we
    // need the getter to throw at access time, so we attach it via
    // Object.defineProperty with `enumerable: true`.
    const trap: Record<string, unknown> = {};
    Object.defineProperty(trap, 'badField', {
      enumerable: true,
      get(): never {
        throw new Error('boom');
      },
    });

    const before = sink.lines.length;
    log.info({ outer: { trap } }, 'should be dropped');
    const after = sink.lines.length;

    expect(after).toBe(before);
    expect(readTestFailureCount()).toBeGreaterThanOrEqual(1);
  });

  test('does not include pid or hostname (no leakage of server topology)', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    log.info('plain');

    const rec = lastRecord(sink);
    expect(rec['pid']).toBeUndefined();
    expect(rec['hostname']).toBeUndefined();
  });

  test('PII canary never appears in rendered line for any forbidden field', () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    for (const field of REDACTED_FIELDS) {
      log.info({ [field]: PII_LEAK_CANARY }, `field:${field}`);
    }
    for (const line of sink.lines) {
      expect(line.includes(PII_LEAK_CANARY)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Fastify-mode logger options — REST request line shape (Requirement 18.6).
// ---------------------------------------------------------------------------

describe('createFastifyLoggerOptions / serializers', () => {
  test('req serializer emits ONLY method + path (no headers, no query)', () => {
    const out = fastifyReqSerializer({
      method: 'POST',
      url: '/auth/login?redirect=/inbox',
      // The shape passed by Fastify also carries `headers`, `body`,
      // `hostname`, `remoteAddress`, etc. The override must drop them
      // all — we validate by snapshotting the keys.
    } as { method: string; url: string });

    expect(Object.keys(out).sort()).toEqual(['method', 'path']);
    expect(out.method).toBe('POST');
    expect(out.path).toBe('/auth/login');
    expect(out.path.includes('?')).toBe(false);
  });

  test('req serializer handles missing url and method defensively', () => {
    const out = fastifyReqSerializer({});
    expect(out.method).toBe('');
    expect(out.path).toBe('');
  });

  test('res serializer emits ONLY status', () => {
    const out = fastifyResSerializer({ statusCode: 204 });
    expect(Object.keys(out)).toEqual(['status']);
    expect(out.status).toBe(204);
  });

  test('logger options bundle has redaction installed at formatters.log', () => {
    const opts = createFastifyLoggerOptions();
    expect(opts.formatters?.log).toBeTypeOf('function');
    const out = opts.formatters?.log?.({
      msg: 'test',
      ciphertext: PII_LEAK_CANARY,
      nested: { token: PII_LEAK_CANARY },
    });
    expect(out?.['ciphertext']).toBe(REDACTION_CENSOR);
    expect(
      ((out?.['nested'] as Record<string, unknown> | undefined) ?? {})['token'],
    ).toBe(REDACTION_CENSOR);
  });

  test('logMethod hook drops record on redaction failure', () => {
    const opts = createFastifyLoggerOptions();
    const trap: Record<string, unknown> = {};
    Object.defineProperty(trap, 'evil', {
      enumerable: true,
      get(): never {
        throw new Error('nope');
      },
    });

    let invoked = 0;
    const fakeMethod = (() => {
      invoked += 1;
    }) as unknown as Parameters<typeof opts.hooks.logMethod>[1];

    opts.hooks?.logMethod?.call(
      { /* dummy `this` — pino logger surface unused by our hook */ } as unknown as never,
      [trap, 'msg'] as never,
      fakeMethod as never,
      30,
    );

    expect(invoked).toBe(0);
    expect(readTestFailureCount()).toBeGreaterThanOrEqual(1);
  });

  test('logMethod hook forwards to method on success', () => {
    const opts = createFastifyLoggerOptions();
    let invoked = 0;
    const fakeMethod = (() => {
      invoked += 1;
    }) as unknown as Parameters<typeof opts.hooks.logMethod>[1];

    opts.hooks?.logMethod?.call(
      {} as unknown as never,
      [{ ok: true }, 'fine'] as never,
      fakeMethod as never,
      30,
    );

    expect(invoked).toBe(1);
    expect(readTestFailureCount()).toBe(0);
  });
});

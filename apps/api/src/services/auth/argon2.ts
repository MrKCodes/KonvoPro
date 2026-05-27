// Argon2id password hashing service (task 2.1).
//
// Realizes Requirements 1.1, 1.12, and design.md §18.2:
//   - 1.1  : password hashes are produced with Argon2id at m=64 MiB, t=3, p=4.
//   - 1.12 : the verify benchmark at API_Gateway startup MUST emit an alert
//            metric to Prometheus when it completes in less than 250 ms.
//   - 18.2 : `m=64 MiB, t=3, p=4`, benchmarked to >= 250 ms on host CPU at
//            startup, alert if below.
//
// Design notes:
//   - The module wraps the libsodium-backed `argon2` npm package (node-argon2,
//     the C++/Rust binding around the reference Argon2 implementation). We
//     do NOT roll our own KDF.
//   - Params are passed in explicitly (`Argon2Params`) so this module is
//     unit-testable. `createArgon2Service(params)` is the production wiring
//     consumed by `server.ts`, which pulls the values from `loadConfig()`.
//   - The hash output is the standard PHC-formatted string (`$argon2id$v=19$
//     m=...,t=...,p=...$<salt>$<hash>`). The params are embedded in the hash
//     itself, so future param changes do NOT invalidate previously-stored
//     hashes — `verify()` reads the params from the stored hash.
//   - Salt is 16 bytes of CSPRNG output (the library default; we do not
//     override `salt` in the options).
//   - The benchmark is intentionally tiny: hash a fresh password once,
//     time exactly one `verify()` call. We do not loop or warm up; per
//     §18.2 the alert condition is a single sub-250 ms pass at boot.
//
// CJS/ESM interop:
//   `argon2` is a CommonJS module. Under apps/api's ESM configuration
//   (`"type": "module"` + `verbatimModuleSyntax: true`) we use the default
//   import (`esModuleInterop` synthesizes it) and reference its members via
//   the default-export object. If a future toolchain bump rejects this,
//   switch to `import * as argon2 from 'argon2'` (named-namespace) — the
//   member access stays identical.

import argon2 from 'argon2';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Argon2id parameters. Per design.md §18.2 the production values are
 * `memoryKib = 65536` (64 MiB), `timeCost = 3`, `parallelism = 4`. Tests
 * may pass smaller values to keep the suite fast.
 *
 * `memoryKib` is the working-memory cost in KiB (`m` in the Argon2 paper),
 * `timeCost` is the number of iterations (`t`), `parallelism` is the number
 * of parallel lanes (`p`).
 */
export interface Argon2Params {
  readonly memoryKib: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

/**
 * Password hashing service. Both methods are async; both are CPU-bound and
 * intentionally slow per the configured parameters.
 *
 * `hash` returns a PHC-formatted encoded string that embeds the params,
 * salt, and digest. Callers persist this string verbatim.
 *
 * `verify` reads the params from the stored hash, so old hashes remain
 * verifiable across param upgrades.
 */
export interface Argon2Service {
  hash(password: string): Promise<string>;
  verify(passwordHash: string, password: string): Promise<boolean>;
}

/**
 * Result of a single boot-time verify benchmark.
 *
 * `durationMs` is the wall-clock time of one `verify()` call against a
 * freshly produced hash, measured via `process.hrtime.bigint()`.
 *
 * `underBudget === true` means the verify finished in **less than** 250 ms,
 * which per Requirement 1.12 is the alert condition (the host CPU is
 * fast enough that the configured params are weaker than intended).
 */
export interface Argon2BenchmarkResult {
  readonly durationMs: number;
  readonly underBudget: boolean;
}

/**
 * Sink for benchmark results. Phase 1 (this task) ships a console-based
 * default that emits a structured JSON line tagged with the Prometheus
 * metric name `konvo_argon2_verify_under_budget_total`. Phase 9 / task 10.1
 * will wire a real prom-client `Counter` and inject it here, replacing the
 * default observer without changing this module.
 */
export interface Argon2BenchmarkObserver {
  onBenchmarkResult(result: Argon2BenchmarkResult): void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Per Requirement 1.12 / design.md §18.2: the verify benchmark must take at
 * least 250 ms on the host CPU. A faster result triggers the alert.
 */
export const ARGON2_VERIFY_BUDGET_MS = 250;

/**
 * Prometheus metric name emitted by the default observer when the boot-time
 * verify benchmark completes in less than `ARGON2_VERIFY_BUDGET_MS`. Task
 * 10.1 will replace the console observer with a real prom-client counter
 * exposed under this exact name.
 */
export const ARGON2_VERIFY_UNDER_BUDGET_METRIC =
  'konvo_argon2_verify_under_budget_total';

// ---------------------------------------------------------------------------
// Service factory
// ---------------------------------------------------------------------------

/**
 * Construct an `Argon2Service` bound to a specific parameter set.
 *
 * The returned service uses `argon2id` exclusively (never `argon2i` or
 * `argon2d`) per design.md §18.2. The library generates a fresh 16-byte
 * salt for every `hash()` call by default; we do not override it.
 */
export function createArgon2Service(params: Argon2Params): Argon2Service {
  validateParams(params);

  return {
    async hash(password: string): Promise<string> {
      // `argon2.hash` returns the encoded PHC string by default
      // (`raw: false`), which embeds the algorithm, version, params, salt,
      // and digest. That string is what callers persist.
      return argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: params.memoryKib,
        timeCost: params.timeCost,
        parallelism: params.parallelism,
      });
    },

    async verify(passwordHash: string, password: string): Promise<boolean> {
      // `argon2.verify` reads the params from the encoded hash, so we do
      // not pass `memoryCost`/`timeCost`/`parallelism` here. Old hashes
      // remain verifiable after a param upgrade.
      return argon2.verify(passwordHash, password);
    },
  };
}

function validateParams(params: Argon2Params): void {
  // Sanity bounds. The config layer (apps/api/src/config.ts) already
  // enforces `ARGON2_M_KIB >= 16384`, `ARGON2_T >= 1`, `ARGON2_P >= 1`,
  // but tests construct params directly so we re-check defensively.
  if (!Number.isInteger(params.memoryKib) || params.memoryKib < 1) {
    throw new Error(
      `argon2 memoryKib must be a positive integer, got ${String(params.memoryKib)}`,
    );
  }
  if (!Number.isInteger(params.timeCost) || params.timeCost < 1) {
    throw new Error(
      `argon2 timeCost must be a positive integer, got ${String(params.timeCost)}`,
    );
  }
  if (!Number.isInteger(params.parallelism) || params.parallelism < 1) {
    throw new Error(
      `argon2 parallelism must be a positive integer, got ${String(params.parallelism)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Boot-time benchmark
// ---------------------------------------------------------------------------

/**
 * Sample password used by the boot-time benchmark. Length and entropy don't
 * matter for the benchmark — Argon2 work is dictated by the parameters,
 * not the input — but we keep it >= 12 chars so it would also satisfy the
 * production password-length policy if anyone reuses this string.
 */
const BENCHMARK_SAMPLE_PASSWORD = 'konvo-argon2-benchmark-sample';

/**
 * Run a single verify against a freshly-produced hash and report the
 * wall-clock duration. The caller (server bootstrap) feeds the result to
 * an observer that emits the Prometheus alert metric when underBudget.
 *
 * The hash step is intentionally NOT timed: we only care about the verify
 * cost because that's the path every login traverses on every attempt.
 */
export async function runArgon2VerifyBenchmark(
  svc: Argon2Service,
  params: Argon2Params,
): Promise<Argon2BenchmarkResult> {
  validateParams(params);

  const passwordHash = await svc.hash(BENCHMARK_SAMPLE_PASSWORD);

  const startNs = process.hrtime.bigint();
  const ok = await svc.verify(passwordHash, BENCHMARK_SAMPLE_PASSWORD);
  const endNs = process.hrtime.bigint();

  if (!ok) {
    // A failed self-verify indicates a broken argon2 binding — the
    // process should not start.
    throw new Error(
      'argon2 self-test failed: verify() returned false for a freshly produced hash',
    );
  }

  // ns -> ms with sub-millisecond precision. BigInt subtraction handles
  // wraparound-safe timestamps; we only convert to Number after dividing.
  const durationMs = Number(endNs - startNs) / 1_000_000;

  return {
    durationMs,
    underBudget: durationMs < ARGON2_VERIFY_BUDGET_MS,
  };
}

// ---------------------------------------------------------------------------
// Default observer (console; replaced by prom-client in task 10.1)
// ---------------------------------------------------------------------------

/**
 * Console-based fallback observer used until task 10.1 wires the real
 * prom-client `Counter`. Behavior:
 *
 *   - When `underBudget === true` (alert condition): emit a single
 *     structured JSON line on stderr via `console.warn`. The line is shaped
 *     like a pino record so the redacting logger from task 4.9 can ingest
 *     it without further transformation. The `metric` field carries the
 *     exact Prometheus counter name task 10.1 will register; this means
 *     observability dashboards can be authored against the final metric
 *     name now, even though the counter itself doesn't exist yet.
 *
 *   - When `underBudget === false`: emit an `info`-level line documenting
 *     the measured duration. Useful for ops to see the boot benchmark
 *     succeeded without scraping `/metrics`.
 *
 * This observer is exported as `defaultArgon2BenchmarkObserver` and is
 * what `server.ts` wires by default. Tests can pass a stub instead.
 */
export const defaultArgon2BenchmarkObserver: Argon2BenchmarkObserver = {
  onBenchmarkResult(result: Argon2BenchmarkResult): void {
    if (result.underBudget) {
      // Alert condition (Requirement 1.12). Use console.warn so the line
      // lands on stderr and Loki ingests it at WARN.
      console.warn(
        JSON.stringify({
          level: 'warn',
          msg: 'argon2 verify benchmark under budget; params are weaker than intended for this CPU',
          metric: ARGON2_VERIFY_UNDER_BUDGET_METRIC,
          metricKind: 'counter',
          metricInc: 1,
          durationMs: result.durationMs,
          budgetMs: ARGON2_VERIFY_BUDGET_MS,
        }),
      );
      return;
    }

    console.log(
      JSON.stringify({
        level: 'info',
        msg: 'argon2 verify benchmark within budget',
        durationMs: result.durationMs,
        budgetMs: ARGON2_VERIFY_BUDGET_MS,
      }),
    );
  },
};

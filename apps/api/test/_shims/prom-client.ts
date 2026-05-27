// Test-only shim for `prom-client`.
//
// The api package declares `prom-client` in its dependencies (used by
// `apps/api/src/obs/metrics.ts` for the Prometheus exposition endpoint
// — Requirement 18.1). The current pnpm-lockfile in this checkout is
// incomplete (a separate registry issue with `@livekit/server-sdk`
// blocks a full `pnpm install`), so vitest cannot resolve the bare
// specifier `prom-client` without help. We alias it to this shim from
// `vitest.config.ts` so test files can import any module that
// transitively pulls in `metrics.ts` without exploding at module-load.
//
// The shim implements just enough of `prom-client`'s surface that
// `metrics.ts` consumes during module evaluation:
//
//   - `Counter`, `Gauge`, `Histogram` constructors that accept the
//     same options shape as the real package and record `inc` / `set` /
//     `observe` calls into in-memory state. Counter/Gauge reset state
//     between tests; Histogram retains observations so timer-driven
//     tests can assert on them if they want to.
//   - `Registry` with `registerMetric`, async `metrics()` (returns
//     synthetic exposition text), and `clear()`.
//   - `collectDefaultMetrics(registry)` (no-op).
//
// Production builds always consume the real `prom-client` from npm;
// this shim is wired only via the alias in `vitest.config.ts` and
// never reaches a runtime artifact.

interface LabelValues {
  [key: string]: string | number;
}

class CounterShim {
  readonly name: string;
  count = 0;
  constructor(opts: { name: string }) {
    this.name = opts.name;
  }
  inc(arg1?: LabelValues | number, arg2?: number): void {
    const v = typeof arg1 === 'number' ? arg1 : (arg2 ?? 1);
    this.count += v;
  }
  reset(): void {
    this.count = 0;
  }
  labels(): CounterShim {
    return this;
  }
}

class GaugeShim {
  readonly name: string;
  value = 0;
  constructor(opts: { name: string }) {
    this.name = opts.name;
  }
  set(v: number): void {
    this.value = v;
  }
  inc(v = 1): void {
    this.value += v;
  }
  dec(v = 1): void {
    this.value -= v;
  }
  reset(): void {
    this.value = 0;
  }
  labels(): GaugeShim {
    return this;
  }
}

class HistogramShim {
  readonly name: string;
  observations: number[] = [];
  constructor(opts: { name: string }) {
    this.name = opts.name;
  }
  observe(v: number): void {
    this.observations.push(v);
  }
  startTimer(): () => number {
    const start = Date.now();
    return (): number => {
      const elapsed = (Date.now() - start) / 1000;
      this.observe(elapsed);
      return elapsed;
    };
  }
  reset(): void {
    this.observations = [];
  }
  labels(): HistogramShim {
    return this;
  }
}

class RegistryShim {
  readonly contentType = 'text/plain; version=0.0.4; charset=utf-8';
  #metrics: Array<{ name: string }> = [];
  registerMetric(m: { name: string }): void {
    this.#metrics.push(m);
  }
  async metrics(): Promise<string> {
    return this.#metrics.map((m) => `# HELP ${m.name}\n`).join('');
  }
  clear(): void {
    this.#metrics = [];
  }
  resetMetrics(): void {
    /* no-op */
  }
}

function collectDefaultMetricsShim(_args?: unknown): void {
  /* no-op */
}

const promClientShim = {
  Counter: CounterShim,
  Gauge: GaugeShim,
  Histogram: HistogramShim,
  Registry: RegistryShim,
  collectDefaultMetrics: collectDefaultMetricsShim,
  register: new RegistryShim(),
};

export default promClientShim;
export const Counter = CounterShim;
export const Gauge = GaugeShim;
export const Histogram = HistogramShim;
export const Registry = RegistryShim;
export const collectDefaultMetrics = collectDefaultMetricsShim;
export const register = new RegistryShim();

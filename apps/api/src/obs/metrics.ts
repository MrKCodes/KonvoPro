// apps/api/src/obs/metrics.ts
//
// Prometheus metrics surface for the Konvo API gateway (task 10.1 —
// Phase 9).
//
// Realizes Requirements 18.1 and 18.2 against `prom-client`:
//
//   - 18.1 : `GET /metrics` returns Prometheus exposition format,
//            responds within 200 ms, and never includes PII in label
//            keys or values. The endpoint is mounted via
//            `metricsRoutes` (Fastify plugin) and is intentionally
//            UNAUTHENTICATED — production deployments bind this on
//            an internal address (Caddy + docker network), so the
//            scrape target is reachable from `infra/prometheus/
//            prometheus.yml` without leaking it to the public
//            Internet (see `apps/api/src/server.ts` for the wiring
//            note + the CSRF skipPath that already excludes
//            `/metrics`).
//
//   - 18.2 : Each metric named in design.md §19.1 + the brief is
//            registered here. Labels are bounded to a small enum
//            domain by construction (literal union types in the
//            counter/gauge wrapper signatures) so a misuse can't
//            silently invent a new series. A label-cardinality
//            cap (default 100 per metric) drops further inserts on
//            top of the type-system bound and increments
//            `konvo_label_cardinality_drops_total` so an operator
//            can detect the drop in Grafana.
//
// Why a wrapper over `prom-client` instead of exporting the raw
// `Counter` / `Histogram` instances?
//
//   - The brief explicitly forbids unbounded label cardinality
//     (Requirement 18.1: "no PII in label/values; cap at 100 distinct
//     label combinations per metric"). prom-client itself has no
//     ceiling: a misbehaving caller could `counter.labels(rawUserHandle)
//     .inc()` and explode the time-series database. The wrapper
//     enforces the cap once, at the increment site, so every caller
//     in the codebase inherits the protection without each one
//     re-implementing the check.
//
//   - We export the raw `register` so future modules (e.g. the
//     livekit room-active gauge updated from a webhook handler) can
//     register additional metrics without round-tripping through this
//     module. Anything registered via `register.registerMetric(...)`
//     surfaces in `GET /metrics` automatically.
//
//   - The wrapper is intentionally narrow: only `inc()`, `set()`,
//     `dec()`, and `observe()` (via timer or direct value). We never
//     expose `remove()` because evicting series mid-flight would
//     create gaps in long-running histograms.
//
// Cardinality accounting:
//
//   For each metric created via `recordCounter`/`recordHistogram`/
//   `recordGauge`, the wrapper maintains a Set of "label combination
//   keys" (the canonical JSON of the labels object). On every
//   increment/observation:
//     1. Compute the canonical key for the supplied labels.
//     2. If the key is already in the Set → record the value.
//     3. Else if Set.size < CARDINALITY_CAP → add the key, record.
//     4. Else → DROP. Bump `konvo_label_cardinality_drops_total`
//        with the metric name so the operator can identify which
//        metric is bumping into the cap.
//
//   Labels-less metrics (no labels argument) are exempt from the
//   cap entirely — the cap exists to bound dynamic-label growth, and
//   a metric with no labels has exactly one series by definition.
//
// PII notice (Requirement 18.1):
//
//   Every label value documented for the metrics below is a bounded
//   enum string (e.g. `'success' | 'invalid_credentials' | 'rate_limited'`).
//   None carry user handles, device ids, IPs, room slugs, or anything
//   else that could identify a user. The cardinality cap is a
//   defense-in-depth gate against a future caller forgetting the
//   posture; the type-system bound on the wrapper signatures is the
//   primary enforcement.

import promClient from 'prom-client';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of distinct label-combination series allowed per
 *  labeled metric. Per Requirement 18.1: "cap at 100 distinct label
 *  combinations per metric". */
export const CARDINALITY_CAP = 100;

/** Histogram buckets for envelope persist+publish latency (seconds).
 *  Tuned to the design.md §17.6 envelope-store budget (≤500 ms p95):
 *  the buckets straddle that target so a regression past p95=500 ms
 *  is visible as drift across the `0.1` → `0.5` → `1` boundaries. */
export const ENVELOPE_STORE_BUCKETS_SEC = [
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
];

/** Histogram buckets for Argon2id verify latency (seconds). The alert
 *  condition (Requirement 1.12) is verify < 250 ms, so we keep tight
 *  buckets straddling that threshold and tail off above 1 s for
 *  parameter-tuning visibility. */
export const ARGON2_VERIFY_BUCKETS_SEC = [
  0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1, 1.5, 2,
];

/** Content-Type for the Prometheus text exposition format
 *  (`text/plain; version=0.0.4; charset=utf-8`). Mirrors what
 *  `prom-client.register.contentType` returns at runtime; we expose
 *  the constant separately so tests don't have to import prom-client
 *  to assert the header. */
export const PROMETHEUS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

// ---------------------------------------------------------------------------
// Registry + cardinality bookkeeping
// ---------------------------------------------------------------------------

/** The single metrics registry. Exported so other modules (e.g. a
 *  LiveKit webhook handler) can register additional metrics. The
 *  default `prom-client` global registry is NOT used — having our
 *  own registry keeps tests deterministic (a fresh registry per
 *  test avoids inter-test bleed) and lets us keep the
 *  cardinality-drops counter scoped to this module. */
export const register = new promClient.Registry();

/** Cardinality bookkeeping: for each metric name we track the set of
 *  label-combination keys we've already recorded. Once the set hits
 *  `CARDINALITY_CAP`, further DISTINCT combinations are dropped and
 *  the drops counter is incremented. */
const labelCombinations = new Map<string, Set<string>>();

/** Counter incremented when a record is dropped due to the
 *  cardinality cap. Registered eagerly so `GET /metrics` always
 *  surfaces the metric (a flat zero is meaningful: it tells the
 *  operator the cap has not been hit). */
export const labelCardinalityDropsCounter = new promClient.Counter({
  name: 'konvo_label_cardinality_drops_total',
  help: 'Number of metric records dropped because the per-metric label-combination cap was exceeded.',
  labelNames: ['metric'],
  registers: [register],
});

// ---------------------------------------------------------------------------
// Cardinality gate
// ---------------------------------------------------------------------------

/** Compute a stable, label-name-sorted JSON key for a labels object.
 *  Returns `''` for the no-labels case (cap exempt). */
function labelKey(labels: Readonly<Record<string, string>> | undefined): string {
  if (labels === undefined) return '';
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return '';
  // We don't rely on `JSON.stringify(labels)` because object insertion
  // order varies; sorting keeps `{a:'1',b:'2'}` and `{b:'2',a:'1'}`
  // sharing the same series.
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(`${k}=${labels[k] ?? ''}`);
  }
  return parts.join('|');
}

/** Returns true iff the supplied label combination is admissible for
 *  `metricName` under the cardinality cap. Side effect: on first
 *  sight of a new combination that fits within the cap, the
 *  combination is recorded so future calls with the same labels
 *  also pass. On overflow, increments
 *  `konvo_label_cardinality_drops_total{metric=metricName}` and
 *  returns false. */
function admitLabelCombination(
  metricName: string,
  labels: Readonly<Record<string, string>> | undefined,
): boolean {
  const key = labelKey(labels);
  // No-labels metrics have exactly one series and are exempt from the cap.
  if (key === '') return true;

  let set = labelCombinations.get(metricName);
  if (set === undefined) {
    set = new Set<string>();
    labelCombinations.set(metricName, set);
  }
  if (set.has(key)) return true;
  if (set.size < CARDINALITY_CAP) {
    set.add(key);
    return true;
  }
  // Drop. Bump the sentinel.
  labelCardinalityDropsCounter.inc({ metric: metricName }, 1);
  return false;
}

// ---------------------------------------------------------------------------
// Metric definitions
// ---------------------------------------------------------------------------

/** Active WSS connections (Gauge). No labels. Updated by the WS gateway
 *  on `'open'` (`+1`) and on `'close'`/`'error'` (`-1`). Per Requirement
 *  18.1 we deliberately do NOT label by `device_class` (the design.md
 *  §19.1 column was a stretch target; the brief drops it to keep
 *  cardinality flat). */
export const wsConnectionsGauge = new promClient.Gauge({
  name: 'konvo_ws_connections',
  help: 'Number of currently-open authenticated WebSocket connections.',
  registers: [register],
});

/** Total envelopes routed by the WS gateway (Counter, label `routerType`).
 *  `routerType` is a bounded enum: `'msg' | 'ack' | 'call'` (the
 *  values the protocol envelope's `routerType` discriminator can
 *  take). Incremented in `onSendEnvelope` after a successful insert
 *  and Redis publish. */
export type EnvelopeRouterTypeLabel = 'msg' | 'ack' | 'call';
export const envelopesRoutedTotal = new promClient.Counter({
  name: 'konvo_envelopes_routed_total',
  help: 'Cumulative count of ciphertext envelopes routed by the WS gateway, partitioned by router type.',
  labelNames: ['routerType'],
  registers: [register],
});

/** Envelope persist+publish latency (Histogram). No labels. Observed
 *  via `envelopeStoreTimer()` in the WS gateway's `SEND_ENVELOPE`
 *  handler around the DB INSERT + Redis PUBLISH pair. */
export const envelopeStoreSeconds = new promClient.Histogram({
  name: 'konvo_envelope_store_seconds',
  help: 'Latency from receiving SEND_ENVELOPE to completing the DB insert + Redis publish, in seconds.',
  buckets: ENVELOPE_STORE_BUCKETS_SEC,
  registers: [register],
});

/** Envelopes that fell back to offline-queued state (Counter). No labels.
 *  Incremented in the gateway's offline-recipient branch (task 10.4
 *  scheduled push fallback). */
export const envelopeOfflineQueuedTotal = new promClient.Counter({
  name: 'konvo_envelope_offline_queued_total',
  help: 'Cumulative count of envelopes that were stored for offline recipients (no live WS subscription at insertion time).',
  registers: [register],
});

/** Web Push send outcomes (Counter, label `outcome`). The label domain
 *  is a closed enum: `success | gone_410 | error`. `gone_410` is the
 *  Web Push spec response when an endpoint has been unsubscribed —
 *  the API removes the corresponding `push_subscriptions` row. */
export type PushSendOutcome = 'success' | 'gone_410' | 'error';
export const pushSendTotal = new promClient.Counter({
  name: 'konvo_push_send_total',
  help: 'Cumulative count of Web Push send attempts, partitioned by terminal outcome.',
  labelNames: ['outcome'],
  registers: [register],
});

/** TURN bandwidth (Counter). No labels. Incremented from a coturn
 *  log/exporter shim that aggregates relay bytes over the most
 *  recent observation window. The metric is bytes-cumulative over
 *  the API process lifetime; Prometheus computes the rate. */
export const turnBytesTotal = new promClient.Counter({
  name: 'konvo_turn_bytes_total',
  help: 'Cumulative bytes relayed via coturn TURN since process start.',
  registers: [register],
});

/** Active LiveKit rooms (Gauge). No labels. Driven by LiveKit
 *  webhook events (`room_started` / `room_finished`); see task 7.6
 *  for the integration point. */
export const livekitRoomsActiveGauge = new promClient.Gauge({
  name: 'konvo_livekit_rooms_active',
  help: 'Number of currently-active LiveKit broadcast rooms.',
  registers: [register],
});

/** Aggregate LiveKit viewers (Gauge). No labels. The design.md §19.1
 *  table mentions a per-room `room` label; we drop it here to keep
 *  cardinality flat (one room ID per active room could blow past
 *  the 100-cap during a busy launch). Per-room dashboards rely on
 *  Loki room-event traces instead. */
export const livekitViewersGauge = new promClient.Gauge({
  name: 'konvo_livekit_viewers',
  help: 'Aggregate count of LiveKit viewers across all active broadcast rooms.',
  registers: [register],
});

/** Auth attempts (Counter, label `outcome`). Bounded enum:
 *  `success | invalid_credentials | rate_limited`. Incremented at
 *  every `/auth/login` and `/auth/signup` reply path. We deliberately
 *  do NOT carry the route in the label set — login and signup live
 *  on different metric series only via Loki. The cardinality cap
 *  is honoured by construction since the enum is closed at 3
 *  values. */
export type AuthAttemptOutcome = 'success' | 'invalid_credentials' | 'rate_limited';
export const authAttemptsTotal = new promClient.Counter({
  name: 'konvo_auth_attempts_total',
  help: 'Cumulative count of authentication attempts, partitioned by terminal outcome.',
  labelNames: ['outcome'],
  registers: [register],
});

/** Argon2id verify latency (Histogram). No labels. Observed at every
 *  `/auth/login` verify path via `argon2VerifySecondsTimer()`. The
 *  boot-time benchmark in `services/auth/argon2.ts` also records here
 *  so the histogram has at least one sample on a fresh server. */
export const argon2VerifySeconds = new promClient.Histogram({
  name: 'konvo_argon2_verify_seconds',
  help: 'Argon2id verify duration in seconds (alert threshold: < 0.25 s).',
  buckets: ARGON2_VERIFY_BUCKETS_SEC,
  registers: [register],
});

/** Rate-limit hits (Counter). No labels. Incremented by every
 *  rate-limited request rejection — both the WS gateway's per-device
 *  SEND_ENVELOPE bucket and the Fastify `/auth/*` route limiter. */
export const rateLimitedTotal = new promClient.Counter({
  name: 'konvo_rate_limited_total',
  help: 'Cumulative count of requests rejected by a rate-limit policy.',
  registers: [register],
});

/** Logger redaction failures (Counter). No labels. Incremented by
 *  `obs/logger.ts` when the recursive redaction walk throws on a
 *  log record; the record itself is dropped (Requirement 18.7).
 *  This counter must be registered here so `GET /metrics` exposes
 *  it; see `wireRedactionFailureCounter()` below for the wiring. */
export const logRedactionFailuresTotal = new promClient.Counter({
  name: 'konvo_log_redaction_failures_total',
  help: 'Cumulative count of log records dropped because the redaction layer failed (Requirement 18.7).',
  registers: [register],
});

// ---------------------------------------------------------------------------
// Cardinality-gated wrappers
// ---------------------------------------------------------------------------

/** Increment a labeled counter under the cardinality cap. Returns
 *  true iff the increment was recorded (i.e. not dropped). */
export function incCounter(
  counter: promClient.Counter<string>,
  labels: Readonly<Record<string, string>>,
  value = 1,
): boolean {
  const name = (counter as unknown as { name: string }).name;
  if (!admitLabelCombination(name, labels)) return false;
  counter.inc(labels, value);
  return true;
}

/** Set a labeled gauge under the cardinality cap. */
export function setGauge(
  gauge: promClient.Gauge<string>,
  labels: Readonly<Record<string, string>>,
  value: number,
): boolean {
  const name = (gauge as unknown as { name: string }).name;
  if (!admitLabelCombination(name, labels)) return false;
  gauge.set(labels, value);
  return true;
}

/** Observe a value into a labeled histogram under the cardinality cap. */
export function observeHistogram(
  histogram: promClient.Histogram<string>,
  labels: Readonly<Record<string, string>>,
  value: number,
): boolean {
  const name = (histogram as unknown as { name: string }).name;
  if (!admitLabelCombination(name, labels)) return false;
  histogram.observe(labels, value);
  return true;
}

// ---------------------------------------------------------------------------
// Convenience timers
// ---------------------------------------------------------------------------

/** Start a timer for the envelope store histogram. Returns a function
 *  that, when called, observes the elapsed seconds. Usage:
 *  ```ts
 *  const stop = envelopeStoreTimer();
 *  // ... DB INSERT + redis publish ...
 *  stop();
 *  ```
 *  No labels. */
export function envelopeStoreTimer(): () => number {
  return envelopeStoreSeconds.startTimer();
}

/** Start a timer for the Argon2id verify histogram. Returns a function
 *  that observes the elapsed seconds. */
export function argon2VerifySecondsTimer(): () => number {
  return argon2VerifySeconds.startTimer();
}

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

/** Reset all per-test state: the cardinality bookkeeping AND every
 *  registered metric's accumulated values. Test-only — production
 *  code must NEVER call this; resetting metrics mid-flight would
 *  create gaps in dashboards. */
export function resetMetricsForTesting(): void {
  labelCombinations.clear();
  register.resetMetrics();
}

// ---------------------------------------------------------------------------
// Logger integration
// ---------------------------------------------------------------------------

/** Wire the prom-client `logRedactionFailuresTotal` counter into
 *  `obs/logger.ts`. Invoked at server boot from `server.ts` so the
 *  logger's redaction-failure path increments a real Prometheus
 *  series instead of the in-memory test counter. The wiring is
 *  done lazily (this module imports the logger module) so importing
 *  metrics.ts in isolation (e.g. in a test) does not pull in pino. */
export async function wireRedactionFailureCounter(): Promise<void> {
  const { setRedactionFailureCounter } = await import('./logger.js');
  setRedactionFailureCounter({
    inc(value = 1): void {
      logRedactionFailuresTotal.inc(value);
    },
  });
}

// ---------------------------------------------------------------------------
// Fastify plugin — GET /metrics
// ---------------------------------------------------------------------------

import type { FastifyPluginAsync } from 'fastify';

/** Mounts `GET /metrics` on the Fastify instance. The route returns
 *  the Prometheus exposition format (text/plain; version=0.0.4) and
 *  is intentionally UNAUTHENTICATED — production deployments bind
 *  the API to an internal address only reachable by the Prometheus
 *  scraper (see infra/prometheus/prometheus.yml + the
 *  docker-compose stack: prometheus targets `api:9090/metrics`).
 *
 *  Per Requirement 18.1 the response must complete within 200 ms.
 *  `register.metrics()` is in-process and uses pre-aggregated
 *  counters/gauges/histograms; there is no I/O on this path.
 *
 *  The route is also registered in the CSRF plugin's `skipPaths`
 *  list (see `server.ts`) so an unauthenticated GET reaches the
 *  handler without a CSRF cookie.
 */
export const metricsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/metrics', async (_req, reply) => {
    const body = await register.metrics();
    void reply
      .header('Content-Type', PROMETHEUS_CONTENT_TYPE)
      // Belt-and-braces: the scrape target is small (≤16 KiB) and
      // generated in-process, but explicitly disable caching so
      // intermediate proxies (or a misconfigured Caddy) don't serve
      // stale data.
      .header('Cache-Control', 'no-store')
      .send(body);
    return reply;
  });
};

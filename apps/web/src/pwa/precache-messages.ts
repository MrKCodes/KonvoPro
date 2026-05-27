// apps/web/src/pwa/precache-messages.ts
//
// Per-conversation precache retention rule (task 9.1, Requirement
// 14.3). Encodes the spec's "min(500 most recent, last-30-days)"
// rule for both DM threads and broadcast rooms in a single, pure
// helper that's testable without IndexedDB and reusable from the
// SW context (no Dexie imports here).
//
// What "precache" means in Konvo's design:
//   The messages live in IndexedDB (via Dexie). The SW doesn't
//   fetch DM/broadcast bytes — the wire frames are E2EE and would
//   never round-trip through `Cache.add()`. Instead, the
//   Web_Client retains the most recent slice in Dexie so an
//   offline reload renders cached threads (Requirement 14.2 / 14.3).
//   "Precache" here is therefore a retention rule applied
//   periodically, not a `cache.put()` over an HTTP response.
//
// The min() rule (Requirement 14.3 verbatim):
//   "the 500 most recent direct-message and broadcast messages per
//    conversation OR all messages from the last 30 days, whichever
//    is smaller."
//
//   Concretely, for each conversation we take:
//     keep = min(500, count(messages within last 30 days))
//   and retain the `keep` MOST RECENT messages. Older messages
//   beyond that window are eligible for eviction.
//
//   Why min and not max:
//     The user's storage budget is bounded; the spec deliberately
//     picks the smaller of the two windows so a low-traffic
//     conversation doesn't consume slot for stale year-old posts
//     and a high-traffic conversation doesn't blow past 500.

/**
 * Maximum messages retained per conversation. Aligned to
 * Requirement 14.3.
 */
export const MAX_MESSAGES_PER_CONVERSATION = 500;

/**
 * Retention window in milliseconds (30 days). Messages older than
 * `now - PRECACHE_RETENTION_WINDOW_MS` are candidates for
 * eviction.
 */
export const PRECACHE_RETENTION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Minimal shape every retainable record carries. Both
 * `MessageRow` (DMs) and `RoomPostRow` (broadcast posts) satisfy
 * this — the rule cares only about the timestamp.
 */
export interface PrecacheCandidate {
  readonly createdAt: number;
}

/**
 * Apply the "min(500, last-30-days)" rule to a single
 * conversation's message list and return the subset that should
 * be retained for offline use, sorted MOST RECENT FIRST.
 *
 * Inputs:
 *   `messages`  — every record we have for the conversation. Order
 *                 unspecified; this function sorts internally so
 *                 the caller doesn't have to. Empty array → empty
 *                 result.
 *   `now`       — wall-clock millis used as the upper bound of
 *                 the 30-day window. Defaults to `Date.now()`;
 *                 tests pin it for determinism.
 *
 * Returns the subset of `messages` (NOT a copy of each element —
 * the same references are returned) sorted by `createdAt` DESC.
 *
 * Properties verified by `pwa-precache-messages.test.ts`:
 *   - `result.length === min(MAX_PER_CONVERSATION, count(in_window))`
 *   - For every retained record `r` and every dropped record `d`,
 *     `r.createdAt >= d.createdAt` (we keep the newest).
 *   - For inputs of length ≤ MAX where every message is in window,
 *     every input is retained.
 *   - For inputs where no message is in window, the result is empty.
 *   - The function is total (never throws on any finite input).
 */
export function selectMessagesToRetain<T extends PrecacheCandidate>(
  messages: readonly T[],
  now: number = Date.now(),
): T[] {
  if (messages.length === 0) return [];

  const cutoff = now - PRECACHE_RETENTION_WINDOW_MS;

  // Step 1 — discard anything older than the 30-day window. The
  // rule explicitly bounds retention to "messages from the last 30
  // days", so a conversation with 1000 messages all older than 30
  // days yields zero retained.
  const inWindow = messages.filter((m) => m.createdAt >= cutoff);
  if (inWindow.length === 0) return [];

  // Step 2 — sort newest first. We can't assume the caller
  // delivered a sorted list (the messages repository's
  // `listAllForThread` sorts ASC; this rule wants DESC).
  // `.slice()` keeps the caller's array immutable.
  const newestFirst = inWindow.slice().sort(
    (a, b) => b.createdAt - a.createdAt,
  );

  // Step 3 — keep at most MAX_MESSAGES_PER_CONVERSATION. `.slice`
  // (rather than mutating with .length =) returns a fresh array
  // and is idempotent on inputs already at or below the cap.
  return newestFirst.slice(0, MAX_MESSAGES_PER_CONVERSATION);
}

/**
 * Apply the rule across a map of conversations and return the
 * SAME map shape with the retained subset per key. Used by the
 * eviction sweep that runs against Dexie tables: walk threads,
 * walk rooms, hand each conversation's candidates here, persist
 * the result.
 *
 * The function is intentionally generic so the same helper drives
 * both the DM and broadcast eviction paths.
 */
export function selectRetentionByConversation<T extends PrecacheCandidate>(
  byConversation: ReadonlyMap<string, readonly T[]>,
  now: number = Date.now(),
): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const [key, messages] of byConversation) {
    out.set(key, selectMessagesToRetain(messages, now));
  }
  return out;
}

/**
 * Compute the IDs of records to EVICT given the full set of
 * candidates and the retained subset. Identity comparison is via
 * the supplied `idOf` projector so the helper works for DM rows
 * (numeric `id`) and broadcast rows (string composite key)
 * uniformly.
 *
 * Returns the eviction set as an array preserving the original
 * iteration order of `messages`. Empty if every candidate is
 * retained.
 */
export function diffEviction<T extends PrecacheCandidate, ID>(
  messages: readonly T[],
  retained: readonly T[],
  idOf: (m: T) => ID,
): ID[] {
  if (messages.length === 0) return [];
  const retainedIds = new Set<ID>(retained.map(idOf));
  const evictions: ID[] = [];
  for (const m of messages) {
    const id = idOf(m);
    if (!retainedIds.has(id)) evictions.push(id);
  }
  return evictions;
}

// apps/web/test/pwa-precache-messages.test.ts
//
// Unit + property tests for the message retention rule that drives
// the PWA's offline precache (task 9.1, Requirement 14.3).
//
// The rule under test (`selectMessagesToRetain`) is pure: given a
// list of `{ createdAt }` records and a wall-clock `now`, return
// the subset retained for offline use. The rule has three
// observable properties:
//
//   1. CAP — `result.length <= MAX_MESSAGES_PER_CONVERSATION` for
//      every input.
//   2. WINDOW — every retained record's `createdAt` lies within
//      `[now - PRECACHE_RETENTION_WINDOW_MS, now]`.
//   3. NEWEST-FIRST — for any retained `r` and dropped `d`,
//      `r.createdAt >= d.createdAt`.
//
// We assert each property in a focused test rather than via
// fast-check generators here; the existing test harness in this
// package doesn't include fast-check, and the rule's behavior is
// well-covered by hand-picked corner cases (empty, exactly at the
// cap, exactly on the cutoff). When task 4.1 brings fast-check to
// `apps/web` we can expand into property tests.

import { describe, expect, it } from 'vitest';

import {
  diffEviction,
  MAX_MESSAGES_PER_CONVERSATION,
  PRECACHE_RETENTION_WINDOW_MS,
  selectMessagesToRetain,
  selectRetentionByConversation,
} from '../src/pwa/precache-messages.js';

const NOW = 1_700_000_000_000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

interface Msg {
  readonly id: number;
  readonly createdAt: number;
}

function mkMsg(id: number, createdAt: number): Msg {
  return { id, createdAt };
}

describe('selectMessagesToRetain — cap rule (Requirement 14.3)', () => {
  it('returns an empty array for an empty input', () => {
    expect(selectMessagesToRetain([], NOW)).toEqual([]);
  });

  it('retains every message when count is below the cap and all are in window', () => {
    const messages = Array.from({ length: 100 }, (_, i) =>
      mkMsg(i, NOW - i * 1_000),
    );
    const retained = selectMessagesToRetain(messages, NOW);
    expect(retained).toHaveLength(100);
    // Every input id present in result.
    expect(new Set(retained.map((m) => m.id))).toEqual(
      new Set(messages.map((m) => m.id)),
    );
  });

  it('caps retention at MAX_MESSAGES_PER_CONVERSATION when all are in window', () => {
    const total = MAX_MESSAGES_PER_CONVERSATION + 250;
    const messages = Array.from({ length: total }, (_, i) =>
      mkMsg(i, NOW - i * 1_000),
    );
    const retained = selectMessagesToRetain(messages, NOW);
    expect(retained).toHaveLength(MAX_MESSAGES_PER_CONVERSATION);
    // Every retained message is newer than every dropped message.
    const retainedIds = new Set(retained.map((m) => m.id));
    const dropped = messages.filter((m) => !retainedIds.has(m.id));
    const minRetained = Math.min(...retained.map((m) => m.createdAt));
    const maxDropped = Math.max(...dropped.map((m) => m.createdAt));
    expect(minRetained).toBeGreaterThanOrEqual(maxDropped);
  });

  it('respects the min(500, last-30-days) — drops anything older than 30 days', () => {
    // 100 messages within 30 days, 100 messages older than 30 days.
    const inWindow = Array.from({ length: 100 }, (_, i) =>
      mkMsg(i, NOW - i * 1_000),
    );
    const stale = Array.from({ length: 100 }, (_, i) =>
      mkMsg(1000 + i, NOW - PRECACHE_RETENTION_WINDOW_MS - (i + 1) * 1_000),
    );
    const retained = selectMessagesToRetain([...inWindow, ...stale], NOW);
    expect(retained).toHaveLength(100);
    // No stale messages survive.
    for (const m of retained) {
      expect(m.createdAt).toBeGreaterThanOrEqual(
        NOW - PRECACHE_RETENTION_WINDOW_MS,
      );
    }
  });

  it('returns nothing when every message predates the 30-day window', () => {
    const messages = Array.from({ length: 600 }, (_, i) =>
      mkMsg(i, NOW - PRECACHE_RETENTION_WINDOW_MS - (i + 1) * 1_000),
    );
    expect(selectMessagesToRetain(messages, NOW)).toHaveLength(0);
  });

  it('keeps a message exactly at the cutoff boundary', () => {
    // The rule uses `>=` against `now - WINDOW`, so a message
    // whose `createdAt` equals the cutoff is still retained.
    const cutoff = NOW - PRECACHE_RETENTION_WINDOW_MS;
    const onBoundary = mkMsg(1, cutoff);
    expect(selectMessagesToRetain([onBoundary], NOW)).toEqual([onBoundary]);
  });

  it('drops a message one millisecond past the cutoff', () => {
    const cutoff = NOW - PRECACHE_RETENTION_WINDOW_MS;
    const justOutside = mkMsg(1, cutoff - 1);
    expect(selectMessagesToRetain([justOutside], NOW)).toEqual([]);
  });

  it('returns retained messages newest-first', () => {
    const messages = [
      mkMsg(1, NOW - 5 * MS_PER_DAY),
      mkMsg(2, NOW - 1 * MS_PER_DAY),
      mkMsg(3, NOW - 3 * MS_PER_DAY),
      mkMsg(4, NOW - 0),
    ];
    const retained = selectMessagesToRetain(messages, NOW);
    expect(retained.map((m) => m.id)).toEqual([4, 2, 3, 1]);
  });

  it('does not mutate the input array', () => {
    const messages = [
      mkMsg(1, NOW - 1_000),
      mkMsg(2, NOW - 2_000),
    ];
    const before = messages.slice();
    selectMessagesToRetain(messages, NOW);
    expect(messages).toEqual(before);
  });
});

describe('selectRetentionByConversation', () => {
  it('applies the rule independently per conversation key', () => {
    const conv1 = Array.from({ length: 5 }, (_, i) => mkMsg(i, NOW - i * 1_000));
    const conv2 = Array.from({ length: 5 }, (_, i) =>
      mkMsg(100 + i, NOW - PRECACHE_RETENTION_WINDOW_MS - (i + 1) * 1_000),
    );
    const out = selectRetentionByConversation(
      new Map([
        ['c1', conv1],
        ['c2', conv2],
      ]),
      NOW,
    );
    expect(out.get('c1')).toHaveLength(5);
    expect(out.get('c2')).toHaveLength(0);
  });

  it('returns empty map for empty input', () => {
    expect(selectRetentionByConversation(new Map(), NOW).size).toBe(0);
  });
});

describe('diffEviction', () => {
  it('returns ids of messages NOT in the retained subset', () => {
    const messages = [mkMsg(1, NOW), mkMsg(2, NOW - 1), mkMsg(3, NOW - 2)];
    const retained = [messages[0]!, messages[2]!];
    expect(diffEviction(messages, retained, (m) => m.id)).toEqual([2]);
  });

  it('returns an empty list when every message is retained', () => {
    const messages = [mkMsg(1, NOW), mkMsg(2, NOW - 1)];
    expect(diffEviction(messages, messages, (m) => m.id)).toEqual([]);
  });

  it('returns every id when retained is empty', () => {
    const messages = [mkMsg(1, NOW), mkMsg(2, NOW - 1)];
    expect(diffEviction(messages, [], (m) => m.id)).toEqual([1, 2]);
  });
});

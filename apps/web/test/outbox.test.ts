// apps/web/test/outbox.test.ts
//
// Unit tests for the Dexie-backed outbox repository (task 3.7).
//
// Coverage map:
//   - `enqueue` round-trips a row and returns it with a numeric id.
//   - FIFO eviction at the 1000-entry cap (requirement 4.8).
//   - 7-day age eviction (requirement 4.8).
//   - `listInOrder` returns rows in primary-key ASC order — the
//     replay-on-reconnect ordering invariant (requirement 4.9).
//   - `deleteByClientNonce` removes the matching row.
//   - `enqueue` is idempotent on duplicate `clientNonce`.
//
// Tests run under jsdom + fake-indexeddb so the real Dexie code
// path is exercised. Each test uses a unique DB name to avoid the
// global fake-indexeddb state bleeding between cases.

import { afterEach, describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import {
  DexieOutboxStore,
  OUTBOX_MAX_AGE_MS,
  OUTBOX_MAX_ENTRIES,
} from '../src/db/repositories/outbox.js';
import { KonvoDb } from '../src/db/schema.js';

let activeDb: KonvoDb | null = null;
function freshDb(): KonvoDb {
  const name = `konvo-test-outbox-${Math.random().toString(36).slice(2)}`;
  activeDb = new KonvoDb(name);
  return activeDb;
}

afterEach(async () => {
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

function makeEnvelope(seed: number): CiphertextEnvelope {
  return {
    sessionId: `session-${seed}`,
    senderDeviceId: `sender-${seed}`,
    recipientDeviceId: `recipient-${seed}`,
    type: EnvelopeRouterType.MESSAGE,
    ciphertext: new Uint8Array([seed & 0xff, (seed >> 8) & 0xff]),
  };
}

describe('DexieOutboxStore.enqueue', () => {
  it('persists a row and returns it with an auto-assigned id', async () => {
    const store = new DexieOutboxStore(freshDb());
    const entry = await store.enqueue({
      clientNonce: 'nonce-1',
      envelope: makeEnvelope(1),
      enqueuedAt: 1_700_000_000_000,
    });
    expect(entry.id).toBeGreaterThan(0);
    expect(entry.clientNonce).toBe('nonce-1');
    expect(entry.retryCount).toBe(0);
    expect(entry.envelope.sessionId).toBe('session-1');
  });

  it('is idempotent on duplicate clientNonce', async () => {
    const store = new DexieOutboxStore(freshDb());
    const first = await store.enqueue({
      clientNonce: 'dup-nonce',
      envelope: makeEnvelope(1),
    });
    const second = await store.enqueue({
      clientNonce: 'dup-nonce',
      envelope: makeEnvelope(2),
    });
    expect(second.id).toBe(first.id);
    expect(await store.count()).toBe(1);
    // Original envelope is preserved (no clobber).
    expect(second.envelope.sessionId).toBe('session-1');
  });
});

describe('DexieOutboxStore.listInOrder', () => {
  it('returns rows in primary-key ASC order (FIFO)', async () => {
    // Inject a frozen clock so the age sweep doesn't see our
    // synthetic timestamps as "older than 7 days".
    const clock = 1_700_000_000_000;
    const store = new DexieOutboxStore(freshDb(), () => clock);
    for (let i = 0; i < 5; i += 1) {
      await store.enqueue({
        clientNonce: `nonce-${i}`,
        envelope: makeEnvelope(i),
        enqueuedAt: clock - 1_000 + i,
      });
    }
    const list = await store.listInOrder();
    expect(list).toHaveLength(5);
    for (let i = 0; i < 5; i += 1) {
      expect(list[i]!.clientNonce).toBe(`nonce-${i}`);
    }
  });
});

describe('DexieOutboxStore FIFO capacity eviction', () => {
  it('evicts the oldest rows once the table exceeds OUTBOX_MAX_ENTRIES', async () => {
    // To keep this test fast we use a small artificial cap by
    // pre-loading the table with synthetic rows up to OUTBOX_MAX_ENTRIES,
    // then enqueuing one more row to force the eviction sweep. We
    // can't override the constant cleanly without a constructor
    // arg, so we run the full 1000+1 cycle. That's still fast under
    // fake-indexeddb (well under a second on a laptop).
    //
    // We freeze the clock so the age sweep doesn't drop our
    // synthetic rows alongside the FIFO sweep.
    const clock = 1_700_000_000_000;
    const store = new DexieOutboxStore(freshDb(), () => clock);
    for (let i = 0; i < OUTBOX_MAX_ENTRIES; i += 1) {
      await store.enqueue({
        clientNonce: `nonce-${i}`,
        envelope: makeEnvelope(i),
        enqueuedAt: clock - 5_000 + i,
      });
    }
    expect(await store.count()).toBe(OUTBOX_MAX_ENTRIES);

    // The oldest row should be `nonce-0`. Adding a new row pushes
    // the count over the cap; the sweep should drop the oldest.
    await store.enqueue({
      clientNonce: 'nonce-overflow',
      envelope: makeEnvelope(9_999),
      enqueuedAt: clock,
    });

    expect(await store.count()).toBe(OUTBOX_MAX_ENTRIES);
    const survivors = await store.listInOrder();
    // The very first row (`nonce-0`) should be gone; the new row
    // should be the last entry in FIFO order.
    expect(survivors.find((e) => e.clientNonce === 'nonce-0')).toBeUndefined();
    expect(survivors[survivors.length - 1]!.clientNonce).toBe('nonce-overflow');
  }, 30_000);
});

describe('DexieOutboxStore age-based eviction', () => {
  it('evicts rows older than OUTBOX_MAX_AGE_MS on the next enqueue', async () => {
    // Inject a controlled clock so we can synthesise a 7-day-old
    // row without waiting.
    let clock = 1_700_000_000_000;
    const store = new DexieOutboxStore(freshDb(), () => clock);

    // Enqueue a fresh row first so the age sweep on subsequent
    // enqueues has something to compare against.
    await store.enqueue({
      clientNonce: 'fresh-nonce-1',
      envelope: makeEnvelope(2),
      enqueuedAt: clock - 1_000,
    });

    // Manually back-date a row so it sits past the 7-day cutoff
    // *without* triggering an enqueue-time sweep that would catch
    // it before we want.
    await activeDb!.outbox.add({
      clientNonce: 'old-nonce',
      envelope: makeEnvelope(1),
      enqueuedAt: clock - OUTBOX_MAX_AGE_MS - 1,
      retryCount: 0,
    });
    expect(await store.count()).toBe(2);

    // Advance the clock by a millisecond and enqueue a brand new
    // row. The age sweep on `enqueue` should drop `old-nonce`.
    clock += 1;
    await store.enqueue({
      clientNonce: 'fresh-nonce-2',
      envelope: makeEnvelope(3),
      enqueuedAt: clock,
    });

    const survivors = await store.listInOrder();
    expect(survivors.map((e) => e.clientNonce)).toEqual([
      'fresh-nonce-1',
      'fresh-nonce-2',
    ]);
  });

  it('sweepAged is idempotent and reports the number of removed rows', async () => {
    let clock = 1_700_000_000_000;
    const store = new DexieOutboxStore(freshDb(), () => clock);

    await store.enqueue({
      clientNonce: 'fresh',
      envelope: makeEnvelope(1),
      enqueuedAt: clock,
    });
    // Bypass the enqueue-time sweep by inserting the stale row
    // directly via the underlying Dexie table.
    await activeDb!.outbox.add({
      clientNonce: 'stale',
      envelope: makeEnvelope(2),
      enqueuedAt: clock - OUTBOX_MAX_AGE_MS - 1,
      retryCount: 0,
    });
    // Advance the clock by 1ms so the sweep cutoff strictly
    // exceeds the stale row's enqueuedAt (the sweep uses `<`).
    clock += 1;

    expect(await store.sweepAged()).toBe(1);
    expect(await store.sweepAged()).toBe(0);
    const survivors = await store.listInOrder();
    expect(survivors.map((e) => e.clientNonce)).toEqual(['fresh']);
  });
});

describe('DexieOutboxStore.deleteByClientNonce', () => {
  it('removes the matching row', async () => {
    const store = new DexieOutboxStore(freshDb());
    await store.enqueue({
      clientNonce: 'a',
      envelope: makeEnvelope(1),
    });
    await store.enqueue({
      clientNonce: 'b',
      envelope: makeEnvelope(2),
    });
    await store.deleteByClientNonce('a');
    const survivors = await store.listInOrder();
    expect(survivors.map((e) => e.clientNonce)).toEqual(['b']);
  });

  it('is idempotent on a missing clientNonce', async () => {
    const store = new DexieOutboxStore(freshDb());
    await expect(
      store.deleteByClientNonce('does-not-exist'),
    ).resolves.toBeUndefined();
  });
});

describe('DexieOutboxStore.recordReplayAttempt', () => {
  it('bumps retryCount and stamps lastTryAt', async () => {
    let clock = 1_700_000_000_000;
    const store = new DexieOutboxStore(freshDb(), () => clock);
    const entry = await store.enqueue({
      clientNonce: 'r1',
      envelope: makeEnvelope(1),
      enqueuedAt: clock,
    });
    expect(entry.retryCount).toBe(0);

    clock += 5_000;
    await store.recordReplayAttempt('r1');
    const after = await store.findByClientNonce('r1');
    expect(after?.retryCount).toBe(1);
    expect(after?.lastTryAt).toBe(clock);
  });
});

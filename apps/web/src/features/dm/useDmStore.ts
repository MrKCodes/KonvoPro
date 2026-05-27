// apps/web/src/features/dm/useDmStore.ts
//
// Lightweight React hooks that surface the Dexie-backed DM data
// through `useSyncExternalStore`. The store of record is still
// the Dexie repositories owned by `DmController`; these hooks
// pull a snapshot, expose it to React, and re-pull whenever the
// controller emits a change.
//
// The hooks intentionally avoid Suspense or React Query — Dexie
// reads are quick under jsdom/fake-indexeddb and a plain
// "render with `null` until first snapshot lands" loop keeps
// the test surface mock-free.

import { useCallback, useEffect, useState } from 'react';

import type { Message } from '../../db/repositories/messages.js';
import type { Thread } from '../../db/repositories/threads.js';
import type { DmController } from './controller.js';

/**
 * Pull-style hook that returns the most recent thread list from
 * `DmController.listThreads()`. Re-fetches on every controller
 * change. Returns `null` until the first fetch resolves so
 * components can render a "Loading…" placeholder; subsequent
 * empty states resolve to `[]`.
 */
export function useDmThreads(controller: DmController): readonly Thread[] | null {
  const [threads, setThreads] = useState<readonly Thread[] | null>(null);

  const refresh = useCallback((): void => {
    void controller.listThreads().then((next) => setThreads(next));
  }, [controller]);

  useEffect(() => {
    refresh();
    return controller.subscribe(() => refresh());
  }, [controller, refresh]);

  return threads;
}

/**
 * Pull-style hook for the messages in a single thread. Returns
 * `null` until the first fetch resolves; otherwise returns the
 * full ascending message list.
 *
 * `threadId` may be `null` to indicate "no thread selected" —
 * in that case the hook returns `null` and skips fetching.
 */
export function useDmMessages(
  controller: DmController,
  threadId: string | null,
  limit?: number,
): readonly Message[] | null {
  const [messages, setMessages] = useState<readonly Message[] | null>(null);

  const refresh = useCallback((): void => {
    if (threadId === null) {
      setMessages(null);
      return;
    }
    void controller
      .listMessagesForThread(threadId, limit)
      .then((next) => setMessages(next));
  }, [controller, threadId, limit]);

  useEffect(() => {
    refresh();
    return controller.subscribe((change) => {
      // Cheap optimisation: skip the round-trip if the change
      // is scoped to a different thread. The DM controller
      // always populates `threadId` for thread-scoped events.
      if (
        change.threadId !== undefined &&
        change.threadId !== threadId
      ) {
        return;
      }
      refresh();
    });
  }, [controller, threadId, refresh]);

  return messages;
}

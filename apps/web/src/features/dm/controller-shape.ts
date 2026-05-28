// apps/web/src/features/dm/controller-shape.ts
//
// Structural interface that both `DmController` (Phase-3 libsignal)
// and `PlaintextDmController` (Phase-2 transitional) implement.
//
// Why a separate interface rather than picking one of the classes
// as the contract: TypeScript's structural compatibility breaks
// across classes that declare ECMAScript private fields (`#x`)
// because the # creates a brand. A shared interface restores
// duck-typing so the React components (ThreadList, ThreadView,
// Composer) can accept either controller without `as unknown as`
// casts.

import type { Message } from '../../db/repositories/messages.js';
import type { Thread } from '../../db/repositories/threads.js';

export interface DmChange {
  readonly kind:
    | 'message_inserted'
    | 'message_state_changed'
    | 'thread_updated';
  readonly threadId?: string;
  readonly messageId?: number;
}

export type DmChangeListener = (change: DmChange) => void;

/** Common surface consumed by ThreadList / ThreadView / Composer.
 *  Both `DmController` and `PlaintextDmController` satisfy it. */
export interface DmControllerLike {
  subscribe(listener: DmChangeListener): () => void;
  listThreads(): Promise<readonly Thread[]>;
  listMessagesForThread(
    threadId: string,
    limit?: number,
  ): Promise<readonly Message[]>;
  sendMessage(args: {
    readonly peerUserId: string;
    readonly peerHandle?: string;
    readonly body: Uint8Array;
  }): Promise<Message>;
  retry(messageId: number): Promise<Message | null>;
  markFailed(messageId: number): Promise<Message | null>;
}

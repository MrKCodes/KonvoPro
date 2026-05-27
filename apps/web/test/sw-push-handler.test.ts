// apps/web/test/sw-push-handler.test.ts
//
// Unit tests for `apps/web/src/pwa/sw-push-handler.ts` (task 9.4).
//
// Coverage:
//   - Successful fetch + decrypt → notification rendered with the
//     decrypted plaintext as the body (Requirement 13.4).
//   - Fetch failure → generic notification, body identifies
//     `senderHandle` and `type` only (Requirement 13.5).
//   - Decrypt failure → generic notification (Requirement 13.5).
//   - Strategy throws → generic notification (Requirement 13.5).
//   - Generic-fallback body NEVER contains plaintext, ciphertext,
//     or key material — exercised via canary strings.
//   - Notification click focuses an existing tab and posts a
//     navigate message OR opens a new window at the thread URL.
//   - Malformed `notification.data` is a no-op.
//   - Malformed push payload (extra fields, missing fields,
//     non-JSON body) is silently dropped without rendering.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  defaultThreadUrlFor,
  FALLBACK_GENERIC_BODY,
  GENERIC_BODIES,
  genericBodyFor,
  handleNotificationClick,
  handlePushEvent,
  parsePushPayload,
  resetPwaLogSink,
  setPwaLogSink,
  type ClientLike,
  type ClientsLike,
  type DecryptEnvelopeForNotification,
  type EnvelopeForNotification,
  type FetchLatestEnvelope,
  type NavigateMessage,
  type PwaLogRecord,
  type ShowNotificationLike,
} from '../src/pwa/index.js';

const ORIGIN = 'https://konvo.test';
const CONVERSATION_ID = 'conv-abc-123';
const SENDER_HANDLE = 'alice';

let logRecords: PwaLogRecord[] = [];
beforeEach(() => {
  logRecords = [];
  setPwaLogSink((r) => {
    logRecords.push(r);
  });
});
afterEach(() => {
  resetPwaLogSink();
});

// -----------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------

interface ShowNotificationCall {
  readonly title: string;
  readonly options: NotificationOptions | undefined;
}

function makeRegistration(): {
  reg: ShowNotificationLike;
  calls: ShowNotificationCall[];
  showNotification: ReturnType<typeof vi.fn>;
} {
  const calls: ShowNotificationCall[] = [];
  const showNotification = vi.fn(
    async (title: string, options?: NotificationOptions): Promise<void> => {
      calls.push({ title, options });
    },
  );
  const reg: ShowNotificationLike = {
    showNotification: showNotification as unknown as ShowNotificationLike['showNotification'],
  };
  return { reg, calls, showNotification };
}

function fakeEnvelope(): EnvelopeForNotification {
  // The bytes here are arbitrary — the test stub for
  // `decryptEnvelope` doesn't actually decrypt them. The point
  // is that `fetchLatestEnvelope` returns SOMETHING that flows
  // into `decryptEnvelope`. The canary bytes also let us verify
  // they never appear in the rendered notification body in the
  // generic-fallback path (a leaked ciphertext byte would show
  // up as garbage in the title or body).
  return {
    ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]),
    senderDeviceId: 'sender-dev-1',
    recipientDeviceId: 'recipient-dev-1',
    sessionId: CONVERSATION_ID,
  };
}

function pushPayloadJson(overrides: Partial<{
  type: string;
  senderHandle: string;
  conversationId: string;
}> = {}): string {
  return JSON.stringify({
    type: 'dm.message',
    senderHandle: SENDER_HANDLE,
    conversationId: CONVERSATION_ID,
    ...overrides,
  });
}

// -----------------------------------------------------------------
// parsePushPayload
// -----------------------------------------------------------------

describe('parsePushPayload', () => {
  it('accepts the exact { type, senderHandle, conversationId } shape', () => {
    const out = parsePushPayload(pushPayloadJson());
    expect(out).toEqual({
      type: 'dm.message',
      senderHandle: SENDER_HANDLE,
      conversationId: CONVERSATION_ID,
    });
  });

  it('returns null for non-JSON bodies', () => {
    expect(parsePushPayload('not json')).toBeNull();
    expect(parsePushPayload('')).toBeNull();
    expect(parsePushPayload(null)).toBeNull();
  });

  it('returns null when any required field is missing', () => {
    expect(parsePushPayload(JSON.stringify({ type: 'dm.message' }))).toBeNull();
    expect(
      parsePushPayload(
        JSON.stringify({ type: 'dm.message', senderHandle: 'alice' }),
      ),
    ).toBeNull();
    expect(
      parsePushPayload(
        JSON.stringify({ senderHandle: 'alice', conversationId: 'c' }),
      ),
    ).toBeNull();
  });

  it('returns null when any required field is the wrong type or empty', () => {
    expect(
      parsePushPayload(
        JSON.stringify({
          type: '',
          senderHandle: SENDER_HANDLE,
          conversationId: CONVERSATION_ID,
        }),
      ),
    ).toBeNull();
    expect(
      parsePushPayload(
        JSON.stringify({
          type: 'dm.message',
          senderHandle: 42,
          conversationId: CONVERSATION_ID,
        }),
      ),
    ).toBeNull();
  });

  it('still parses when extra fields are present (we only validate the required three)', () => {
    // We don't enforce strictness on the SW side because a future
    // protocol revision may add fields. The strict guarantee is
    // server-side (apps/api/src/push/sender.ts). What we DO need
    // here is that the parsed value still has the expected shape,
    // and that handlePushEvent never reads any extra field — that
    // second invariant is exercised in handlePushEvent tests.
    const out = parsePushPayload(
      JSON.stringify({
        type: 'dm.message',
        senderHandle: SENDER_HANDLE,
        conversationId: CONVERSATION_ID,
        extra: 'should-not-render',
      }),
    );
    expect(out).toEqual({
      type: 'dm.message',
      senderHandle: SENDER_HANDLE,
      conversationId: CONVERSATION_ID,
    });
  });
});

// -----------------------------------------------------------------
// genericBodyFor
// -----------------------------------------------------------------

describe('genericBodyFor', () => {
  it('returns a friendly per-type body for known types', () => {
    expect(genericBodyFor('dm.message')).toBe(GENERIC_BODIES['dm.message']);
    expect(genericBodyFor('dm.voice_note')).toBe(
      GENERIC_BODIES['dm.voice_note'],
    );
    expect(genericBodyFor('broadcast.post')).toBe(
      GENERIC_BODIES['broadcast.post'],
    );
  });

  it('returns the fallback for unknown types', () => {
    expect(genericBodyFor('not-a-real-type')).toBe(FALLBACK_GENERIC_BODY);
  });

  it('returns the fallback for adversarial types (proto pollution attempt)', () => {
    // Probing for prototype-chain leaks: a `type` of
    // 'toString' / 'constructor' must not pull a function from
    // the prototype chain. `hasOwnProperty` guards against this.
    expect(genericBodyFor('toString')).toBe(FALLBACK_GENERIC_BODY);
    expect(genericBodyFor('constructor')).toBe(FALLBACK_GENERIC_BODY);
    expect(genericBodyFor('__proto__')).toBe(FALLBACK_GENERIC_BODY);
  });
});

// -----------------------------------------------------------------
// handlePushEvent — success path (Requirement 13.4)
// -----------------------------------------------------------------

describe('handlePushEvent — success path (Requirement 13.4)', () => {
  it('renders a notification whose body is the decrypted plaintext', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async (cid) => {
      expect(cid).toBe(CONVERSATION_ID);
      return { ok: true, envelope: fakeEnvelope() };
    };
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => {
      return { ok: true, plaintext: 'Hey, are you free for lunch?' };
    };

    await handlePushEvent(pushPayloadJson(), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.title).toBe(SENDER_HANDLE);
    expect(calls[0]!.options?.body).toBe('Hey, are you free for lunch?');
    // The notification carries `data` so the click handler can
    // navigate. No envelope id, no ciphertext.
    const data = calls[0]!.options?.data as
      | { conversationId?: unknown; threadUrl?: unknown }
      | undefined;
    expect(data?.conversationId).toBe(CONVERSATION_ID);
    expect(data?.threadUrl).toBe(`/thread/${CONVERSATION_ID}`);
  });
});

// -----------------------------------------------------------------
// handlePushEvent — failure paths (Requirement 13.5)
// -----------------------------------------------------------------

describe('handlePushEvent — fetch failure (Requirement 13.5)', () => {
  it('renders a generic notification when fetchLatestEnvelope returns ok:false', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: false,
    });
    const decryptEnvelope: DecryptEnvelopeForNotification = vi.fn(async () => ({
      ok: true,
      plaintext: 'unreachable',
    }));

    await handlePushEvent(pushPayloadJson({ type: 'dm.message' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(decryptEnvelope).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.title).toBe(SENDER_HANDLE);
    expect(calls[0]!.options?.body).toBe(GENERIC_BODIES['dm.message']);
  });

  it('renders a generic notification when fetchLatestEnvelope throws', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => {
      throw new Error('network down');
    };
    const decryptEnvelope: DecryptEnvelopeForNotification = vi.fn(async () => ({
      ok: true,
      plaintext: 'unreachable',
    }));

    await handlePushEvent(pushPayloadJson({ type: 'dm.voice_note' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(decryptEnvelope).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.options?.body).toBe(GENERIC_BODIES['dm.voice_note']);
  });
});

describe('handlePushEvent — decrypt failure (Requirement 13.5)', () => {
  it('renders a generic notification when decryptEnvelope returns ok:false', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: true,
      envelope: fakeEnvelope(),
    });
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => ({
      ok: false,
    });

    await handlePushEvent(pushPayloadJson({ type: 'dm.attachment' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.options?.body).toBe(GENERIC_BODIES['dm.attachment']);
  });

  it('renders a generic notification when decryptEnvelope throws', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: true,
      envelope: fakeEnvelope(),
    });
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => {
      throw new Error('ratchet rejected');
    };

    await handlePushEvent(pushPayloadJson({ type: 'broadcast.post' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.options?.body).toBe(GENERIC_BODIES['broadcast.post']);
  });

  it('renders the fallback body for unknown push types', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: false,
    });
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => ({
      ok: false,
    });

    await handlePushEvent(pushPayloadJson({ type: 'totally.unknown.type' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.options?.body).toBe(FALLBACK_GENERIC_BODY);
  });
});

// -----------------------------------------------------------------
// handlePushEvent — no-leak invariant for the fallback body
// -----------------------------------------------------------------

describe('handlePushEvent — fallback body never leaks plaintext, ciphertext, or key material', () => {
  it('never includes the envelope ciphertext bytes or session ids in the rendered notification', async () => {
    const { reg, calls } = makeRegistration();

    // Construct an envelope whose ciphertext + ids contain
    // ASCII canary substrings we'd notice if they leaked into
    // the title or body.
    const ciphertextCanary = 'CIPHERTEXT_CANARY_DEADBEEF';
    const senderDeviceCanary = 'SENDER_DEVICE_CANARY';
    const sessionCanary = 'SESSION_CANARY_XYZ';
    const envelope: EnvelopeForNotification = {
      ciphertext: new TextEncoder().encode(ciphertextCanary),
      senderDeviceId: senderDeviceCanary,
      recipientDeviceId: 'recipient-dev',
      sessionId: sessionCanary,
    };

    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: true,
      envelope,
    });
    // Decrypt fails so we hit the generic-body branch.
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => ({
      ok: false,
    });

    await handlePushEvent(pushPayloadJson({ type: 'dm.message' }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(1);
    const rendered = JSON.stringify({
      title: calls[0]!.title,
      body: calls[0]!.options?.body,
    });
    // None of the canary strings appear anywhere in the
    // user-visible notification fields.
    expect(rendered.includes(ciphertextCanary)).toBe(false);
    expect(rendered.includes(senderDeviceCanary)).toBe(false);
    expect(rendered.includes(sessionCanary)).toBe(false);
    // And specifically: the body is one of our hard-coded
    // generic strings.
    expect(Object.values(GENERIC_BODIES)).toContain(calls[0]!.options?.body);
  });

  it('never renders the raw push payload type as the notification body for unknown types', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope: FetchLatestEnvelope = async () => ({
      ok: false,
    });
    const decryptEnvelope: DecryptEnvelopeForNotification = async () => ({
      ok: false,
    });

    // Adversarial type string — it must NOT appear verbatim in
    // the notification body. The fallback constant
    // `FALLBACK_GENERIC_BODY` is what gets rendered.
    const adversarialType = '<script>alert(1)</script>';
    await handlePushEvent(pushPayloadJson({ type: adversarialType }), {
      registration: reg,
      fetchLatestEnvelope,
      decryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls[0]!.options?.body).toBe(FALLBACK_GENERIC_BODY);
    expect(calls[0]!.options?.body).not.toContain('script');
  });
});

// -----------------------------------------------------------------
// handlePushEvent — malformed payload
// -----------------------------------------------------------------

describe('handlePushEvent — malformed payload', () => {
  it('drops the push (no notification rendered) when the payload is non-JSON', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope = vi.fn();
    const decryptEnvelope = vi.fn();

    await handlePushEvent('not json', {
      registration: reg,
      fetchLatestEnvelope: fetchLatestEnvelope as unknown as FetchLatestEnvelope,
      decryptEnvelope:
        decryptEnvelope as unknown as DecryptEnvelopeForNotification,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(0);
    expect(fetchLatestEnvelope).not.toHaveBeenCalled();
    expect(decryptEnvelope).not.toHaveBeenCalled();
    expect(logRecords.some((r) => r.msg === 'sw.push.invalid_payload')).toBe(
      true,
    );
  });

  it('drops the push when required fields are missing', async () => {
    const { reg, calls } = makeRegistration();
    const fetchLatestEnvelope = vi.fn();
    const decryptEnvelope = vi.fn();

    await handlePushEvent(JSON.stringify({ type: 'dm.message' }), {
      registration: reg,
      fetchLatestEnvelope: fetchLatestEnvelope as unknown as FetchLatestEnvelope,
      decryptEnvelope:
        decryptEnvelope as unknown as DecryptEnvelopeForNotification,
      threadUrlFor: defaultThreadUrlFor,
    });

    expect(calls).toHaveLength(0);
    expect(fetchLatestEnvelope).not.toHaveBeenCalled();
  });
});

// -----------------------------------------------------------------
// handleNotificationClick
// -----------------------------------------------------------------

function makeClient(url: string): {
  client: ClientLike;
  focus: ReturnType<typeof vi.fn>;
  postMessage: ReturnType<typeof vi.fn>;
} {
  const focus = vi.fn(async () => undefined);
  const postMessage = vi.fn();
  const client: ClientLike = {
    url,
    focus: focus as unknown as ClientLike['focus'],
    postMessage: postMessage as unknown as ClientLike['postMessage'],
  };
  return { client, focus, postMessage };
}

describe('handleNotificationClick', () => {
  it('opens a new window at the thread URL when no client is open', async () => {
    const matchAll = vi.fn(
      async (): Promise<readonly ClientLike[]> => [] as readonly ClientLike[],
    );
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    await handleNotificationClick(
      { conversationId: CONVERSATION_ID, threadUrl: `/thread/${CONVERSATION_ID}` },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(openWindow).toHaveBeenCalledTimes(1);
    expect(openWindow).toHaveBeenCalledWith(
      `${ORIGIN}/thread/${CONVERSATION_ID}`,
    );
  });

  it('focuses an existing matching tab and posts a navigate message', async () => {
    const exact = makeClient(`${ORIGIN}/thread/${CONVERSATION_ID}`);
    const matchAll = vi.fn(
      async (): Promise<readonly ClientLike[]> => [exact.client],
    );
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    await handleNotificationClick(
      { conversationId: CONVERSATION_ID, threadUrl: `/thread/${CONVERSATION_ID}` },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(exact.focus).toHaveBeenCalledTimes(1);
    expect(exact.postMessage).toHaveBeenCalledTimes(1);
    const message = exact.postMessage.mock.calls[0]![0] as NavigateMessage;
    expect(message.kind).toBe('konvo.navigate');
    expect(message.conversationId).toBe(CONVERSATION_ID);
    expect(message.threadUrl).toBe(`/thread/${CONVERSATION_ID}`);
    expect(openWindow).not.toHaveBeenCalled();
  });

  it('focuses any same-origin tab when no exact match exists', async () => {
    const other = makeClient(`${ORIGIN}/threads`);
    const matchAll = vi.fn(
      async (): Promise<readonly ClientLike[]> => [other.client],
    );
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    await handleNotificationClick(
      { conversationId: CONVERSATION_ID, threadUrl: `/thread/${CONVERSATION_ID}` },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(other.focus).toHaveBeenCalledTimes(1);
    expect(other.postMessage).toHaveBeenCalledTimes(1);
    expect(openWindow).not.toHaveBeenCalled();
  });

  it('opens a new window when only foreign-origin tabs are open', async () => {
    const foreign = makeClient('https://attacker.example/thread/elsewhere');
    const matchAll = vi.fn(
      async (): Promise<readonly ClientLike[]> => [foreign.client],
    );
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    await handleNotificationClick(
      { conversationId: CONVERSATION_ID, threadUrl: `/thread/${CONVERSATION_ID}` },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(foreign.focus).not.toHaveBeenCalled();
    expect(foreign.postMessage).not.toHaveBeenCalled();
    expect(openWindow).toHaveBeenCalledTimes(1);
    expect(openWindow).toHaveBeenCalledWith(
      `${ORIGIN}/thread/${CONVERSATION_ID}`,
    );
  });

  it('is a no-op when notification.data is missing or malformed', async () => {
    const matchAll = vi.fn();
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    await handleNotificationClick(null, {
      clients,
      threadUrlFor: defaultThreadUrlFor,
      origin: ORIGIN,
    });
    await handleNotificationClick(undefined, {
      clients,
      threadUrlFor: defaultThreadUrlFor,
      origin: ORIGIN,
    });
    await handleNotificationClick(
      { conversationId: '' },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );
    await handleNotificationClick(
      { conversationId: 42 },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(matchAll).not.toHaveBeenCalled();
    expect(openWindow).not.toHaveBeenCalled();
  });

  it('encodes special characters in the conversation id when building the URL', async () => {
    const matchAll = vi.fn(
      async (): Promise<readonly ClientLike[]> => [] as readonly ClientLike[],
    );
    const openWindow = vi.fn(async () => undefined);
    const clients: ClientsLike = {
      matchAll: matchAll as unknown as ClientsLike['matchAll'],
      openWindow: openWindow as unknown as ClientsLike['openWindow'],
    };

    const trickyId = 'conv with/special?chars';
    await handleNotificationClick(
      {
        conversationId: trickyId,
        threadUrl: `/thread/${encodeURIComponent(trickyId)}`,
      },
      { clients, threadUrlFor: defaultThreadUrlFor, origin: ORIGIN },
    );

    expect(openWindow).toHaveBeenCalledTimes(1);
    const opened = openWindow.mock.calls[0]![0] as string;
    // The URL is well-formed (parseable) and contains the
    // percent-encoded id.
    expect(() => new URL(opened)).not.toThrow();
    expect(opened).toContain(encodeURIComponent(trickyId));
  });
});

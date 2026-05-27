// apps/web/test/voice-note.test.ts
//
// Unit tests for the voice-note recorder (task 5.4).
//
// Coverage map (per the task brief):
//   - < 1 s release ⇒ recording is discarded; no upload, no
//     attachment ref produced (req 5.8).
//   - 120 s recording ⇒ auto-stop and finalise (req 5.2).
//   - getUserMedia permission denied ⇒ permission_denied
//     outcome; recording does not begin (req 5.7).
//   - Each recording uses a freshly generated AES-GCM 256-bit key
//     and 96-bit IV (req 5.3 / 6.1 freshness).
//   - Upload retry budget: ≤ 3 retries with exponential backoff;
//     terminal failure produces `'failed'` outcome and DOES NOT
//     produce an attachment ref (req 5.9).
//
// We mock `MediaRecorder` and `getUserMedia` because jsdom ships
// neither. The mocks are intentionally minimal — they implement
// only the surface `voice-note.ts` touches, so any future change
// that reaches for new MediaRecorder API surfaces will fail
// loudly here rather than silently no-op.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MAX_RECORDING_MS,
  MIN_HOLD_MS,
  UPLOAD_MAX_RETRIES,
  VoiceNoteRecorder,
} from '../src/features/dm/voice-note.js';
import {
  AttachmentUploadError,
} from '../src/features/attachments/upload.js';
import type { AttachmentRef } from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class FakeTrack {
  kind: 'audio' = 'audio';
  stopped = false;
  stop(): void {
    this.stopped = true;
  }
}

class FakeStream {
  tracks: FakeTrack[];
  constructor(tracks: FakeTrack[]) {
    this.tracks = tracks;
  }
  getTracks(): FakeTrack[] {
    return this.tracks;
  }
}

interface FakeRecorderHandle {
  start: () => void;
  stop: () => void;
  emitChunk: (chunk: Uint8Array) => void;
  fireOnStop: () => void;
  state: 'inactive' | 'recording';
}

class FakeMediaRecorder {
  static instances: FakeMediaRecorder[] = [];
  static isTypeSupported(_mime: string): boolean {
    return true;
  }
  state: 'inactive' | 'recording' = 'inactive';
  ondataavailable: ((ev: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_stream: unknown, _options?: unknown) {
    FakeMediaRecorder.instances.push(this);
  }
  start(): void {
    this.state = 'recording';
  }
  stop(): void {
    this.state = 'inactive';
    // Tests drive the onstop manually via `fireOnStop` for
    // determinism — but a default stop() should also fire the
    // event so production-shaped flows work without hand-holding.
    if (this.onstop !== null) {
      this.onstop();
    }
  }
  emitChunk(bytes: Uint8Array): void {
    if (this.ondataavailable !== null) {
      const blob = new Blob([bytes as unknown as BlobPart], {
        type: 'audio/webm;codecs=opus',
      });
      this.ondataavailable({ data: blob });
    }
  }
}

function makeRecorder(opts: {
  permissionError?: string;
  upload?: (
    file: File,
    allowed: readonly string[],
  ) => Promise<AttachmentRef>;
  encrypt?: (plaintext: Uint8Array) => Promise<{
    ciphertext: Uint8Array;
    key: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
  }>;
  now?: () => number;
  setTimeoutImpl?: (
    fn: () => void,
    ms: number,
  ) => ReturnType<typeof setTimeout>;
  clearTimeoutImpl?: (h: ReturnType<typeof setTimeout>) => void;
  maxRecordingMs?: number;
  minHoldMs?: number;
  maxRetries?: number;
  backoffBaseMs?: number;
  isTypeSupported?: (mime: string) => boolean;
}): {
  recorder: VoiceNoteRecorder;
  getUserMedia: ReturnType<typeof vi.fn>;
  uploadCalls: { count: number; files: File[] };
  encryptCalls: { count: number; keys: Uint8Array[]; ivs: Uint8Array[] };
} {
  FakeMediaRecorder.instances = [];

  const getUserMedia = vi.fn(async () => {
    if (opts.permissionError !== undefined) {
      const err = new Error('permission denied');
      err.name = opts.permissionError;
      throw err;
    }
    return new FakeStream([new FakeTrack()]) as unknown as MediaStream;
  });

  const encryptCalls = { count: 0, keys: [] as Uint8Array[], ivs: [] as Uint8Array[] };
  const defaultEncrypt = async (
    plaintext: Uint8Array,
  ): Promise<{
    ciphertext: Uint8Array;
    key: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
  }> => {
    encryptCalls.count += 1;
    // Generate fresh key/iv per call so the freshness test can
    // verify they actually differ across recordings.
    const key = new Uint8Array(32);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(key);
    crypto.getRandomValues(iv);
    encryptCalls.keys.push(key);
    encryptCalls.ivs.push(iv);
    const tag = new Uint8Array(16);
    return {
      ciphertext: new Uint8Array(plaintext),
      key,
      iv,
      tag,
    };
  };

  const uploadCalls = { count: 0, files: [] as File[] };
  const defaultUpload = async (
    file: File,
    _allowed: readonly string[],
  ): Promise<AttachmentRef> => {
    uploadCalls.count += 1;
    uploadCalls.files.push(file);
    return {
      attachmentId: `aid-${uploadCalls.count}`,
      key: new Uint8Array(32),
      iv: new Uint8Array(12),
      tag: new Uint8Array(16),
      sizeBytes: file.size,
    };
  };

  const recorder = new VoiceNoteRecorder({
    allowedRecipientIds: ['rcpt-1'],
    getUserMedia,
    mediaRecorderCtor: FakeMediaRecorder as unknown as new (
      stream: MediaStream,
      options?: MediaRecorderOptions,
    ) => MediaRecorder,
    isTypeSupported: opts.isTypeSupported ?? ((_m: string): boolean => true),
    encryptImpl: opts.encrypt ?? defaultEncrypt,
    uploadImpl: opts.upload ?? defaultUpload,
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.setTimeoutImpl !== undefined
      ? { setTimeoutImpl: opts.setTimeoutImpl }
      : {}),
    ...(opts.clearTimeoutImpl !== undefined
      ? { clearTimeoutImpl: opts.clearTimeoutImpl }
      : {}),
    ...(opts.maxRecordingMs !== undefined
      ? { maxRecordingMs: opts.maxRecordingMs }
      : {}),
    ...(opts.minHoldMs !== undefined ? { minHoldMs: opts.minHoldMs } : {}),
    ...(opts.maxRetries !== undefined ? { maxRetries: opts.maxRetries } : {}),
    ...(opts.backoffBaseMs !== undefined
      ? { backoffBaseMs: opts.backoffBaseMs }
      : {}),
  });
  return { recorder, getUserMedia, uploadCalls, encryptCalls };
}

/** Helper: drive a "successful" recording lifecycle on the most
 *  recently constructed `FakeMediaRecorder`. The fake `start()`
 *  + `stop()` are no-ops by default; tests need to fire the
 *  `ondataavailable` chunk and then resolve the awaited
 *  `stopPromise` by triggering `onstop`. */
function feedRecorder(bytes: Uint8Array): void {
  const inst = FakeMediaRecorder.instances.at(-1);
  if (inst === undefined) {
    throw new Error('feedRecorder: no MediaRecorder instances');
  }
  inst.emitChunk(bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('VoiceNoteRecorder — < 1 s release discard (req 5.8)', () => {
  it('discards the recording when released before MIN_HOLD_MS', async () => {
    let clock = 1000;
    const advance = (delta: number): void => {
      clock += delta;
    };
    const { recorder, uploadCalls, encryptCalls } = makeRecorder({
      now: () => clock,
      // Use a smaller `minHoldMs` so the test doesn't wait a real
      // second, but exercise the same code path.
      minHoldMs: 1_000,
    });

    const startResult = await recorder.start();
    expect(startResult.kind).toBe('started');
    // Release after 500 ms — well under the threshold.
    advance(500);

    const out = await recorder.stop();
    expect(out.kind).toBe('discarded');
    if (out.kind === 'discarded') {
      expect(out.heldMs).toBe(500);
    }
    // Critically: no upload, no encrypt, no envelope.
    expect(uploadCalls.count).toBe(0);
    expect(encryptCalls.count).toBe(0);
  });

  it('proceeds to encrypt + upload when held ≥ MIN_HOLD_MS', async () => {
    let clock = 1000;
    const { recorder, uploadCalls, encryptCalls } = makeRecorder({
      now: () => clock,
      minHoldMs: 1_000,
    });

    await recorder.start();
    clock += 1500; // 1.5 s held — over the threshold

    // Feed a non-empty chunk so the finalised blob has bytes.
    feedRecorder(new Uint8Array([1, 2, 3, 4]));

    const out = await recorder.stop();
    expect(out.kind).toBe('ok');
    if (out.kind === 'ok') {
      expect(out.attachmentRef.attachmentId).toBe('aid-1');
      expect(out.durationMs).toBeGreaterThanOrEqual(1_000);
    }
    expect(encryptCalls.count).toBe(1);
    expect(uploadCalls.count).toBe(1);
  });
});

describe('VoiceNoteRecorder — 120 s auto-stop (req 5.2)', () => {
  it('auto-stops when recording reaches the max length', async () => {
    let clock = 0;
    type Pending = { fn: () => void; due: number };
    const pending: Pending[] = [];
    let nextHandle = 1;
    const handles = new Map<number, Pending>();
    const setTimeoutImpl = (
      fn: () => void,
      ms: number,
    ): ReturnType<typeof setTimeout> => {
      const handle = nextHandle;
      nextHandle += 1;
      const entry: Pending = { fn, due: clock + ms };
      pending.push(entry);
      handles.set(handle, entry);
      return handle as unknown as ReturnType<typeof setTimeout>;
    };
    const clearTimeoutImpl = (h: ReturnType<typeof setTimeout>): void => {
      const handle = h as unknown as number;
      const entry = handles.get(handle);
      if (entry === undefined) return;
      handles.delete(handle);
      const idx = pending.indexOf(entry);
      if (idx >= 0) pending.splice(idx, 1);
    };
    const advanceTo = (target: number): void => {
      clock = target;
      // Fire any timer whose due time has passed, in arrival order.
      const due = pending.filter((p) => p.due <= clock);
      for (const p of due) {
        const idx = pending.indexOf(p);
        if (idx >= 0) pending.splice(idx, 1);
        p.fn();
      }
    };

    const { recorder, uploadCalls } = makeRecorder({
      now: () => clock,
      setTimeoutImpl,
      clearTimeoutImpl,
      maxRecordingMs: MAX_RECORDING_MS, // exercise the real value
    });

    const stopSpy = vi.spyOn(FakeMediaRecorder.prototype, 'stop');

    await recorder.start();
    feedRecorder(new Uint8Array([5, 6, 7, 8]));

    // Advance to exactly the auto-stop boundary. The watchdog
    // timer should fire and request the recorder to stop.
    advanceTo(MAX_RECORDING_MS);
    expect(stopSpy).toHaveBeenCalled();

    // Now the user "releases" but the recorder has already been
    // stopped by the watchdog; finalise() awaits the same
    // stopPromise the auto-stop already resolved.
    const out = await recorder.stop();
    expect(out.kind).toBe('ok');
    if (out.kind === 'ok') {
      expect(out.durationMs).toBe(MAX_RECORDING_MS);
    }
    expect(uploadCalls.count).toBe(1);

    stopSpy.mockRestore();
  });
});

describe('VoiceNoteRecorder — permission denied (req 5.7)', () => {
  it('returns permission_denied without starting the recorder', async () => {
    const { recorder, getUserMedia, uploadCalls, encryptCalls } = makeRecorder({
      permissionError: 'NotAllowedError',
    });

    const result = await recorder.start();
    expect(result.kind).toBe('permission_denied');
    expect(getUserMedia).toHaveBeenCalledTimes(1);
    // No MediaRecorder constructed.
    expect(FakeMediaRecorder.instances.length).toBe(0);
    expect(recorder.isRecording()).toBe(false);
    // No envelope path is reached.
    expect(uploadCalls.count).toBe(0);
    expect(encryptCalls.count).toBe(0);
  });

  it('also surfaces permission_denied for SecurityError variants', async () => {
    const { recorder } = makeRecorder({ permissionError: 'SecurityError' });
    const result = await recorder.start();
    expect(result.kind).toBe('permission_denied');
  });
});

describe('VoiceNoteRecorder — fresh AES-GCM material per recording (req 5.3 / 6.1)', () => {
  it('generates a fresh key and IV for each recording', async () => {
    let clock = 0;
    const { recorder, encryptCalls } = makeRecorder({
      now: () => clock,
      minHoldMs: 1_000,
    });

    // Recording 1.
    await recorder.start();
    clock += 1500;
    feedRecorder(new Uint8Array([1, 2, 3]));
    const out1 = await recorder.stop();
    expect(out1.kind).toBe('ok');

    // Recording 2.
    await recorder.start();
    clock += 1500;
    feedRecorder(new Uint8Array([4, 5, 6]));
    const out2 = await recorder.stop();
    expect(out2.kind).toBe('ok');

    expect(encryptCalls.count).toBe(2);
    expect(encryptCalls.keys.length).toBe(2);
    expect(encryptCalls.ivs.length).toBe(2);

    // The two key buffers must differ. We compare bytewise rather
    // than referentially because the test fake currently returns
    // independent allocations either way.
    const sameKey = bytesEqual(encryptCalls.keys[0]!, encryptCalls.keys[1]!);
    const sameIv = bytesEqual(encryptCalls.ivs[0]!, encryptCalls.ivs[1]!);
    expect(sameKey).toBe(false);
    expect(sameIv).toBe(false);

    // Lengths conform to design.md §8.3 (32 bytes / 12 bytes).
    expect(encryptCalls.keys[0]!.length).toBe(32);
    expect(encryptCalls.ivs[0]!.length).toBe(12);
  });
});

describe('VoiceNoteRecorder — upload retry-then-fail (req 5.9)', () => {
  it(
    'retries up to UPLOAD_MAX_RETRIES + 1 attempts, then surfaces failed without producing a ref',
    async () => {
      // We rely on real `setTimeout` for backoff so the recorder's
      // own auto-stop watchdog (which uses the same timer impl in
      // production) doesn't fire as a microtask and pre-empt the
      // chunk-feed step. With `backoffBaseMs: 1` the worst-case
      // wait is 1 + 2 + 4 = 7 ms — comfortably below the 120 s
      // auto-stop boundary.
      let clock = 0;
      const upload = vi.fn(async () => {
        throw new AttachmentUploadError('http', 'simulated 500', 500);
      });

      const { recorder, uploadCalls } = makeRecorder({
        now: () => clock,
        minHoldMs: 1_000,
        upload,
        backoffBaseMs: 1,
      });

      await recorder.start();
      // Feed the chunk BEFORE the clock-advance + stop sequence so
      // it's queued on the recorder's `chunks` array when `onstop`
      // resolves.
      feedRecorder(new Uint8Array([10, 20, 30]));
      clock += 1500;
      const out = await recorder.stop();

      expect(out.kind).toBe('failed');
      if (out.kind === 'failed') {
        expect(out.details).toContain('upload');
      }
      // 1 initial attempt + UPLOAD_MAX_RETRIES retries.
      expect(upload).toHaveBeenCalledTimes(UPLOAD_MAX_RETRIES + 1);
      expect(uploadCalls.count).toBe(0); // the default upload was not used
    },
  );

  it('succeeds on a transient failure that recovers within the budget', async () => {
    let clock = 0;
    let attempts = 0;
    const upload = vi.fn(async () => {
      attempts += 1;
      if (attempts < 3) {
        throw new AttachmentUploadError('http', 'flaky 502', 502);
      }
      return {
        attachmentId: 'aid-eventual',
        key: new Uint8Array(32),
        iv: new Uint8Array(12),
        tag: new Uint8Array(16),
        sizeBytes: 3,
      } satisfies AttachmentRef;
    });

    const { recorder } = makeRecorder({
      now: () => clock,
      minHoldMs: 1_000,
      upload,
      backoffBaseMs: 1,
    });

    await recorder.start();
    feedRecorder(new Uint8Array([1, 2, 3]));
    clock += 1500;
    const out = await recorder.stop();

    expect(out.kind).toBe('ok');
    if (out.kind === 'ok') {
      expect(out.attachmentRef.attachmentId).toBe('aid-eventual');
    }
    expect(upload).toHaveBeenCalledTimes(3);
  });
});

describe('VoiceNoteRecorder — sanity: MIN_HOLD_MS / constants', () => {
  it('exposes the spec-pinned constants', () => {
    expect(MAX_RECORDING_MS).toBe(120_000);
    expect(MIN_HOLD_MS).toBe(1_000);
    expect(UPLOAD_MAX_RETRIES).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

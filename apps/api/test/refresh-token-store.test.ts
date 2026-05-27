// apps/api/test/refresh-token-store.test.ts
//
// Unit tests for `createRefreshTokenStore` (task 2.2) — the second leg of
// the auth-service test suite (task 2.11).
//
// Validates Requirements 1.7 and 1.14:
//   - 1.7  : every refresh-token use rotates the token; the prior raw
//            value becomes invalid.
//   - 1.14 : if a refresh token that has already been rotated/revoked is
//            presented, ALL active refresh tokens for the owning user are
//            revoked AND the rotation is rejected. (Family revoke.)
//
// Strategy: the production store talks to Postgres via `pg.Pool.connect()`
// + transactional `client.query(...)` calls (BEGIN / SELECT FOR UPDATE /
// UPDATE / INSERT / COMMIT). Standing up a real database for unit tests
// would be heavy, so we drive a *stateful* pool stub backed by an
// in-memory Map<token_hash, row>. The stub interprets the same SQL the
// store emits and stores rows with the same column shape, so the test
// observes the actual logical effects (rotation marker, family revoke,
// revoke idempotency) — not just whether the right strings were called.
//
// The stub is the smallest faithful pg.Pool we can get away with:
//   - `connect()` hands back a fresh client object so concurrent
//     transactions in production code don't conflate state.
//   - The client's `query()` matches on a normalized (whitespace-collapsed)
//     SQL prefix and dispatches to a small set of handlers covering every
//     statement the store emits today. Any unrecognized SQL throws so
//     future store changes that introduce a new statement fail loudly
//     here rather than silently passing.
//   - `release()` is a no-op (we don't pool clients).
//
// Note on `now()`: production uses Postgres's `now()` for `rotated_at` /
// `revoked_at`. We substitute `new Date()` at the moment the UPDATE runs
// — same observable behaviour from the store's perspective. `expires_at`
// is supplied by the store as a JS Date (computed from `Date.now() + ttlMs`).

import { describe, expect, it } from 'vitest';

import {
  createRefreshTokenStore,
  InvalidRefreshTokenError,
  RefreshTokenExpiredError,
} from '../src/services/auth/tokens.js';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface RefreshTokenRow {
  id: string;
  user_id: string;
  token_hash: Buffer;
  issued_at: Date;
  expires_at: Date;
  rotated_at: Date | null;
  revoked_at: Date | null;
}

interface FakeDb {
  /** Map keyed by base64 of token_hash so Buffer values compare by value. */
  rows: Map<string, RefreshTokenRow>;
  nextId: number;
}

/** Strip leading/trailing whitespace and collapse internal whitespace runs.
 *  Lets us match SQL by content regardless of how the source formats it
 *  across multiple lines. */
function normalizeSql(sql: string): string {
  return sql.trim().replace(/\s+/g, ' ').toUpperCase();
}

function bufKey(buf: Buffer): string {
  return buf.toString('base64');
}

function makePool(db: FakeDb) {
  return {
    async connect() {
      // Each `connect()` returns a fresh client. The store always
      // pairs `connect()` with `release()` in a try/finally, so a
      // forgotten release would surface as a leak in the test —
      // we don't bother counting outstanding clients here because
      // the store is the only consumer.
      return {
        async query<T = unknown>(
          sql: string,
          params?: readonly unknown[],
        ): Promise<{ rows: T[]; rowCount: number }> {
          const norm = normalizeSql(sql);

          // Transaction control. Our stub doesn't actually isolate
          // writes — there's only one test at a time and the store
          // serialises its own work on a single connection — so we
          // accept BEGIN/COMMIT/ROLLBACK as no-ops. The semantics the
          // tests care about (FOR UPDATE serialisation, family revoke
          // ordering) are visible through the row Map regardless.
          if (norm === 'BEGIN' || norm === 'COMMIT' || norm === 'ROLLBACK') {
            return { rows: [], rowCount: 0 };
          }

          // INSERT INTO refresh_tokens (...) VALUES ($1, $2, $3) RETURNING id
          if (
            norm.startsWith('INSERT INTO REFRESH_TOKENS') &&
            norm.includes('RETURNING ID')
          ) {
            const [userId, tokenHash, expiresAt] = params as [
              string,
              Buffer,
              Date,
            ];
            const id = `rt-${++db.nextId}`;
            const row: RefreshTokenRow = {
              id,
              user_id: userId,
              token_hash: tokenHash,
              issued_at: new Date(),
              expires_at: expiresAt,
              rotated_at: null,
              revoked_at: null,
            };
            db.rows.set(bufKey(tokenHash), row);
            return { rows: [{ id } as unknown as T], rowCount: 1 };
          }

          // INSERT without RETURNING — the post-rotation issue path.
          if (norm.startsWith('INSERT INTO REFRESH_TOKENS')) {
            const [userId, tokenHash, expiresAt] = params as [
              string,
              Buffer,
              Date,
            ];
            const id = `rt-${++db.nextId}`;
            db.rows.set(bufKey(tokenHash), {
              id,
              user_id: userId,
              token_hash: tokenHash,
              issued_at: new Date(),
              expires_at: expiresAt,
              rotated_at: null,
              revoked_at: null,
            });
            return { rows: [], rowCount: 1 };
          }

          // SELECT ... FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE
          if (
            norm.startsWith('SELECT') &&
            norm.includes('FROM REFRESH_TOKENS') &&
            norm.includes('WHERE TOKEN_HASH = $1') &&
            norm.includes('FOR UPDATE')
          ) {
            const [tokenHash] = params as [Buffer];
            const row = db.rows.get(bufKey(tokenHash));
            if (row === undefined) {
              return { rows: [], rowCount: 0 };
            }
            // Project only the columns the store SELECTs. We keep the
            // shape deliberately narrow so a column drift in production
            // surfaces here as a missing field rather than silently
            // succeeding via TypeScript's structural typing.
            return {
              rows: [
                {
                  id: row.id,
                  user_id: row.user_id,
                  expires_at: row.expires_at,
                  rotated_at: row.rotated_at,
                  revoked_at: row.revoked_at,
                } as unknown as T,
              ],
              rowCount: 1,
            };
          }

          // UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1
          if (
            norm.startsWith('UPDATE REFRESH_TOKENS') &&
            norm.includes('SET ROTATED_AT') &&
            norm.includes('WHERE ID = $1')
          ) {
            const [id] = params as [string];
            for (const row of db.rows.values()) {
              if (row.id === id) {
                row.rotated_at = new Date();
                return { rows: [], rowCount: 1 };
              }
            }
            return { rows: [], rowCount: 0 };
          }

          // UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL
          // (single-token revoke; idempotent)
          if (
            norm.startsWith('UPDATE REFRESH_TOKENS') &&
            norm.includes('SET REVOKED_AT') &&
            norm.includes('WHERE TOKEN_HASH = $1') &&
            norm.includes('REVOKED_AT IS NULL')
          ) {
            const [tokenHash] = params as [Buffer];
            const row = db.rows.get(bufKey(tokenHash));
            if (row === undefined || row.revoked_at !== null) {
              // Idempotent: unknown token or already-revoked token is a
              // no-op. Production matches at most one row via the
              // UNIQUE constraint on token_hash; we mirror that here.
              return { rows: [], rowCount: 0 };
            }
            row.revoked_at = new Date();
            return { rows: [], rowCount: 1 };
          }

          // UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL
          // (family revoke — both the explicit revokeAllForUser entry
          // point AND the implicit branch inside rotate() use this same
          // statement.)
          if (
            norm.startsWith('UPDATE REFRESH_TOKENS') &&
            norm.includes('SET REVOKED_AT') &&
            norm.includes('WHERE USER_ID = $1') &&
            norm.includes('REVOKED_AT IS NULL')
          ) {
            const [userId] = params as [string];
            let updated = 0;
            for (const row of db.rows.values()) {
              if (row.user_id === userId && row.revoked_at === null) {
                row.revoked_at = new Date();
                updated += 1;
              }
            }
            return { rows: [], rowCount: updated };
          }

          // Unrecognized statement — fail loud so a future store change
          // doesn't silently bypass these tests.
          throw new Error(`refresh-token-store stub: unrecognized SQL ${sql}`);
        },
        release(): void {
          // no-op
        },
      };
    },
  };
}

function makeDb(): FakeDb {
  return { rows: new Map(), nextId: 0 };
}

const PEPPER = 'x'.repeat(32) + '-pepper';
const USER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createRefreshTokenStore — issue + rotate happy path', () => {
  it('issue() persists a row and rotate() returns a new raw token bound to the same user', async () => {
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    const issued = await store.issue(USER_A);
    expect(typeof issued.raw).toBe('string');
    expect(issued.raw.length).toBeGreaterThan(0);
    expect(issued.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // Exactly one row, owned by USER_A, not yet rotated/revoked.
    expect(db.rows.size).toBe(1);
    const [issuedRow] = [...db.rows.values()];
    expect(issuedRow?.user_id).toBe(USER_A);
    expect(issuedRow?.rotated_at).toBeNull();
    expect(issuedRow?.revoked_at).toBeNull();

    const rotated = await store.rotate(issued.raw);
    expect(rotated.userId).toBe(USER_A);
    expect(rotated.raw).not.toBe(issued.raw);
    expect(rotated.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // Now there are TWO rows: the original (rotated) and the new (active).
    expect(db.rows.size).toBe(2);
    // The original row must be marked rotated_at; the successor must not.
    const rows = [...db.rows.values()];
    const original = rows.find((r) => r.id === issuedRow?.id);
    const successor = rows.find((r) => r.id !== issuedRow?.id);
    expect(original?.rotated_at).toBeInstanceOf(Date);
    expect(original?.revoked_at).toBeNull();
    expect(successor?.rotated_at).toBeNull();
    expect(successor?.revoked_at).toBeNull();
    expect(successor?.user_id).toBe(USER_A);
  });

  it('rotate() with a token unknown to the store throws InvalidRefreshTokenError without writing', async () => {
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    // Pre-populate one unrelated row so we can verify we don't touch it.
    await store.issue(USER_B);
    const sizeBefore = db.rows.size;
    const snapshot = [...db.rows.values()].map((r) => ({ ...r }));

    await expect(store.rotate('token-that-was-never-issued')).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );

    // No new row, no mutation of the unrelated row.
    expect(db.rows.size).toBe(sizeBefore);
    const after = [...db.rows.values()];
    expect(after).toHaveLength(snapshot.length);
    expect(after[0]?.rotated_at).toEqual(snapshot[0]?.rotated_at);
    expect(after[0]?.revoked_at).toEqual(snapshot[0]?.revoked_at);
  });
});

describe('createRefreshTokenStore — replay detection (Requirement 1.14)', () => {
  it('rotate() of a previously-rotated token throws AND revokes every active token for that user', async () => {
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    // USER_A holds three tokens (e.g. three browser sessions). Two of
    // them are completely innocent; only the first one will be rotated.
    const issuedA1 = await store.issue(USER_A);
    const issuedA2 = await store.issue(USER_A);
    const issuedA3 = await store.issue(USER_A);

    // USER_B holds one token that must NOT be touched by USER_A's family
    // revoke — the policy is per-user, not global.
    const issuedB1 = await store.issue(USER_B);

    // First legitimate rotation: A1 → A1'.
    const rotated = await store.rotate(issuedA1.raw);
    expect(rotated.userId).toBe(USER_A);

    // Now an attacker (or a stale tab) replays the original A1 raw
    // value. This MUST be rejected AND must revoke every active token
    // for USER_A — including A2 and A3 — but leave USER_B alone.
    await expect(store.rotate(issuedA1.raw)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );

    const rows = [...db.rows.values()];

    // Every USER_A row that was previously active is now revoked.
    // (The original A1 row was already rotated, so it stays
    // rotated-but-not-revoked — the replay branch revokes ACTIVE rows
    // only via `WHERE revoked_at IS NULL`, which is exactly what we
    // want; the original is already neutralised by rotated_at.)
    const aRows = rows.filter((r) => r.user_id === USER_A);
    const aActive = aRows.filter(
      (r) => r.revoked_at === null && r.rotated_at === null,
    );
    expect(aActive).toHaveLength(0);

    // A2, A3, and the successor A1' must all carry revoked_at != null.
    const aRevoked = aRows.filter((r) => r.revoked_at !== null);
    expect(aRevoked.length).toBeGreaterThanOrEqual(3); // A2, A3, A1'

    // USER_B's token must remain entirely untouched.
    const bRow = rows.find((r) => r.user_id === USER_B);
    expect(bRow?.revoked_at).toBeNull();
    expect(bRow?.rotated_at).toBeNull();

    // Sanity: the raw values for A2 / A3 are now unusable.
    await expect(store.rotate(issuedA2.raw)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
    await expect(store.rotate(issuedA3.raw)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );

    // ...but USER_B's token is still rotateable, confirming the family
    // revoke didn't leak across users.
    const rotatedB = await store.rotate(issuedB1.raw);
    expect(rotatedB.userId).toBe(USER_B);
  });

  it('rotate() of an explicitly-revoked token (e.g. via logout) also triggers family revoke', async () => {
    // A revoked token presented in a refresh attempt is functionally
    // identical to a rotated one for the purposes of Requirement 1.14:
    // the user's session was already torn down, so seeing this token
    // again is the same compromise signal as replay.
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    const issued1 = await store.issue(USER_A);
    const issued2 = await store.issue(USER_A);

    // User explicitly logs out of session 1.
    await store.revoke(issued1.raw);

    // Attempting to rotate the now-revoked token must trip the family
    // revoke branch.
    await expect(store.rotate(issued1.raw)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );

    const rows = [...db.rows.values()];
    for (const row of rows) {
      if (row.user_id !== USER_A) continue;
      // Every USER_A row should now be revoked.
      expect(row.revoked_at).not.toBeNull();
    }

    // And the parallel session is indeed dead.
    await expect(store.rotate(issued2.raw)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });
});

describe('createRefreshTokenStore — expiration', () => {
  it('rotate() of an expired-but-otherwise-valid token throws RefreshTokenExpiredError WITHOUT family revoke', async () => {
    // The expired branch is critical to test in isolation: per
    // Requirement 1.14 / file-header note in tokens.ts, an honest
    // expired token is NOT a compromise signal, so it MUST NOT trigger
    // the family revoke. A bug here would log every user out as their
    // sessions naturally expired — a serious denial-of-service
    // regression.
    const db = makeDb();
    // 1ms TTL ensures the row is expired before we present it; the
    // store's expiry check uses `Date.now()` so this is deterministic
    // without time mocking.
    const store = createRefreshTokenStore(makePool(db), PEPPER, 1);

    const issued1 = await store.issue(USER_A);
    const issued2 = await store.issue(USER_A);

    // Wait past expiry.
    await new Promise((r) => setTimeout(r, 5));

    await expect(store.rotate(issued1.raw)).rejects.toBeInstanceOf(
      RefreshTokenExpiredError,
    );

    const rows = [...db.rows.values()];

    // Critical assertion: NO row was revoked. The expired token's row
    // is left untouched (no rotated_at, no revoked_at) so a subsequent
    // presentation of the same expired raw value still hits the
    // expired branch rather than the replay branch.
    for (const row of rows) {
      expect(row.rotated_at).toBeNull();
      expect(row.revoked_at).toBeNull();
    }

    // The parallel session — also expired by clock, but never
    // presented — must remain rotateable in principle (i.e. its row is
    // not flagged as compromised). Of course rotate() will still
    // complain that it's expired, but with the expired error, NOT
    // the invalid error. That distinction is the whole point of this
    // test.
    await expect(store.rotate(issued2.raw)).rejects.toBeInstanceOf(
      RefreshTokenExpiredError,
    );
  });
});

describe('createRefreshTokenStore — revoke idempotency', () => {
  it('revoke() on an unknown raw token is a silent no-op (no throw)', async () => {
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    // Pre-populate a row to make sure we don't accidentally revoke
    // something we shouldn't.
    await store.issue(USER_A);
    const before = [...db.rows.values()].map((r) => ({ ...r }));

    await expect(store.revoke('token-that-was-never-issued')).resolves.toBeUndefined();

    const after = [...db.rows.values()];
    expect(after).toHaveLength(before.length);
    expect(after[0]?.revoked_at).toBeNull();
    expect(after[0]?.rotated_at).toBeNull();
  });

  it('revoke() on an active token marks it revoked; subsequent revoke() calls are no-ops', async () => {
    const db = makeDb();
    const store = createRefreshTokenStore(makePool(db), PEPPER);

    const issued = await store.issue(USER_A);

    // First revoke flips revoked_at.
    await store.revoke(issued.raw);
    const rowAfter1 = [...db.rows.values()][0];
    const firstRevokedAt = rowAfter1?.revoked_at;
    expect(firstRevokedAt).toBeInstanceOf(Date);

    // Second revoke is a no-op: the WHERE clause `AND revoked_at IS
    // NULL` excludes already-revoked rows so the timestamp is NOT
    // bumped. We want to assert the same Date instance survives —
    // bumping the timestamp on every revoke would let a caller
    // distinguish "first revoke" from "later revoke" by inspecting
    // the row, leaking liveness information.
    await store.revoke(issued.raw);
    const rowAfter2 = [...db.rows.values()][0];
    expect(rowAfter2?.revoked_at).toEqual(firstRevokedAt);

    // Third revoke — same expectation.
    await store.revoke(issued.raw);
    const rowAfter3 = [...db.rows.values()][0];
    expect(rowAfter3?.revoked_at).toEqual(firstRevokedAt);
  });
});

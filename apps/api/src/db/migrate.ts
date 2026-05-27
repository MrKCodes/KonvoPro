// Postgres bootstrap migration runner.
//
// Realizes Requirement 17.2 ("apply database schema migrations
// automatically before the API_Gateway accepts requests") and
// Requirement 17.8 ("on migration failure, refuse to accept inbound
// requests and preserve the pre-migration state without rollback to a
// partial state"). The single SQL file at infra/postgres/init.sql is the
// source of truth (design.md §4); it is mounted into the postgres
// container's docker-entrypoint-initdb.d for fresh volumes AND executed
// here at api boot so reruns, upgrades, and CI environments converge.
//
// Design notes:
//   - One Pool, opened just for migration, executed inside a single
//     transaction. On any error the transaction rolls back so we never
//     leave the schema half-applied (req 17.8).
//   - The SQL file itself is idempotent (CREATE ... IF NOT EXISTS), but
//     wrapping in a transaction guards against partial writes for any
//     future non-idempotent statements we add.
//   - The pool is closed before this function returns so the api process
//     does not hold migration connections during normal serving.

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

const { Pool } = pg;

/**
 * Resolve infra/postgres/init.sql relative to this source file. From
 * apps/api/src/db/migrate.ts the bootstrap SQL lives four directories up.
 * The path resolves identically whether invoked from `tsx`, `node` on the
 * compiled JS, or from a packaged container that preserves the repo
 * layout.
 */
function resolveInitSqlPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // apps/api/src/db -> apps/api/src -> apps/api -> apps -> repo root
  return resolve(here, '..', '..', '..', '..', 'infra', 'postgres', 'init.sql');
}

/**
 * Run all pending migrations against the given database. Throws on
 * failure; callers (server bootstrap, CLI) MUST treat a thrown error as a
 * hard refusal to start serving traffic.
 *
 * The function is safe to call repeatedly: every statement in init.sql
 * uses IF NOT EXISTS, and the wrapping transaction means a partial
 * application is impossible.
 */
export async function runMigrations(databaseUrl: string): Promise<void> {
  const sqlPath = resolveInitSqlPath();
  const sql = await readFile(sqlPath, 'utf8');

  const pool = new Pool({ connectionString: databaseUrl });
  const client = await pool.connect();

  try {
    // The init.sql file already wraps its DDL in BEGIN/COMMIT, but we
    // open an outer transaction defensively so any future statements
    // appended outside that block are still atomic.
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('COMMIT');
  } catch (err) {
    // ROLLBACK best-effort. Even if it fails (e.g. broken connection),
    // re-throwing the original error keeps req 17.8 intact: the api
    // process refuses to serve and the operator sees the failure.
    try {
      await client.query('ROLLBACK');
    } catch {
      // swallow secondary error; primary error is what the operator needs
    }
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

// CLI entrypoint. Allows running `node apps/api/dist/db/migrate.js` (or
// `tsx apps/api/src/db/migrate.ts`) without booting Fastify, useful for
// CI seeding and operator break-glass.
if (import.meta.url === `file://${process.argv[1]}`) {
  const databaseUrl =
    process.env['DATABASE_URL'] ??
    'postgres://konvo:konvo@postgres:5432/konvo?sslmode=disable';

  runMigrations(databaseUrl)
    .then(() => {
      // eslint-disable-next-line no-console
      console.log('migrations applied');
    })
    .catch((err: unknown) => {
      // eslint-disable-next-line no-console
      console.error('migration failed:', err);
      process.exit(1);
    });
}

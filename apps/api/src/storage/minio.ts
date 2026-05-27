// apps/api/src/storage/minio.ts
//
// MinIO / S3 storage client for E2EE attachment ciphertext blobs (task
// 5.2 — Phase 4). Realizes the I/O side of the design.md §3.3
// "Attachment Encrypt + Upload Flow" and §9 attachments REST surface:
//
//   - `POST /attachments`  -> putObject(blob_key, ciphertext)
//   - `GET  /attachments/:id` -> getObject(blob_key) returning a stream
//   - existence probe for 404s -> headObject(blob_key)
//
// The blob bytes are AES-GCM-256 ciphertext produced client-side by
// `packages/crypto/src/attachment.ts`. The AES key, IV, and tag NEVER
// reach the server; they live inside an E2EE envelope alongside the
// `AttachmentRef` (design.md §6.1). MinIO sees opaque ciphertext only —
// this preserves the blind-router invariant from design.md §1.2 even
// when the operator has full filesystem access to the attachment
// volume.
//
// Why a thin wrapper rather than calling `minio` directly from routes:
//   - Tests need to substitute an in-memory implementation. The
//     `Storage` interface decouples route code from the SDK so the
//     unit tests in `test/attachments-routes.test.ts` can run without
//     a live MinIO container or even the `minio` package being
//     resolvable in the test environment.
//   - We keep the SDK-flavoured surface area (multipart upload,
//     server-side encryption, lifecycle policy) hidden so future
//     migrations to a different S3-compatible store touch one file.
//
// Buffering vs. streaming on upload:
//   The route hands us a fully-buffered `Buffer` for the ciphertext
//   (the multipart parser is configured with a 25 MiB cap per
//   Requirement 6.3, so the whole ciphertext is in memory anyway by
//   the time we reach this layer). The `minio` SDK accepts a Buffer
//   directly, so we don't need to wrap it in a Readable.
//
// Streaming on download:
//   `getObject` returns a `Readable` from the SDK. We forward that
//   stream to the Fastify reply via `reply.send(stream)`, never
//   buffering the bytes in the API process. The reply is set with
//   `Content-Type: application/octet-stream` and a `Content-Length`
//   sourced from `headObject` so clients can show progress without
//   waiting for the stream to drain.
//
// Why no presigned URLs (Requirement 6.6):
//   The design explicitly forbids issuing presigned GETs for E2EE
//   blobs. The API process MUST mediate every read so the
//   authorization check (owner OR allowed recipient) is enforced on
//   the same code path that returns the bytes. A presigned URL would
//   bypass that check and let any user with the URL bytes fetch the
//   ciphertext.

import type { Readable } from 'node:stream';

// We import the minio SDK lazily inside `createMinioStorage` so unit
// tests that only construct a fake `Storage` never have to resolve the
// `minio` module. The dynamic import keeps the SDK out of the test
// path entirely while production code (server.ts) gets the real
// client.

/** Result of a `getObject` call. The body is a Node `Readable` that
 *  the route forwards to `reply.send(...)`. The size and mime are
 *  sourced from the same metadata HEAD that decided the object exists
 *  in the first place — they're echoed here so the route can set
 *  `Content-Length` without a second round-trip. */
export interface GetObjectResult {
  /** Node Readable stream of the ciphertext bytes. */
  readonly body: Readable;
  /** Object size in bytes (from the S3 metadata). */
  readonly sizeBytes: number;
}

/** Result of `headObject`. `null` if the object does not exist. */
export interface HeadObjectResult {
  readonly sizeBytes: number;
}

/** The minimal storage surface the attachments route needs. Restated
 *  as an interface so tests can substitute an in-memory
 *  implementation without depending on the real `minio` SDK. */
export interface Storage {
  /** Upload a buffered body under a generated key. Returns when the
   *  upload completes. */
  putObject(bucket: string, key: string, body: Buffer): Promise<void>;
  /** Fetch the object body as a Readable stream + size. Throws on
   *  missing-object so callers can distinguish 404 from genuine
   *  errors. Use `headObject` first when the route needs to short-
   *  circuit on existence. */
  getObject(bucket: string, key: string): Promise<GetObjectResult>;
  /** Probe whether an object exists, returning its size. Returns
   *  `null` if the object is missing. We never throw on a
   *  not-found case; every other failure (network, auth) MUST throw
   *  so the route's 5xx path catches it. */
  headObject(bucket: string, key: string): Promise<HeadObjectResult | null>;
}

/** Configuration passed to `createMinioStorage`. Mirrors the env
 *  contract validated by `apps/api/src/config.ts` (MINIO_ENDPOINT,
 *  MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_USE_SSL). The bucket name
 *  travels with each call rather than being baked into the client so
 *  the same client can later serve other buckets (e.g. logs export)
 *  without reconstruction. */
export interface MinioStorageConfig {
  /** `host:port` (no scheme). E.g. `minio:9000`. */
  readonly endpoint: string;
  readonly accessKey: string;
  readonly secretKey: string;
  /** Use HTTPS for the S3 connection. `false` for the local
   *  docker-compose stack; `true` for production behind TLS. */
  readonly useSsl: boolean;
}

/** Construct a real MinIO-backed `Storage` instance. The `minio` SDK
 *  is resolved lazily so tests that build their own `Storage` stub
 *  never trigger a require/import of the SDK.
 *
 *  Throws (synchronously, before returning a Storage) if the
 *  endpoint can't be parsed into `host` + `port`. The caller (server
 *  bootstrap) treats that as a hard failure: an invalid endpoint
 *  config means we cannot serve attachment uploads / downloads at
 *  all, so the process should refuse to start (Requirement 17.6
 *  spirit, applied to MinIO).
 */
export async function createMinioStorage(
  config: MinioStorageConfig,
): Promise<Storage> {
  // The `minio` package exports a `Client` class. We import via the
  // dynamic ESM form so module resolution happens at runtime; tests
  // that don't call this function never resolve the SDK.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const minioModule = (await import('minio')) as unknown as {
    readonly Client: new (opts: {
      endPoint: string;
      port: number;
      useSSL: boolean;
      accessKey: string;
      secretKey: string;
    }) => MinioClientShape;
  };

  const { host, port } = parseEndpoint(config.endpoint, config.useSsl);

  const client = new minioModule.Client({
    endPoint: host,
    port,
    useSSL: config.useSsl,
    accessKey: config.accessKey,
    secretKey: config.secretKey,
  });

  return {
    async putObject(bucket, key, body): Promise<void> {
      // The 5-arg form is `putObject(bucket, key, stream, size, meta)`.
      // We pass a Buffer (which the SDK accepts) and the byte length so
      // the SDK can set Content-Length without reading the stream
      // first. We do NOT pass content-type metadata: every blob is
      // ciphertext-as-bytes, and tagging it `application/octet-stream`
      // here is redundant with the route's reply Content-Type on the
      // download side.
      await client.putObject(bucket, key, body, body.length);
    },

    async getObject(bucket, key): Promise<GetObjectResult> {
      // Probe size first via `statObject` (head). Two round-trips on
      // the happy path is acceptable: the size lets us emit
      // Content-Length on the reply, which downloaders use for
      // progress UIs. If the object disappeared between the
      // headObject the route ran and this getObject, the underlying
      // stream errors and the route catches it as a 5xx.
      const stat = await client.statObject(bucket, key);
      const stream = await client.getObject(bucket, key);
      return { body: stream, sizeBytes: stat.size };
    },

    async headObject(bucket, key): Promise<HeadObjectResult | null> {
      try {
        const stat = await client.statObject(bucket, key);
        return { sizeBytes: stat.size };
      } catch (err) {
        if (isNotFoundError(err)) {
          return null;
        }
        throw err;
      }
    },
  };
}

/** Type-narrow shape of the minio Client we actually use. We restate
 *  it here rather than `import type { Client } from 'minio'` so this
 *  file type-checks even when the `minio` package isn't resolvable
 *  (e.g. during unit-test builds that don't ship the SDK). */
interface MinioClientShape {
  putObject(
    bucket: string,
    key: string,
    body: Buffer,
    size: number,
  ): Promise<unknown>;
  getObject(bucket: string, key: string): Promise<Readable>;
  statObject(
    bucket: string,
    key: string,
  ): Promise<{ size: number; etag?: string }>;
}

/** Parse an `endpoint` string into `{ host, port }`. The MinIO SDK
 *  takes them separately; our config exposes a single `host:port` so
 *  the env var matches the docker-compose service URL. If the port
 *  is omitted we default to 80/443 by SSL flag. */
function parseEndpoint(
  endpoint: string,
  useSsl: boolean,
): { host: string; port: number } {
  const colonIdx = endpoint.lastIndexOf(':');
  if (colonIdx < 0) {
    return { host: endpoint, port: useSsl ? 443 : 80 };
  }
  const host = endpoint.slice(0, colonIdx);
  const portStr = endpoint.slice(colonIdx + 1);
  const port = Number.parseInt(portStr, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(
      `MINIO_ENDPOINT has invalid port: ${endpoint} (port="${portStr}")`,
    );
  }
  return { host, port };
}

/** Detect a not-found / no-such-key error from the minio SDK. The SDK
 *  surfaces these as errors with a `code` field; we accept the common
 *  variants ("NoSuchKey", "NotFound") plus a generic "404" status. */
function isNotFoundError(err: unknown): boolean {
  if (err === null || err === undefined || typeof err !== 'object') {
    return false;
  }
  const e = err as { code?: unknown; statusCode?: unknown };
  if (typeof e.code === 'string') {
    const c = e.code;
    if (c === 'NoSuchKey' || c === 'NotFound' || c === 'NoSuchObject') {
      return true;
    }
  }
  if (typeof e.statusCode === 'number' && e.statusCode === 404) {
    return true;
  }
  return false;
}

// apps/web/src/app/screens/BroadcastScreen.tsx
//
// Broadcast room layout. Renders the room list (driven by the
// existing Dexie-backed `RoomList`) plus a small inline
// "Create room" form so users can actually publish a room from
// the SPA, and routes the detail pane to a read-only public view
// for the active slug — the full admin/live A/V flow needs an
// authenticated WS client which lands later.

import { useState, type FormEvent } from 'react';

import {
  RoomList,
  broadcastApi,
  BroadcastApiError,
} from '../../features/broadcast/index.js';
import { db } from '../../db/schema.js';
import { DexieRoomsStore } from '../../db/repositories/rooms.js';
import { BroadcastIcon, PlusIcon } from '../Icons.js';
import { navigate, type Route } from '../router.js';
import { PublicRoomScreen } from './PublicRoomScreen.js';

const SLUG_RE = /^[a-z0-9-]{3,64}$/;

export interface BroadcastScreenProps {
  readonly route: Route;
}

export function BroadcastScreen({ route }: BroadcastScreenProps): {
  list: JSX.Element;
  detail: JSX.Element;
} {
  const slug = route.kind === 'broadcast-room' ? route.slug : null;

  return {
    list: (
      <section aria-label="Broadcast rooms">
        <header className="list-header">
          <h2>Broadcast rooms</h2>
        </header>
        <CreateRoomForm />
        <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
          <RoomList onSelect={(picked) => navigate(`/broadcast/${picked}`)} />
        </div>
      </section>
    ),
    detail:
      slug === null ? (
        <div className="empty" style={{ flex: 1 }}>
          <BroadcastIcon size={32} />
          <h3>Public, signed posts</h3>
          <p>
            Broadcast rooms are public — posts are signed by the
            author so viewers can verify authorship, but bodies are
            plaintext. Pick a room on the left or create a new one.
          </p>
        </div>
      ) : (
        // Inline the public-read view so authenticated users see
        // the live feed for the chosen room without having to
        // bounce through the standalone /r/:slug route. The full
        // admin composer + Go Live affordance still requires a
        // wired WS client; we surface a quick path to the
        // standalone public view as a fallback.
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <PublicRoomScreen slug={slug} />
        </div>
      ),
  };
}

/**
 * Inline "Create room" form. POSTs `/rooms` and on success mirrors
 * the new row into the local rooms cache (so `RoomList` shows it
 * immediately) and routes to its broadcast view.
 *
 * The form lives in the list pane rather than the detail pane so
 * it's reachable from any /broadcast* URL without the user having
 * to leave the page.
 */
function CreateRoomForm(): JSX.Element {
  const [open, setOpen] = useState<boolean>(false);
  const [slug, setSlug] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const slugOk = SLUG_RE.test(slug);
  const nameOk = name.trim().length >= 1 && name.trim().length <= 80;
  const submitDisabled = submitting || !slugOk || !nameOk;

  async function handleSubmit(ev: FormEvent<HTMLFormElement>): Promise<void> {
    ev.preventDefault();
    if (submitDisabled) return;
    setSubmitting(true);
    setError(null);
    try {
      const room = await broadcastApi.createRoom({
        slug,
        name: name.trim(),
        ...(description.trim().length > 0
          ? { description: description.trim() }
          : {}),
      });
      // Mirror the new room into the local cache so RoomList
      // re-reads and shows it on next render.
      const store = new DexieRoomsStore(db);
      await store.upsert({
        slug: room.slug,
        roomId: room.id,
        name: room.name,
        ownerHandle: room.ownerHandle,
        createdAt: Date.parse(room.createdAt),
        subscribed: true,
      });
      setSlug('');
      setName('');
      setDescription('');
      setOpen(false);
      navigate(`/broadcast/${room.slug}`);
    } catch (err) {
      const msg =
        err instanceof BroadcastApiError
          ? err.serverError ?? `HTTP ${err.status ?? '?'}`
          : (err as Error).message;
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) {
    return (
      <div style={{ padding: 'var(--space-3) var(--space-4) 0' }}>
        <button
          type="button"
          onClick={() => setOpen(true)}
          style={{
            width: '100%',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 'var(--space-2)',
          }}
          data-testid="broadcast-create-toggle"
        >
          <PlusIcon size={16} label="Create room" />
          <span>Create a room</span>
        </button>
      </div>
    );
  }

  return (
    <form
      onSubmit={(ev) => void handleSubmit(ev)}
      data-testid="broadcast-create-form"
      style={{
        padding: 'var(--space-3) var(--space-4)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-3)',
        borderBottom: '1px solid var(--color-border)',
        background: 'var(--color-bg-elevated)',
      }}
    >
      <h3 style={{ margin: 0, fontSize: 'var(--type-16)' }}>New room</h3>
      <label>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--type-12)',
            color: 'var(--color-fg-muted)',
            marginBottom: 'var(--space-1)',
          }}
        >
          Slug (3–64 chars; lowercase, digits, hyphens)
        </span>
        <input
          type="text"
          value={slug}
          onChange={(e) => setSlug(e.currentTarget.value.toLowerCase())}
          pattern="[a-z0-9-]{3,64}"
          required
          minLength={3}
          maxLength={64}
          data-testid="broadcast-create-slug"
          autoComplete="off"
          spellCheck={false}
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
      </label>
      <label>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--type-12)',
            color: 'var(--color-fg-muted)',
            marginBottom: 'var(--space-1)',
          }}
        >
          Name
        </span>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          required
          maxLength={80}
          data-testid="broadcast-create-name"
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
      </label>
      <label>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--type-12)',
            color: 'var(--color-fg-muted)',
            marginBottom: 'var(--space-1)',
          }}
        >
          Description (optional)
        </span>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.currentTarget.value)}
          maxLength={280}
          data-testid="broadcast-create-description"
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
      </label>
      {error !== null ? (
        <p role="alert" data-testid="broadcast-create-error" style={{ margin: 0 }}>
          {error}
        </p>
      ) : null}
      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <button
          type="submit"
          disabled={submitDisabled}
          data-testid="broadcast-create-submit"
          style={{
            background: 'var(--color-accent)',
            color: 'var(--color-accent-fg)',
            borderColor: 'var(--color-accent)',
            flex: 1,
          }}
        >
          {submitting ? 'Creating…' : 'Create room'}
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setError(null);
          }}
          data-testid="broadcast-create-cancel"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

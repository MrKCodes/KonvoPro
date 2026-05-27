// apps/web/src/features/devices/DeviceList.tsx
//
// Settings → Devices listing (task 2.10).
//
// Realizes Requirement 2.10:
//   - Renders the user's enrolled devices via `GET /devices`.
//   - Each row carries a "Revoke" button. Clicking it opens a
//     confirmation modal; only after explicit confirm does the SPA
//     fire `DELETE /devices/:id`. This matches the "revoke
//     confirmation modal" from the task brief.
//   - On revoke success the row disappears from the list. If the
//     user revoked their CURRENT browser's device id (matched against
//     `readStoredDeviceId()`), we also clear the local cache so the
//     next reload re-enrolls.
//
// The component is intentionally framework-agnostic (no router) — the
// parent screen owns navigation. We surface a `getCurrentDeviceId`
// override so tests don't need to touch localStorage.

import { useCallback, useEffect, useMemo, useState } from 'react';

import {
  authApi,
  AuthApiError,
  type AuthApiClient,
} from '../auth/api.js';
import {
  clearStoredDeviceId,
  readStoredDeviceId,
} from './enrollment.js';
import type { DeviceListItem } from '@konvo/protocol';

export interface DeviceListProps {
  readonly api?: AuthApiClient;
  /** Override how the component identifies the current browser's
   *  device id, so tests don't need to mutate localStorage. */
  readonly getCurrentDeviceId?: () => string | null;
}

interface FetchState {
  readonly kind: 'idle' | 'loading' | 'ready' | 'error';
  readonly devices: readonly DeviceListItem[];
  readonly errorMessage?: string;
}

const INITIAL: FetchState = { kind: 'idle', devices: [] };

interface RevokePrompt {
  readonly device: DeviceListItem;
}

export function DeviceList(props: DeviceListProps): JSX.Element {
  const apiClient = props.api ?? authApi;
  const getCurrentDeviceId = useMemo(
    () => props.getCurrentDeviceId ?? readStoredDeviceId,
    [props.getCurrentDeviceId],
  );

  const [state, setState] = useState<FetchState>(INITIAL);
  const [revokePrompt, setRevokePrompt] = useState<RevokePrompt | null>(null);
  const [revoking, setRevoking] = useState<boolean>(false);

  const refresh = useCallback(async (): Promise<void> => {
    setState({ kind: 'loading', devices: [] });
    try {
      const res = await apiClient.listDevices();
      setState({ kind: 'ready', devices: res.devices });
    } catch (err) {
      setState({
        kind: 'error',
        devices: [],
        errorMessage: errorToMessage(err),
      });
    }
  }, [apiClient]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleConfirmRevoke(): Promise<void> {
    if (revokePrompt === null) return;
    const target = revokePrompt.device;
    setRevoking(true);
    try {
      await apiClient.revokeDevice(target.id);
      // If we just revoked THIS browser's device, clear the cached
      // deviceId so a subsequent reload re-enrolls cleanly. The user
      // is also effectively logged out of the current device — but
      // logging out here is the parent screen's call.
      const current = getCurrentDeviceId();
      if (current === target.id) {
        clearStoredDeviceId();
      }
      setRevokePrompt(null);
      await refresh();
    } catch (err) {
      setState((prev) => ({
        ...prev,
        kind: 'error',
        errorMessage: errorToMessage(err),
      }));
    } finally {
      setRevoking(false);
    }
  }

  return (
    <section aria-labelledby="device-list-heading">
      <h1 id="device-list-heading">Your devices</h1>

      {state.kind === 'loading' ? (
        <p role="status">Loading…</p>
      ) : null}

      {state.kind === 'error' ? (
        <p role="alert" data-testid="device-list-error">
          {state.errorMessage ?? 'Failed to load devices.'}
        </p>
      ) : null}

      {state.kind === 'ready' && state.devices.length === 0 ? (
        <p>No enrolled devices yet.</p>
      ) : null}

      {state.devices.length > 0 ? (
        <ul data-testid="device-list">
          {state.devices.map((device) => {
            const isCurrent = getCurrentDeviceId() === device.id;
            return (
              <li key={device.id} data-testid={`device-row-${device.id}`}>
                <span>{device.name}</span>
                {isCurrent ? <span aria-label="this device"> (this device)</span> : null}
                <span>
                  {' · '}Last seen{' '}
                  {device.lastSeenAt === null ? 'never' : formatTimestamp(device.lastSeenAt)}
                </span>
                <button
                  type="button"
                  onClick={() => setRevokePrompt({ device })}
                  data-testid={`revoke-button-${device.id}`}
                >
                  Revoke
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}

      {revokePrompt !== null ? (
        <RevokeModal
          device={revokePrompt.device}
          isCurrent={getCurrentDeviceId() === revokePrompt.device.id}
          busy={revoking}
          onConfirm={() => void handleConfirmRevoke()}
          onCancel={() => setRevokePrompt(null)}
        />
      ) : null}
    </section>
  );
}

interface RevokeModalProps {
  readonly device: DeviceListItem;
  readonly isCurrent: boolean;
  readonly busy: boolean;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}

/** Confirmation modal. We use a `<dialog>` for the built-in modal
 *  semantics; jsdom renders it as an inert region by default but
 *  Playwright / a real browser surface focus management for free.
 *  We wire `aria-modal` and `role="dialog"` explicitly so tests can
 *  query by role without depending on `<dialog>`-specific behaviour. */
function RevokeModal(props: RevokeModalProps): JSX.Element {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="revoke-dialog-heading"
      data-testid="revoke-dialog"
    >
      <h2 id="revoke-dialog-heading">Revoke this device?</h2>
      <p>
        Revoking <strong>{props.device.name}</strong> will sign that browser out
        and remove its remaining one-time prekeys.{' '}
        {props.isCurrent ? (
          <span>This is the device you're using right now — you'll be signed out immediately.</span>
        ) : null}
      </p>
      <button
        type="button"
        onClick={props.onConfirm}
        disabled={props.busy}
        data-testid="revoke-confirm-button"
      >
        {props.busy ? 'Revoking…' : 'Revoke'}
      </button>
      <button
        type="button"
        onClick={props.onCancel}
        disabled={props.busy}
        data-testid="revoke-cancel-button"
      >
        Cancel
      </button>
    </div>
  );
}

function formatTimestamp(iso: string): string {
  // Best-effort human format; the value comes from the server as
  // ISO-8601 UTC. Falls back to the raw string on parse failure so a
  // future server change to a non-ISO format doesn't crash the UI.
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return iso;
  return new Date(parsed).toLocaleString();
}

function errorToMessage(err: unknown): string {
  if (err instanceof AuthApiError) {
    if (err.kind === 'http' && err.status === 401) {
      return 'Your session has expired. Please log in again.';
    }
    if (err.kind === 'http' && err.status === 404) {
      return 'That device is no longer available.';
    }
    if (err.kind === 'network') {
      return 'Could not reach the Konvo server. Please check your connection.';
    }
    return 'Failed to update devices. Please try again.';
  }
  return 'Failed to update devices. Please try again.';
}

// apps/web/src/app/Rail.tsx
//
// Persistent vertical rail (desktop / tablet) that collapses to a
// 56px bottom tab bar on mobile via shell.css media queries. The
// component itself doesn't change at the mobile breakpoint; only the
// CSS layout flips.
//
// The active item is derived from the current Route discriminator.
// The leading-edge accent bar is a `::before` pseudo on
// `.rail__btn[aria-current=page]` (see shell.css).

import { navigate, type Route } from './router.js';
import {
  BroadcastIcon,
  CallIcon,
  MessagesIcon,
  SettingsIcon,
} from './Icons.js';

interface RailItem {
  readonly key: string;
  readonly label: string;
  readonly path: string;
  readonly icon: JSX.Element;
  readonly active: (r: Route) => boolean;
}

const ITEMS: ReadonlyArray<RailItem> = [
  {
    key: 'dm',
    label: 'Messages',
    path: '/dm',
    icon: <MessagesIcon label="Messages" />,
    active: (r) =>
      r.kind === 'dm-list' || r.kind === 'dm-thread' || r.kind === 'home',
  },
  {
    key: 'broadcast',
    label: 'Rooms',
    path: '/broadcast',
    icon: <BroadcastIcon label="Rooms" />,
    active: (r) => r.kind === 'broadcast-list' || r.kind === 'broadcast-room',
  },
  {
    key: 'calls',
    label: 'Calls',
    path: '/calls',
    icon: <CallIcon label="Calls" />,
    active: (r) => r.kind === 'calls',
  },
  {
    key: 'settings',
    label: 'Settings',
    path: '/settings',
    icon: <SettingsIcon label="Settings" />,
    active: (r) => r.kind === 'settings',
  },
];

export interface RailProps {
  readonly route: Route;
  readonly bottom?: JSX.Element;
}

export function Rail({ route, bottom }: RailProps): JSX.Element {
  return (
    <nav className="rail" aria-label="Primary">
      <div className="rail__brand" aria-hidden>
        K
      </div>
      <div className="rail__items">
        {ITEMS.map((it) => {
          const active = it.active(route);
          return (
            <button
              key={it.key}
              type="button"
              className="rail__btn"
              aria-current={active ? 'page' : undefined}
              aria-label={it.label}
              onClick={() => navigate(it.path)}
              title={it.label}
            >
              {it.icon}
              <span className="rail__label">{it.label}</span>
            </button>
          );
        })}
      </div>
      {bottom !== undefined ? (
        <div className="rail__bottom">{bottom}</div>
      ) : null}
    </nav>
  );
}

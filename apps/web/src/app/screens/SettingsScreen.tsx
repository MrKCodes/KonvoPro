// apps/web/src/app/screens/SettingsScreen.tsx
//
// Wraps the existing `<Settings />` panel in a list/detail layout.
// The list pane is a scroll-spy nav targeting the `<section>`
// landmarks that `<Settings />` already renders for each subsection
// (Devices / Appearance / Key backup, etc.).
//
// Note: Shell.tsx invokes `SettingsScreen()` as a plain function
// (not a JSX element), so this module CANNOT call React hooks
// directly. The stateful nav and scroll-spy live in the
// `<SettingsNavPanel />` component returned inside `list`.

import { useEffect, useRef, useState } from 'react';

import { Settings } from '../../features/settings/index.js';

const SECTIONS: ReadonlyArray<{ id: string; label: string }> = [
  { id: 'settings-devices-heading', label: 'Devices' },
  { id: 'settings-appearance-heading', label: 'Appearance' },
  { id: 'settings-backup-heading', label: 'Key backup' },
];

export function SettingsScreen(): { list: JSX.Element; detail: JSX.Element } {
  const detailId = 'settings-detail-body';
  return {
    list: <SettingsNavPanel detailId={detailId} />,
    detail: (
      <div id={detailId} className="detail-body">
        <Settings />
      </div>
    ),
  };
}

interface SettingsNavPanelProps {
  readonly detailId: string;
}

function SettingsNavPanel({ detailId }: SettingsNavPanelProps): JSX.Element {
  const [active, setActive] = useState<string>(SECTIONS[0]!.id);
  // Capture a stable ref to the scroll viewport. We look it up by
  // id rather than passing a ref across the screen function
  // boundary — the detail pane is rendered separately by `Shell`
  // so a ref is not portable here.
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const root = document.getElementById(detailId);
    if (root === null) return;
    const targets = SECTIONS.map((s) => document.getElementById(s.id)).filter(
      (el): el is HTMLElement => el !== null,
    );
    if (targets.length === 0) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        const top = visible[0];
        if (top !== undefined && top.target.id !== '') {
          setActive(top.target.id);
        }
      },
      { root, rootMargin: '0px 0px -70% 0px', threshold: 0 },
    );
    for (const t of targets) observer.observe(t);
    observerRef.current = observer;
    return () => {
      observer.disconnect();
      observerRef.current = null;
    };
  }, [detailId]);

  function jumpTo(id: string): void {
    const el = document.getElementById(id);
    if (el === null) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    // Move keyboard focus so screen-reader users land on the
    // heading immediately rather than having to tab into the
    // section. Headings need an explicit tabindex to be focusable.
    el.setAttribute('tabindex', '-1');
    el.focus({ preventScroll: true });
  }

  return (
    <section aria-label="Settings sections">
      <header className="list-header">
        <h2>Settings</h2>
      </header>
      <nav style={{ padding: 'var(--space-3)' }} aria-label="Settings nav">
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {SECTIONS.map((s) => {
            const selected = active === s.id;
            return (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => jumpTo(s.id)}
                  aria-current={selected ? 'true' : undefined}
                  data-testid={`settings-nav-${s.id}`}
                  style={{
                    width: '100%',
                    textAlign: 'left',
                    background: selected
                      ? 'var(--color-bg-elevated)'
                      : 'transparent',
                    borderColor: selected
                      ? 'var(--color-accent)'
                      : 'transparent',
                    padding: 'var(--space-2) var(--space-3)',
                    marginBottom: 'var(--space-1)',
                    color: selected
                      ? 'var(--color-fg)'
                      : 'var(--color-fg-muted)',
                    fontSize: 'var(--type-14)',
                    fontWeight: selected ? 600 : 400,
                  }}
                >
                  {s.label}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
    </section>
  );
}

// apps/web/src/app/Icons.tsx
//
// Inline-SVG icon set. 20px viewport, 1.5px stroke, currentColor.
// No icon-font runtime dependency. Each icon takes optional
// `aria-label`; omit it for decorative-only use sites.
//
// Style note: every <svg> sets `aria-hidden="true"` by default and
// `role="img"` + `aria-label` only when the caller passes a label, so
// icon-only buttons can wrap us with their own label without a
// double-announce.

import type { SVGProps } from 'react';

interface IconProps extends SVGProps<SVGSVGElement> {
  readonly size?: number;
  readonly label?: string;
}

const baseProps = (
  size: number,
  label: string | undefined,
): SVGProps<SVGSVGElement> => ({
  width: size,
  height: size,
  viewBox: '0 0 20 20',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  ...(label === undefined
    ? { 'aria-hidden': true }
    : { role: 'img', 'aria-label': label }),
});

export function MessagesIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M3 5.5C3 4.67 3.67 4 4.5 4h11c.83 0 1.5.67 1.5 1.5v7c0 .83-.67 1.5-1.5 1.5H8l-3.5 3v-3H4.5C3.67 14 3 13.33 3 12.5v-7Z" />
    </svg>
  );
}

export function BroadcastIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <circle cx="10" cy="10" r="2" />
      <path d="M5.5 5.5a6.4 6.4 0 0 0 0 9M14.5 5.5a6.4 6.4 0 0 1 0 9" />
      <path d="M3 3.5a9.2 9.2 0 0 0 0 13M17 3.5a9.2 9.2 0 0 1 0 13" />
    </svg>
  );
}

export function CallIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M4 5.5C4 4.67 4.67 4 5.5 4h2.05c.36 0 .68.26.74.62l.55 3.18c.06.32-.09.64-.37.81L7 9.5a8 8 0 0 0 3.5 3.5l.89-1.47c.17-.28.49-.43.81-.37l3.18.55c.36.06.62.38.62.74v2.05c0 .83-.67 1.5-1.5 1.5C9.6 16.5 3.5 10.4 3.5 5.5Z" />
    </svg>
  );
}

export function SettingsIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <circle cx="10" cy="10" r="2.5" />
      <path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.4 4.4l1.4 1.4M14.2 14.2l1.4 1.4M4.4 15.6l1.4-1.4M14.2 5.8l1.4-1.4" />
    </svg>
  );
}

export function LockIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <rect x="4.5" y="9" width="11" height="7" rx="1.5" />
      <path d="M7 9V6.5a3 3 0 1 1 6 0V9" />
    </svg>
  );
}

export function CheckIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M4 10.5l3.5 3.5L16 5.5" />
    </svg>
  );
}

export function ShieldCheckIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M10 2.5l6 2v5.2c0 4-2.6 6.4-6 7.8-3.4-1.4-6-3.8-6-7.8V4.5l6-2Z" />
      <path d="M7 10l2 2 4-4" />
    </svg>
  );
}

export function SunIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <circle cx="10" cy="10" r="3.5" />
      <path d="M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2M3.7 3.7l1.4 1.4M14.9 14.9l1.4 1.4M3.7 16.3l1.4-1.4M14.9 5.1l1.4-1.4" />
    </svg>
  );
}

export function MoonIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M16 12.5A6.5 6.5 0 0 1 7.5 4 6.5 6.5 0 1 0 16 12.5Z" />
    </svg>
  );
}

export function MonitorIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <rect x="2.5" y="3.5" width="15" height="10" rx="1.5" />
      <path d="M7 17h6M10 13.5V17" />
    </svg>
  );
}

export function ChevronLeftIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M12.5 4 6 10l6.5 6" />
    </svg>
  );
}

export function PlusIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M10 4v12M4 10h12" />
    </svg>
  );
}

export function LogoutIcon({ size = 20, label, ...rest }: IconProps): JSX.Element {
  return (
    <svg {...baseProps(size, label)} {...rest}>
      <path d="M9 4.5H5A1.5 1.5 0 0 0 3.5 6v8A1.5 1.5 0 0 0 5 15.5h4" />
      <path d="M13 7.5l3 2.5-3 2.5M16 10H8" />
    </svg>
  );
}

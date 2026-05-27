// apps/web/src/App.tsx
//
// Root app component. The whole shell + routing logic lives in
// `app/Shell.tsx` and `app/router.tsx` so this file's only job is
// to mount the Shell and act as a thin React boundary.

import { Shell } from './app/Shell.js';

export function App(): JSX.Element {
  return <Shell />;
}

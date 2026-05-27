// Ambient declaration for the deep import `qrcode/lib/browser.js`.
//
// `@types/qrcode` types the package's main entry but doesn't export
// types for the browser-only sub-path (`qrcode/lib/browser.js`),
// which we use from `apps/web/src/features/calls/InCallSafetyNumber.tsx`
// to avoid the canvas-dependent default entry.
//
// We declare the module as `unknown` and let the call site re-cast
// to the precise `toString` shape it consumes — the indirection is
// already there in the component.
declare module 'qrcode/lib/browser.js' {
  const qrcodeBrowser: unknown;
  export default qrcodeBrowser;
  export const toString: unknown;
}

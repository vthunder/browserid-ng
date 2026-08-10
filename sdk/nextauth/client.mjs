// @browserid-ng/nextauth/client — browser helpers that drive the BrowserID
// login dialog and hand you a presentation to pass to Auth.js `signIn`.
// Browser-only (uses window/document/navigator). Import from the client.

let loadPromise = null;

/** Load the broker's include.js once (installs `navigator.id`). */
export function loadBrowserID(broker = "https://browserid.me") {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("loadBrowserID is browser-only"));
  }
  if (window.navigator && window.navigator.id) return Promise.resolve();
  if (loadPromise) return loadPromise;
  const base = String(broker).replace(/\/+$/, "");
  loadPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = `${base}/include.js`;
    s.async = true;
    s.setAttribute("data-browserid-url", base);
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${s.src}`));
    document.head.appendChild(s);
  });
  return loadPromise;
}

/**
 * Register the explicit-trigger login observers (spec v2 `watch` contract).
 * Call ONCE at page init; `onlogin(presentation)` fires after a user-triggered
 * request completes (including across a full-page redirect).
 */
export async function watchBrowserID({ broker, onlogin, onlogout, onready } = {}) {
  await loadBrowserID(broker);
  window.navigator.id.watch({
    onlogin: (presentation) => onlogin && onlogin(presentation),
    onlogout: () => onlogout && onlogout(),
    onready: () => onready && onready(),
  });
}

/** Trigger the login dialog (call on a user click). */
export async function requestBrowserID({ broker, siteName, siteLogo } = {}) {
  await loadBrowserID(broker);
  window.navigator.id.request(
    siteName || siteLogo ? { siteName, siteLogo } : {}
  );
}

/** Tell the identity layer the user logged out (disables auto-reauth). */
export async function logoutBrowserID({ broker } = {}) {
  await loadBrowserID(broker);
  window.navigator.id.logout();
}

/**
 * One-shot convenience: open the dialog and resolve with the presentation.
 * For apps that prefer an imperative `const p = await signInWithBrowserID()`
 * over the observer style; then call your framework's `signIn("browserid",
 * { presentation: p })`.
 */
export function signInWithBrowserID({ broker, siteName, siteLogo } = {}) {
  return loadBrowserID(broker).then(
    () =>
      new Promise((resolve) => {
        let settled = false;
        window.navigator.id.watch({
          onlogin: (presentation) => {
            if (!settled) {
              settled = true;
              resolve(presentation);
            }
          },
          onlogout: () => {},
        });
        window.navigator.id.request(
          siteName || siteLogo ? { siteName, siteLogo } : {}
        );
      })
  );
}

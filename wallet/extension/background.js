// Service worker: talks to the native wallet on 127.0.0.1, holding the
// pairing token in extension storage.
const WALLET = 'http://127.0.0.1:8873';

async function getToken() {
  const { walletToken } = await chrome.storage.local.get('walletToken');
  return walletToken || null;
}

async function pair() {
  const res = await fetch(`${WALLET}/pair`, { method: 'POST' });
  if (!res.ok) throw new Error(`pairing failed: ${res.status}`);
  const { token } = await res.json();
  await chrome.storage.local.set({ walletToken: token });
  return token;
}

async function walletCall(path, body) {
  let token = await getToken();
  if (!token) token = await pair();
  const res = await fetch(`${WALLET}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-wallet-token': token },
    body: JSON.stringify(body || {}),
  });
  if (res.status === 401) { // stale token (app reinstalled) — re-pair once
    token = await pair();
    return walletCall(path, body);
  }
  return res.json();
}

// The requesting page's origin is what the BROWSER says about the sender,
// never what the page wrote into the message: page script cannot forge
// sender.origin (spec §7.3 "trusted origin"; bean fta9). The sender is the
// frame that asked, so an iframe requests for its own origin.
function senderOrigin(sender) {
  if (sender.origin && /^https?:/.test(sender.origin)) return sender.origin;
  try { return new URL(sender.url).origin; } catch { return null; }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      const origin = senderOrigin(sender);
      if (!origin || !/^https?:/.test(origin)) {
        sendResponse({ error: 'untrusted sender origin' });
      } else if (msg.cmd === 'login') {
        sendResponse(await walletCall('/login', {
          origin,
          acceptedFallbacks: msg.payload.acceptedFallbacks || null,
        }));
      } else {
        sendResponse({ error: 'unsupported_kind', kind: msg.cmd });
      }
    } catch (err) {
      sendResponse({ error: String(err.message || err) });
    }
  })();
  return true; // async sendResponse
});

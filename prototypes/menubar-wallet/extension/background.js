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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.cmd === 'login') {
        sendResponse(await walletCall('/login', { origin: msg.payload.origin }));
      } else {
        sendResponse({ error: `unknown cmd ${msg.cmd}` });
      }
    } catch (err) {
      sendResponse({ error: String(err.message || err) });
    }
  })();
  return true; // async sendResponse
});

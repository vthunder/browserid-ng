// Isolated-world relay: bridges the page shim <-> extension service worker.
window.addEventListener('message', (ev) => {
  if (ev.source !== window || !ev.data || ev.data.__bidWallet !== 'request') return;
  const { id, cmd, payload } = ev.data;
  chrome.runtime.sendMessage({ cmd, payload }, (result) => {
    window.postMessage({ __bidWallet: 'response', id, result: result ?? { error: 'no response' } }, '*');
  });
});

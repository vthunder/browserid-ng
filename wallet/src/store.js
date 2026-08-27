// Wallet state at rest, encrypted under the OS keychain: Electron's
// safeStorage derives its encryption key from the login keychain on macOS
// (Keychain-gated custody — the ciphertext on disk is useless without the
// user's login session). Replaces the prototype's plaintext 0600 JSON.
//
// Where safeStorage is unavailable (some Linux dev setups), we fall back to
// plaintext-with-0600 and say so loudly — never silently.
const fs = require('fs/promises');
const path = require('path');

let encFile = null;
let plainFile = null;
let encrypted = false;
let data = {};

const EMPTY = {
  pairToken: null,
  identity: null,
  domain: null,     // access-request `domain` claim = the issuer
  mintUrl: null,
  holder: null,
  holderPrefix: null,
  deviceKey: null,
  deviceCert: null,
  configKey: null,
  configCert: null,
  warrants: {},     // audience -> signed login-warrant JWS
  warrantRefs: {},  // audience -> { uri, idx } (allocated status refs)
  bootstrappedAt: null,
};

async function init(userDataDir) {
  const { safeStorage } = require('electron');
  encFile = path.join(userDataDir, 'wallet-store.enc');
  plainFile = path.join(userDataDir, 'wallet-store.json');
  encrypted = safeStorage.isEncryptionAvailable();
  if (!encrypted) {
    console.warn('[wallet] OS keychain encryption UNAVAILABLE — falling back to plaintext 0600 store');
  }
  data = { ...EMPTY };
  try {
    const blob = await fs.readFile(encFile);
    data = { ...data, ...JSON.parse(safeStorage.decryptString(blob)) };
    return;
  } catch { /* no encrypted store yet */ }
  try {
    // A plaintext store from a keychain-less run (or to upgrade): read it,
    // and if encryption is available now, re-save encrypted + remove it.
    data = { ...data, ...JSON.parse(await fs.readFile(plainFile, 'utf8')) };
    if (encrypted) {
      await save();
      await fs.unlink(plainFile).catch(() => {});
    }
  } catch { /* first run */ }
}

async function save() {
  if (encrypted) {
    const { safeStorage } = require('electron');
    await fs.writeFile(encFile, safeStorage.encryptString(JSON.stringify(data)), { mode: 0o600 });
  } else {
    await fs.writeFile(plainFile, JSON.stringify(data, null, 2), { mode: 0o600 });
  }
}

module.exports = {
  init,
  state: () => data,
  encryptedAtRest: () => encrypted,
  setPairToken: async (t) => { data.pairToken = t; await save(); },
  set: async (patch) => { Object.assign(data, patch); await save(); },
  reset: async () => { data = { ...EMPTY }; await save(); },
};

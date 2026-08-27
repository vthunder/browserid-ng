// Tiny file-backed store for the prototype: pairing token, device key/certs,
// identity. NOT production key storage — Keychain integration is a follow-up.
const fs = require('fs/promises');
const path = require('path');

let file = null;
let data = { pairToken: null, identity: null, deviceKey: null, deviceCert: null, session: null };

async function init(userDataDir) {
  file = path.join(userDataDir, 'wallet-store.json');
  try {
    data = { ...data, ...JSON.parse(await fs.readFile(file, 'utf8')) };
  } catch { /* first run */ }
}

async function save() {
  await fs.writeFile(file, JSON.stringify(data, null, 2), { mode: 0o600 });
}

module.exports = {
  init,
  state: () => data,
  setPairToken: async (t) => { data.pairToken = t; await save(); },
  set: async (patch) => { Object.assign(data, patch); await save(); },
};

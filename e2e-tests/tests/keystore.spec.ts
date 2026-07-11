/**
 * e2fi: the non-extractable keystore module, exercised in a real browser.
 * Covers the crypto core that the dialog, consent, and /account pages share —
 * especially the consent/account warrant-signing paths not otherwise in e2e.
 */
import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BROKER_URL || 'http://localhost:3000';

test('non-extractable key: generate / store / sign / verify round-trip', async ({ page }) => {
  // Any page on the broker origin loads keystore.js; dialog.html is simplest.
  await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
  await page.waitForFunction(() => !!(window as any).Keystore, { timeout: 5000 });

  const r = await page.evaluate(async () => {
    const ks = (window as any).Keystore;
    const email = 'ks-test-' + Date.now() + '@example.com';

    // 1. Generate a non-extractable keypair.
    const kp = await ks.generate();

    // 2. Confirm the private key is NON-EXTRACTABLE (export must throw).
    let extractable = true;
    try { await crypto.subtle.exportKey('jwk', kp.privateKey); } catch { extractable = false; }

    // 3. Store + retrieve by email.
    await ks.put('test.issuer', email, { privateKey: kp.privateKey, publicKeyX: kp.publicKeyX, cert: 'aa.bb.cc' });
    const recs = await ks.forEmail(email);
    const gotHandle = recs.length === 1 && !!recs[0].privateKey && recs[0].cert === 'aa.bb.cc';

    // 4. Sign with the handle, then verify the signature against the public key —
    //    proving the same crypto the warrant/assertion signing relies on works.
    const msg = 'header.payload';
    const sigB64 = await ks.sign(kp.privateKey, msg);
    const pub = await crypto.subtle.importKey('jwk',
      { kty: 'OKP', crv: 'Ed25519', x: kp.publicKeyX }, { name: 'Ed25519' }, false, ['verify']);
    const sig = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const verified = await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig, new TextEncoder().encode(msg));

    return { extractable, gotHandle, verified };
  });

  expect(r.extractable, 'private key must be non-extractable').toBe(false);
  expect(r.gotHandle, 'stored handle round-trips by email').toBe(true);
  expect(r.verified, 'signature from the non-extractable handle verifies').toBe(true);
});

test('migration: legacy localStorage keys import as non-extractable, then the blob is wiped', async ({ page }) => {
  await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
  await page.waitForFunction(() => !!(window as any).Keystore, { timeout: 5000 });

  const r = await page.evaluate(async () => {
    // Seed a legacy localStorage key (valid Ed25519 JWK: generate + export).
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const email = 'legacy-' + Date.now() + '@example.com';
    localStorage.setItem('emails', JSON.stringify({
      'legacy.issuer': { [email]: { priv: { algorithm: 'Ed25519', d: priv.d, x: priv.x }, cert: 'aa.bb.cc' } }
    }));

    await (window as any).Keystore.migrateFromLocalStorage();

    const recs = await (window as any).Keystore.forEmail(email);
    let extractable = true;
    if (recs[0]) { try { await crypto.subtle.exportKey('jwk', recs[0].privateKey); } catch { extractable = false; } }
    return { migrated: recs.length === 1, extractable, blobGone: localStorage.getItem('emails') === null };
  });

  expect(r.migrated, 'legacy key imported into IndexedDB').toBe(true);
  expect(r.extractable, 'migrated key is now non-extractable').toBe(false);
  expect(r.blobGone, 'legacy localStorage blob wiped').toBe(true);
});

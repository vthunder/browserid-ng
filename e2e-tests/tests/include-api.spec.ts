import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('include.js API', () => {
  test.beforeEach(async ({ page }) => {
    // Load a page with include.js from the broker domain
    await page.goto('http://localhost:3000/dialog/test.html');
    // Wait for navigator.id to be defined
    await page.waitForFunction(() => typeof (navigator as any).id === 'object', {
      timeout: 5000
    });
  });

  test('navigator.id is available', async ({ page }) => {
    const navIdType = await page.evaluate(() => typeof (navigator as any).id);
    expect(navIdType).toBe('object');
  });

  test('expected public API functions are available', async ({ page }) => {
    const apiFunctions = ['get', 'getVerifiedEmail', 'logout', 'request', 'watch'];

    for (const func of apiFunctions) {
      const funcType = await page.evaluate((f) => typeof (navigator as any).id[f], func);
      expect(funcType).toBe('function');
    }
  });

  test('watch() rejects invalid loggedInUser values', async ({ page }) => {
    // These should throw errors
    const invalidValues = [
      'true',      // boolean true
      '{}',        // object
      '[]',        // array
      '1'          // number
    ];

    for (const val of invalidValues) {
      const throws = await page.evaluate((v) => {
        const value = v === 'true' ? true : v === '{}' ? {} : v === '[]' ? [] : v === '1' ? 1 : v;
        try {
          (navigator as any).id.watch({
            loggedInUser: value,
            onlogin: function() {},
            onlogout: function() {}
          });
          return false;
        } catch (e) {
          return true;
        }
      }, val);

      expect(throws).toBe(true);
    }
  });

  test('watch() accepts valid loggedInUser values', async ({ page }) => {
    // These should not throw errors: string, null, undefined, false
    const validValues = [
      { val: '"test@example.com"', desc: 'string email' },
      { val: 'null', desc: 'null' },
      { val: 'undefined', desc: 'undefined' },
      { val: 'false', desc: 'false' }
    ];

    for (const { val, desc } of validValues) {
      const throws = await page.evaluate((v) => {
        const value = v === '"test@example.com"' ? 'test@example.com' :
                      v === 'null' ? null :
                      v === 'undefined' ? undefined :
                      v === 'false' ? false : v;
        try {
          (navigator as any).id.watch({
            loggedInUser: value,
            onlogin: function() {},
            onlogout: function() {}
          });
          return false;
        } catch (e) {
          return true;
        }
      }, val);

      expect(throws).toBe(false);
    }
  });

  test('stateless mode rejects loggedInUser', async ({ page }) => {
    // Stateless mode (no onlogout) should not accept loggedInUser
    const throws = await page.evaluate(() => {
      try {
        (navigator as any).id.watch({
          onlogin: function() {},
          loggedInUser: 'test@example.com'
        });
        return false;
      } catch (e) {
        return true;
      }
    });

    expect(throws).toBe(true);
  });

  test('onmatch is ignored with a warning and never fires (watch() v2)', async ({ page }) => {
    // v2 contract (bean 6u70): silent reconciliation is gone, so onmatch has
    // no trigger. Passing it is tolerated for back-compat — warned, ignored,
    // never invoked — and no longer throws.
    const result = await page.evaluate(async () => {
      const warnings: string[] = [];
      const origWarn = console.warn;
      console.warn = (...args: any[]) => { warnings.push(args.join(' ')); origWarn.apply(console, args); };
      let threw = false;
      let matched = false;
      try {
        (navigator as any).id.watch({
          onlogin: function() {},
          onlogout: function() {},
          onmatch: function() { matched = true; }
        });
      } catch (e) {
        threw = true;
      }
      console.warn = origWarn;
      await new Promise((r) => setTimeout(r, 500));
      return { threw, matched, warned: warnings.some((w) => w.includes('onmatch')) };
    });

    expect((result as any).threw).toBe(false);
    expect((result as any).matched).toBe(false);
    expect((result as any).warned).toBe(true);
  });

  test('watch() creates no hidden iframes (communication_iframe is gone)', async ({ page }) => {
    await page.evaluate(() => {
      (navigator as any).id.watch({
        onlogin: function() {},
        onlogout: function() {}
      });
    });

    await page.waitForTimeout(1000);
    const iframeCount = await page.evaluate(() => document.querySelectorAll('iframe').length);
    expect(iframeCount).toBe(0);
  });

  test('onready fires once the automatic phase settles', async ({ page }) => {
    // No pending redirect return and no FedCM opt-in → the automatic phase
    // settles immediately and onready fires on its own.
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 10000);

        (navigator as any).id.watch({
          onlogin: function() {},
          onlogout: function() {},
          onready: function() {
            clearTimeout(timeout);
            resolve({ type: 'ready' });
          }
        });
      });
    });

    expect((result as any).type).toBe('ready');
  });

  test('claimed loggedInUser produces no spontaneous callback — onready only (watch() v2)', async ({ page }) => {
    // Old contract: RP claims a user the broker doesn't know → silent
    // onlogout. v2: no silent reconciliation; nothing fires but onready.
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const events: string[] = [];
        (navigator as any).id.watch({
          loggedInUser: 'nonexistent@example.com',
          onlogin: function() { events.push('login'); },
          onlogout: function() { events.push('logout'); },
          onready: function() { events.push('ready'); }
        });
        // Leave a generous window for any spurious callback, then report.
        setTimeout(() => resolve({ events }), 3000);
      });
    });

    expect((result as any).events).toEqual(['ready']);
  });

  test('logout() fires onlogout in the calling tab (watch() v2)', async ({ page }) => {
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve({ type: 'timeout' }), 5000);
        (navigator as any).id.watch({
          onlogin: function() {},
          onlogout: function() {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          }
        });
        (navigator as any).id.logout();
      });
    });

    expect((result as any).type).toBe('logout');
  });
});

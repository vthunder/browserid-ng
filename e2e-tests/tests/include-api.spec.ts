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

  test('stateless mode rejects onmatch', async ({ page }) => {
    // Stateless mode should not accept onmatch
    const throws = await page.evaluate(() => {
      try {
        (navigator as any).id.watch({
          onlogin: function() {},
          onmatch: function() {}
        });
        return false;
      } catch (e) {
        return true;
      }
    });

    expect(throws).toBe(true);
  });

  test('watch() creates communication iframe', async ({ page }) => {
    // Call watch() and verify the communication iframe is created
    await page.evaluate(() => {
      (navigator as any).id.watch({
        onlogin: function() {},
        onlogout: function() {}
      });
    });

    // Wait for iframe to be created
    await page.waitForTimeout(1000);

    // Check if a hidden iframe pointing to communication_iframe exists
    const iframeCount = await page.evaluate(() => {
      const iframes = document.querySelectorAll('iframe');
      let count = 0;
      for (const iframe of iframes) {
        if (iframe.src && iframe.src.includes('communication_iframe')) {
          count++;
        }
      }
      return count;
    });

    expect(iframeCount).toBe(1);
  });

  test('watch() with onready fires when communication_iframe loads', async ({ page }) => {
    // Check that onready is called
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

  // Note: Silent assertion (onmatch/onlogin) requires localStorage session state
  // which is only set when user signs in via the dialog, not via API.
  // This test verifies the infrastructure works by checking logout behavior
  // when the RP thinks user is logged in but broker doesn't have them in session.
  test('watch() with loggedInUser calls onlogout when not actually logged in', async ({ page }) => {
    // RP claims user is logged in, but broker has no session
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 10000);

        (navigator as any).id.watch({
          loggedInUser: 'nonexistent@example.com',
          onlogin: function(assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', assertion: assertion ? true : false });
          },
          onlogout: function() {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function() {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function() {
            // onready may fire before callbacks
          }
        });
      });
    });

    // Should call onlogout since broker doesn't have this user logged in
    expect((result as any).type).toBe('logout');
  });
});

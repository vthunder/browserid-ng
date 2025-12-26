import { test, expect } from '@playwright/test';

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
});

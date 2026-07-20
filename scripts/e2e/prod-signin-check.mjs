// Confirm regular sign-in still works on the DEPLOYED broker after the iframe
// deletion — mingo.place → dialog → email screen, and (with window.open killed)
// the redirect fallback still engages.
import { chromium } from 'playwright';
const browser = await chromium.launch();
// popup mode
{
  const page = await (await browser.newContext()).newPage();
  const errs = []; page.on('pageerror', e => errs.push(e.message));
  await page.goto('https://mingo.place/');
  const [dialog] = await Promise.all([ page.waitForEvent('popup'), page.click('text=/sign in/i') ]);
  dialog.on('pageerror', e => errs.push('[dialog] ' + e.message));
  await dialog.waitForSelector('#email-screen.active', { timeout: 12000 });
  console.log('✓ popup mode: mingo → dialog email screen, no page errors:', errs.length === 0 ? 'clean' : errs);
}
// redirect mode
{
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => { window.open = () => null; });
  const page = await ctx.newPage();
  await page.goto('https://mingo.place/');
  await page.click('text=/sign in/i');
  await page.waitForURL('**/dialog/dialog.html?rp_redirect=1*', { timeout: 15000 });
  await page.waitForSelector('#email-screen.active', { timeout: 12000 });
  console.log('✓ redirect mode: tab navigated to dialog email screen');
}
await browser.close();

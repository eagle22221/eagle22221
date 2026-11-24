// Captures the screenshots used in the guide from a running vex server.
// Usage: node screenshots.js BASE_URL TOKEN PRACTICE_EXE [GAME_FOLDER] [BUNDLE_EXE]
// BUNDLE_EXE is the practice program with files attached (bundle_pe64.exe), shown in the
// Split view; without it the Split view is captured on PRACTICE_EXE. Pass "" to skip GAME_FOLDER.
const { chromium } = require('playwright');
const path = require('path');
const [, , base, token, exe, game, bundle] = process.argv;
const out = (name) => path.join(__dirname, 'img', name + '.png');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1120, height: 640 }, deviceScaleFactor: 2 });
  await page.emulateMedia({ colorScheme: 'dark' });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const nav = async (label) => { await page.click(`nav button:has-text("${label}")`); await page.waitForTimeout(900); };

  await page.goto(`${base}/#token=${token}`);
  await page.waitForSelector('.welcome');
  await page.screenshot({ path: out('welcome') });

  await page.goto(`${base}/#token=${token}&open=${encodeURIComponent(exe)}`);
  await page.reload();
  await page.waitForSelector('.titleblock');
  await page.waitForTimeout(900);
  await page.screenshot({ path: out('overview') });

  await nav('Sections');
  await page.screenshot({ path: out('sections') });

  await nav('Strings');
  await page.fill('input[placeholder="Search text"]', 'fixture');
  await page.waitForTimeout(700);
  await page.click('tr:has-text("Hello from") button:has-text("Find uses")');
  await page.waitForTimeout(900);
  await page.screenshot({ path: out('strings') });

  await nav('Code');
  await page.click('.fn-list button:has-text("print")');
  await page.waitForTimeout(900);
  await page.screenshot({ path: out('code') });

  await nav('Imports');
  await page.click('tr:has-text("WriteFile") button:has-text("Find uses")');
  await page.waitForTimeout(900);
  await page.screenshot({ path: out('imports') });

  if (bundle) {
    await page.goto(`${base}/#token=${token}&open=${encodeURIComponent(bundle)}`);
    await page.reload();
    await page.waitForSelector('.titleblock');
    await page.waitForTimeout(900);
  }
  await nav('Split');
  // the list of pieces arrives after the view itself
  await page.waitForSelector('.table-wrap table', { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(300);
  await page.setViewportSize({ width: 1120, height: 1000 });   // tall enough for the whole list
  await page.waitForTimeout(300);
  await page.screenshot({ path: out('split') });
  await page.setViewportSize({ width: 1120, height: 640 });

  if (game) {
    await page.setViewportSize({ width: 1120, height: 700 });
    await page.goto(`${base}/#token=${token}&open=${encodeURIComponent(game)}`);
    await page.reload();
    await page.waitForSelector('.view-head');
    await page.waitForTimeout(900);
    const pack = page.locator('.table-wrap button.link').first();
    if (await pack.count()) { await pack.click(); await page.waitForTimeout(900); }
    const image = page.locator('tr:has-text(".png")').first();
    if (await image.count()) { await image.click(); await page.waitForTimeout(900); }
    await page.evaluate(() => {
      const heading = Array.from(document.querySelectorAll('h2')).find((h) => h.textContent.startsWith('Asset packs here'));
      if (heading) heading.scrollIntoView({ block: 'start' });
    });
    await page.mouse.move(4, 4);
    await page.waitForTimeout(300);
    await page.screenshot({ path: out('assets') });
  }
  console.log('page errors:', JSON.stringify(errors));
  await browser.close();
})();

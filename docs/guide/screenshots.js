// Captures the screenshots used in the guide from a running vex server.
// Usage: node screenshots.js BASE_URL TOKEN PRACTICE_EXE [GAME_FOLDER] [BUNDLE_EXE]
// BUNDLE_EXE is the practice program with files attached (bundle_pe64.exe), shown in the
// Split view; without it the Split view is captured on PRACTICE_EXE. Pass "" to skip GAME_FOLDER.
// The opening animation does not play under browser automation, so it never gets in the way.
const { chromium } = require('playwright');
const path = require('path');
const [, , base, token, exe, game, bundle] = process.argv;
const out = (name) => path.join(__dirname, 'img', name + '.png');

const WIDTH = 1440;          // wide enough for the three-column overview and the full row of view tabs
const HEIGHT = 900;

(async () => {
  const browser = await chromium.launch();
  // 1.5x keeps the images about as sharp as before (2160 pixels across) at a sensible file size
  const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1.5 });
  await page.emulateMedia({ colorScheme: 'dark' });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  const size = (height) => page.setViewportSize({ width: WIDTH, height });
  // park the pointer where it highlights nothing, then let the view finish drawing
  const settle = async (ms) => { await page.mouse.move(4, 4); await page.waitForTimeout(ms || 700); };
  // a view from the sidebar, by the exact name it shows there
  const view = async (id, label) => {
    await page.click(`#nav .nav-item:has(.nav-label:text-is("${label}"))`);
    await page.waitForSelector(`#main .view-${id}`);
    await settle(900);
  };
  // open a file or folder in a new tab, the way a person types its path into the Open dialog
  const open = async (target) => {
    const tabs = await page.locator('.filetab').count();
    await page.click('#tab-add');
    await page.fill('#path-input', target);
    await page.press('#path-input', 'Enter');
    await page.waitForFunction((n) => document.querySelectorAll('.filetab').length > n, tabs);
    await page.waitForSelector('#main .view');
    await settle(1200);
  };
  const scrollTop = () => page.evaluate(() => document.querySelectorAll('*').forEach((e) => { if (e.scrollTop) e.scrollTop = 0; }));

  await page.goto(`${base}/#token=${token}`);
  await page.waitForSelector('.welcome');
  await settle();
  await page.screenshot({ path: out('welcome') });

  await page.goto(`${base}/#token=${token}&open=${encodeURIComponent(exe)}`);
  await page.reload();
  await page.waitForSelector('#main .view-overview');
  await page.waitForSelector('.ov-sections table');
  await settle(1200);
  await page.screenshot({ path: out('overview') });

  await view('sections', 'Sections');
  await page.screenshot({ path: out('sections') });

  await view('entropy', 'Entropy');
  await page.waitForSelector('.view-entropy .chart-large svg');
  // point at the highest block, so the readout above the chart is filled in
  const dot = await page.evaluate(() => {
    let best = null;
    for (const d of document.querySelectorAll('.view-entropy .chart-large .chart-dot')) {
      const r = d.getBoundingClientRect();
      if (!best || r.top < best.y) best = { x: r.left + r.width / 2, y: r.top };
    }
    return best;
  });
  if (dot) await page.mouse.move(dot.x, dot.y + 40);
  await page.waitForTimeout(400);
  await page.screenshot({ path: out('entropy') });

  await view('strings', 'Strings');
  await page.fill('.view-strings input[placeholder="Search text"]', 'fixture');
  await page.waitForTimeout(700);
  await page.click('.view-strings tr:has-text("Hello from") button:has-text("Find uses")');
  await settle(900);
  await page.screenshot({ path: out('strings') });

  await view('code', 'Code (Disassembly)');
  await page.click('.fn-list button:has(.fn-name:text-is("print"))');
  await page.waitForSelector('.view-code .xref-list');
  await settle(900);
  await page.screenshot({ path: out('code') });

  await view('imports', 'Imports');
  await page.click('.view-imports tr:has-text("WriteFile") button:has-text("Find uses")');
  await settle(900);
  await page.screenshot({ path: out('imports') });

  // the decode & cipher workbench, captured on the open practice program
  await view('decode', 'Decode');
  await page.waitForSelector('.view-decode .op-chip');
  await page.click('.view-decode .seg-btn:has-text("Base64")');
  await page.fill('.view-decode textarea.decode-input', 'H4sIAAAAAAAC/8tIzcnJV0grys9VKEut4AIA4cVYqQ8AAAA=');
  await page.click('.view-decode .op-chip:has(.op-chip-name:text-is("gunzip"))');
  await page.waitForSelector('.view-decode .decode-steplist');
  await page.waitForTimeout(600);
  await size(1290);   // input, operations, recipe and output
  await scrollTop();
  await settle(400);
  await page.screenshot({ path: out('decode') });
  await size(HEIGHT);

  // the bundle opens in a second tab, next to the practice program
  if (bundle) await open(bundle);
  await view('split', 'Split');
  // the list of pieces arrives after the view itself
  await page.waitForSelector('.view-split table.pieces', { timeout: 5000 }).catch(() => {});
  await size(1010);   // tall enough for the whole list
  await scrollTop();
  await settle(400);
  await page.screenshot({ path: out('split') });
  await size(HEIGHT);

  if (game) {
    // the game folder opens in a third tab; tall enough for the packs and the opened pack with its preview
    await size(680);
    await open(game);
    await page.waitForSelector('#main .view-assets');
    const pack = page.locator('.view-assets .table-wrap button.link').first();
    if (await pack.count()) { await pack.click(); await page.waitForSelector('.view-assets .split tbody tr'); await page.waitForTimeout(600); }
    const image = page.locator('.view-assets .split tr:has-text(".png")').first();
    if (await image.count()) { await image.click(); await page.waitForSelector('.view-assets .preview img'); await page.waitForTimeout(600); }
    // scroll the list of packs to the top
    await page.evaluate(() => {
      const heading = Array.from(document.querySelectorAll('#main h2')).find((h) => h.textContent.startsWith('Asset packs here'));
      const scroller = document.getElementById('scroller');
      if (heading) scroller.scrollTop += heading.getBoundingClientRect().top - scroller.getBoundingClientRect().top - 8;
    });
    await settle(400);
    await page.screenshot({ path: out('assets') });
    await size(HEIGHT);
  }
  console.log('page errors:', JSON.stringify(errors));
  await browser.close();
})();

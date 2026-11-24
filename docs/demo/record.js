// Records the product demo video: a scripted tour of the native vex GUI.
// Usage: start `c/build/vex gui --no-browser --port 8792`, then
//   node docs/demo/record.js http://127.0.0.1:8792 TOKEN docs/demo
// and encode docs/demo/raw/*.webm to MP4 with ffmpeg (libx264, yuv420p).
const { chromium } = require('playwright');
const [, , base, token, D] = process.argv;
const R = '/home/user/eagle22221';
const W = 1280, H = 800;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const overlay = () => {
  window.addEventListener('DOMContentLoaded', () => {
    const c = document.createElement('div');
    Object.assign(c.style, { position: 'fixed', left: '-40px', top: '-40px', width: '18px', height: '18px',
      borderRadius: '50%', background: 'rgba(255,255,255,.92)', border: '2px solid #0A0B0D',
      boxShadow: '0 0 0 5px rgba(122,162,255,.35)', zIndex: 2147483647, pointerEvents: 'none',
      transform: 'translate(-50%,-50%)', transition: 'width .12s,height .12s' });
    document.body.appendChild(c);
    document.addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
    document.addEventListener('mousedown', () => { c.style.width = c.style.height = '28px'; }, true);
    document.addEventListener('mouseup', () => { c.style.width = c.style.height = '18px'; }, true);
    const cap = document.createElement('div');
    Object.assign(cap.style, { position: 'fixed', left: '50%', bottom: '30px', transform: 'translateX(-50%)',
      background: 'rgba(10,11,13,.9)', color: '#fff', font: '600 21px Barlow, sans-serif', padding: '12px 24px',
      borderRadius: '12px', border: '1px solid #3A404C', zIndex: 2147483646, pointerEvents: 'none',
      opacity: '0', transition: 'opacity .35s', maxWidth: '1060px', textAlign: 'center', letterSpacing: '.01em' });
    document.body.appendChild(cap);
    window.__caption = (t) => { cap.textContent = t || ''; cap.style.opacity = t ? '1' : '0'; };
  });
};

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: W, height: H }, colorScheme: 'dark',
    recordVideo: { dir: D + '/raw', size: { width: W, height: H } } });
  await context.addInitScript(overlay);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const caption = (t) => page.evaluate((x) => window.__caption && window.__caption(x), t);
  let mx = W / 2, my = H / 2;
  const moveTo = async (loc, dx = 0.5, dy = 0.5) => {
    const b = await loc.boundingBox();
    const x = b.x + b.width * dx, y = b.y + b.height * dy;
    await page.mouse.move(x, y, { steps: 28 }); mx = x; my = y;
  };
  const click = async (loc, dx, dy) => { await moveTo(loc, dx, dy); await sleep(180); await page.mouse.down(); await sleep(90); await page.mouse.up(); };
  const nav = (label) => page.locator(`nav button:has-text("${label}")`);
  const app = async (open) => {
    await page.goto('about:blank');
    await page.goto(`${base}/#token=${token}` + (open ? `&open=${encodeURIComponent(open)}` : ''));
    await page.mouse.move(mx, my);
  };

  // 1. title card
  await page.goto('file://' + D + '/title.html');
  await sleep(3600);

  // 2. welcome
  await app(null);
  await page.waitForSelector('.welcome');
  await sleep(400);
  await caption('One native vex.exe — double-click it and this opens in your browser');
  await moveTo(page.locator('#open-button'));
  await sleep(2600);

  // 3. overview
  await app(R + '/tests/fixtures/bin/hello_pe64.exe');
  await page.waitForSelector('.titleblock');
  await sleep(300);
  await caption('Overview: what the program is, how it is protected, what it needs');
  await moveTo(page.locator('.titleblock'), 0.3, 0.3);
  await sleep(1500);
  await moveTo(page.locator('.panel').first(), 0.5, 0.4);
  await sleep(2200);

  // 4. file map
  await caption('The whole file drawn to scale — headers, code, data, tables');
  const regions = page.locator('#map-strip .region');
  const n = await regions.count();
  for (let i = 0; i < n; i++) { await moveTo(regions.nth(i), 0.5, 0.55); await sleep(380); }
  await sleep(900);

  // 5. strings -> find uses
  await click(nav('Strings'));
  await page.waitForSelector('input[placeholder="Search text"]');
  await caption('Strings: the text inside the program — and which code uses it');
  const search = page.locator('input[placeholder="Search text"]');
  await click(search);
  await search.pressSequentially('Hello', { delay: 110 });
  await sleep(900);
  const row = page.locator('tr:has-text("Hello from")');
  await click(row.locator('button:has-text("Find uses")'));
  await sleep(1300);
  const hit = row.locator('td').last().locator('button.link').first();
  await moveTo(hit); await sleep(500);

  // 6. code
  await caption('Code: functions, calls in green — annotated with strings and Windows APIs');
  await click(hit);
  await page.waitForSelector('.insn');
  await sleep(2200);
  const call = page.locator('.insn:has-text("call") button.link').first();
  if (await call.count()) {
    await caption('Click a call to follow it into the function it runs');
    await click(call);
    await sleep(2400);
  }
  await click(page.locator('.fn-list button:has-text("print")'));
  await sleep(2400);

  // 7. imports
  await click(nav('Imports'));
  await page.waitForSelector('table');
  await caption('Imports: everything the program asks Windows to do');
  await click(page.locator('tr:has-text("WriteFile") button:has-text("Find uses")'));
  await sleep(2600);

  // 8. sections
  await click(nav('Sections'));
  await caption('Sections, permissions and entropy — packed or encrypted code stands out');
  await sleep(2800);

  // 9. assets
  await app(R + '/examples/demo_game');
  await page.waitForSelector('.view-head');
  await sleep(300);
  await caption('Games: detect the engine and find the asset packs');
  await sleep(2400);
  const pack = page.locator('.table-wrap button.link').first();
  await click(pack);
  await page.waitForSelector('tr:has-text("logo.png")');
  await caption('Browse, preview, extract or replace files — saved as a new pack');
  await page.locator('tr:has-text("logo.png")').scrollIntoViewIfNeeded();
  await click(page.locator('tr:has-text("logo.png")'));
  await sleep(1600);
  await click(page.locator('tr:has-text("config.json")'));
  await sleep(2400);

  // 10. terminal: techniques
  await page.goto('file://' + D + '/term.html');
  await page.mouse.move(-50, -50);
  await sleep(300);
  await caption('Dissect cheats and anti-cheat: flags anti-debug, VM checks, injection, hooking and packing');
  const cmd = '.\\vex.exe techniques evasion_pe64.exe';
  for (const ch of cmd) { await page.evaluate((c) => { document.getElementById('cmd').textContent += c; }, ch); await sleep(55); }
  await sleep(450);
  await page.evaluate(() => {
    const o = document.getElementById('out');
    Object.assign(o.style, { visibility: 'visible', display: 'block', maxHeight: '0px', overflow: 'hidden', transition: 'max-height 3.4s linear' });
    requestAnimationFrame(() => { o.style.maxHeight = '660px'; });
  });
  await sleep(5200);
  await caption('It identifies these techniques — it never disables or defeats them');
  await sleep(2800);

  // 11. end card
  await page.goto('file://' + D + '/end.html');
  await sleep(4200);

  await context.close();
  await browser.close();
  console.log('page errors:', JSON.stringify(errors));
})();

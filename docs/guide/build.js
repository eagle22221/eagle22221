// Renders guide.html to ../binspect-guide.pdf with headless Chromium.
// Usage: node build.js   (run screenshots.js first to refresh img/*.png)
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file://' + path.join(__dirname, 'guide.html'));
  await page.evaluate(() => document.fonts.ready);
  const missing = await page.evaluate(() =>
    Array.from(document.images).filter((i) => !i.complete || !i.naturalWidth).map((i) => i.getAttribute('src')));
  if (missing.length) console.log('missing images:', missing.join(', '));
  await page.pdf({
    path: path.join(__dirname, '..', 'binspect-guide.pdf'),
    format: 'A4',
    printBackground: true,
    preferCSSPageSize: true,
    displayHeaderFooter: true,
    headerTemplate: '<span></span>',
    footerTemplate: '<div style="width:100%;font:8pt sans-serif;color:#4A5D78;padding:0 18mm;display:flex;justify-content:space-between"><span>binspect user guide</span><span class="pageNumber"></span></div>',
    margin: { top: '18mm', bottom: '20mm', left: '18mm', right: '18mm' },
  });
  await browser.close();
  console.log('wrote docs/binspect-guide.pdf');
})();

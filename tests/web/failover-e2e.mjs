// Browser SFU failover: the page watches E2EE video through SFU 1; the driver
// kills SFU 1 once this script prints READY; the page must reconnect to SFU 2,
// re-consume, and keep decoding new frames.
//   node tests/web/failover-e2e.mjs <invite-link> [max-seconds]
import puppeteer from 'puppeteer-core';

const [link, maxSecs = '20'] = process.argv.slice(2);
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--autoplay-policy=no-user-gesture-required'] });
const page = await browser.newPage();
const logs = [];
page.on('console', (m) => logs.push(m.text()));
const decoded = () => page.evaluate(async () => {
  let best = 0;
  for (const r of window.__pc?.getReceivers?.() ?? []) {
    if (r.track.kind !== 'video') continue;
    const st = [...(await r.getStats()).values()].find((x) => x.type === 'inbound-rtp');
    best = Math.max(best, st?.framesDecoded ?? 0);
  }
  return { best, failovers: window.__failovers ?? 0 };
});
let ok = false;
try {
  await page.goto(link);
  await page.waitForFunction(() => !document.getElementById('watch').disabled, { timeout: 15000 });
  await page.click('#watch');
  await page.waitForFunction(() => document.querySelector('.stats')?.textContent.includes('fDec='), { timeout: 20000 });
  await new Promise((r) => setTimeout(r, 4000));
  const before = await decoded();
  if (before.best < 30) throw new Error(`no video before the failure: ${JSON.stringify(before)}`);
  console.log('READY', JSON.stringify(before));
  const t0 = Date.now();
  // after the kill the page's inbound stats belong to a new receiver, so poll the maximum
  let after;
  const deadline = Date.now() + Number(maxSecs) * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    after = await decoded().catch(() => undefined);
    if (after && after.failovers >= 1 && after.best >= 60) break;
  }
  if (!after || after.failovers < 1) throw new Error('page did not fail over: ' + logs.slice(-8).join(' | '));
  if (after.best < 60) throw new Error(`video did not resume after failover: ${JSON.stringify(after)}`);
  console.log(`BROWSER FAILOVER OK: recovered ${Math.round((Date.now() - t0) / 100) / 10}s after READY, ${JSON.stringify(after)}`);
  ok = true;
} catch (e) {
  console.log('FAILED', String(e).slice(0, 400));
  console.log(logs.slice(-12).join('\n'));
} finally {
  await browser.close();
}
process.exit(ok ? 0 : 2);

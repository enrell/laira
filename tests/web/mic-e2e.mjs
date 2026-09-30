// Browser mic E2EE: page A (member) turns its fake microphone on; page B
// (another member) must decrypt and decode it. Both join by invite link.
//   node tests/web/mic-e2e.mjs <inviteA> <inviteB> [seconds]
import puppeteer from 'puppeteer-core';

const [linkA, linkB, secs = '10'] = process.argv.slice(2);
const browser = await puppeteer.launch({
  executablePath: '/usr/bin/chromium', headless: true,
  args: ['--no-sandbox', '--autoplay-policy=no-user-gesture-required',
    '--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
});
async function dump(page, why) {
  const t = await page.evaluate(() => `status=${document.getElementById('status')?.textContent} watchDisabled=${document.getElementById('watch')?.disabled}\n${document.getElementById('log')?.textContent}`);
  console.log(`--- ${why}\n${t}`);
}
let pageNo = 0;
async function open(link) {
  const tag = 'ABCD'[pageNo++];
  const page = await browser.newPage();
  page.on('console', (m) => { const t = m.text(); if (/mic|sframe|join|failed|error/i.test(t)) console.log(`  [${tag}]`, t.slice(0, 160)); });
  page.on('pageerror', (e) => console.log('PAGEERROR', e));
  await page.goto(link);
  await page.waitForFunction(() => !document.getElementById('watch').disabled, { timeout: 15000 }).catch(async (e) => { await dump(page, 'watch never enabled'); throw e; });
  await page.click('#watch');
  await page.waitForFunction(() => !document.getElementById('mic').disabled, { timeout: 15000 }).catch(async (e) => { await dump(page, 'mic never enabled'); throw e; });
  return page;
}
console.log('opening A');
const A = await open(linkA);
console.log('A watching');
const B = await open(linkB);
console.log('B watching');
await A.evaluate(() => document.getElementById('mic').click());
console.log('mic clicked');
await new Promise((r) => setTimeout(r, Number(secs) * 1000));
const audio = await B.evaluate(async () => {
  const out = [];
  for (const r of window.__pc?.getReceivers?.() ?? []) {
    if (r.track.kind !== 'audio') continue;
    const st = [...(await r.getStats()).values()].find((x) => x.type === 'inbound-rtp');
    if (st?.packetsReceived) out.push({ pkts: st.packetsReceived, energy: st.totalAudioEnergy, samples: st.totalSamplesReceived });
  }
  return out;
});
console.log('B AUDIO', JSON.stringify(audio));
await browser.close();
const ok = audio.some((a) => a.energy > 0.001);
console.log(ok ? 'BROWSER MIC E2EE OK' : 'BROWSER MIC NOT DECODED');
process.exit(ok ? 0 : 2);

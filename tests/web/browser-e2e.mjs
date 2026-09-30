// Browser E2E: headless Chromium joins by invite link, opens the sealed epoch,
// consumes the native sender's SFrame-encrypted video through the SFU and must
// actually decode frames. Usage:
//   node tests/web/browser-e2e.mjs <invite-link> [seconds]
import puppeteer from 'puppeteer-core';

const link = process.argv[2];
const secs = Number(process.argv[3] || 12);
const browser = await puppeteer.launch({
  executablePath: '/usr/bin/chromium', headless: true,
  dumpio: !!process.env.CHROME_LOG, args: [...(process.env.CHROME_LOG ? ['--enable-logging=stderr', '--v=0', '--vmodule=*rtp*=2,*h264*=2,*video_receive*=2,*video_coding*=2'] : []), '--no-sandbox', '--autoplay-policy=no-user-gesture-required', '--use-fake-ui-for-media-stream'],
});
const page = await browser.newPage();
const logs = [];
page.on('console', (m) => logs.push(m.text()));
page.on('pageerror', (e) => logs.push(`PAGEERROR ${e}`));
await page.goto(link);
await page.waitForFunction(() => !document.getElementById('watch').disabled, { timeout: 15000 });
await page.click('#watch');
await new Promise((r) => setTimeout(r, secs * 1000));
const res = await page.evaluate(async () => {
  // Audio and video may come from different peers (separate boxes): look at all.
  const vids = [...document.querySelectorAll('video')];
  const v = vids.sort((a, b) => b.videoWidth - a.videoWidth)[0];
  const stats = [...document.querySelectorAll('.stats')].map((e) => e.textContent).find((t) => t) ?? '';
  const out = { hasVideo: !!v, w: v?.videoWidth ?? 0, h: v?.videoHeight ?? 0, stats, sframe: window.__sframeStats ?? null };
  return out;
});
const dbg = await page.evaluate(async () => {
  const caps = RTCRtpReceiver.getCapabilities('video')?.codecs.filter((c) => /h264/i.test(c.mimeType)).map((c) => c.sdpFmtpLine) ?? [];
  const pc = window.__pc; const c0 = [...window.__consumers][0];
  const rx = pc?.getReceivers?.() ?? [];
  const inb = [];
  for (const r of rx) {
    const st = [...(await r.getStats()).values()].find((x) => x.type === 'inbound-rtp');
    inb.push({ transform: !!r.transform, mid: r.track.id.slice(0, 6), same: r === c0?.rtpReceiver, pkts: st?.packetsReceived, frames: st?.framesReceived, dec: st?.framesDecoded, ssrc: st?.ssrc });
  }
  return { caps, inb };
});
const audio = await page.evaluate(async () => {
  const rx = (window.__pc?.getReceivers?.() ?? []).filter((r) => r.track.kind === 'audio' && r.transform);
  const out = [];
  for (const r of rx) {
    const st = [...(await r.getStats()).values()].find((x) => x.type === 'inbound-rtp');
    if (st?.packetsReceived) out.push({ pkts: st.packetsReceived, samples: st.totalSamplesReceived, energy: st.totalAudioEnergy, concealed: st.concealedSamples });
  }
  return out;
});
console.log('AUDIO', JSON.stringify(audio));
console.log('DBG', JSON.stringify(dbg));
console.log(JSON.stringify(res));
console.log(logs.filter((l) => !/^sframe (video|audio):/.test(l)).slice(-25).join('\n'));
await browser.close();
const audioOk = audio.some((a) => a.energy > 0.01);
if (!audioOk) console.error('AUDIO NOT DECODED');
process.exit(res.w > 0 && audioOk ? 0 : 2);

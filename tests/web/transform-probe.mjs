// Does this Chromium apply RTCRtpScriptTransform on a receiver? Loopback
// peer connection, transform set in ontrack (like the app does), count frames
// seen by the worker. Prints JSON.
import puppeteer from 'puppeteer-core';
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.goto('about:blank');
const res = await page.evaluate(async (early) => {
  const src = `
    let n = 0;
    onrtctransform = (e) => {
      const t = e.transformer;
      t.readable.pipeThrough(new TransformStream({ transform(f, c) { n++; if (n % 10 === 0) postMessage({ n }); c.enqueue(f); } })).pipeTo(t.writable);
    };`;
  const worker = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
  let seen = 0; worker.onmessage = (e) => { seen = e.data.n; };
  const pc1 = new RTCPeerConnection(), pc2 = new RTCPeerConnection();
  pc1.onicecandidate = (e) => e.candidate && pc2.addIceCandidate(e.candidate);
  pc2.onicecandidate = (e) => e.candidate && pc1.addIceCandidate(e.candidate);
  const canvas = document.createElement('canvas'); canvas.width = 320; canvas.height = 240;
  const ctx = canvas.getContext('2d'); setInterval(() => { ctx.fillStyle = `hsl(${Date.now() / 10 % 360},80%,50%)`; ctx.fillRect(0, 0, 320, 240); }, 30);
  const stream = canvas.captureStream(30);
  const tr = pc1.addTransceiver(stream.getVideoTracks()[0], { direction: 'sendonly' });
  const got = new Promise((r) => { pc2.ontrack = (e) => { if (!early && early !== 'late') e.receiver.transform = new RTCRtpScriptTransform(worker, {}); r(e); }; });
  const off = await pc1.createOffer(); await pc1.setLocalDescription(off); await pc2.setRemoteDescription(off);
  if (early === true) pc2.getReceivers()[0].transform = new RTCRtpScriptTransform(worker, {});
  const ans = await pc2.createAnswer(); await pc2.setLocalDescription(ans); await pc1.setRemoteDescription(ans);
  const ev = await got;
  if (early === 'late') { await new Promise((r) => setTimeout(r, 1000)); ev.receiver.transform = new RTCRtpScriptTransform(worker, {}); }
  await new Promise((r) => setTimeout(r, 3000));
  const st = [...(await pc2.getStats()).values()].find((s) => s.type === 'inbound-rtp' && s.kind === 'video');
  return { early, framesSeenByWorker: seen, framesDecoded: st?.framesDecoded };
}, process.argv[2] === 'late' ? 'late' : process.argv[2] === 'early');
console.log(JSON.stringify(res));
await browser.close();

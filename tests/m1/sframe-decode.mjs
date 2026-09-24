// Full-chain SFrame check, browser-equivalent: consume the live encrypted
// video producer on a PlainTransport, depacketize FU-A, strip the fake-SPS
// (0x67) wire prefix, decrypt via WebCrypto (same code as sframe-worker.ts),
// and write the plaintext AUs as an Annex-B stream that ffmpeg decodes.
//   node tests/m1/sframe-decode.mjs [seconds]
import WebSocket from 'ws';
import dgram from 'node:dgram';
import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

const crypto = webcrypto;
const te = new TextEncoder();
const secs = Number(process.argv[2] || 6);

const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (m, p={}) => new Promise((res, rej) => { const i=++id; pend.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p})); });
ws.on('message', d => { const m=JSON.parse(d); if(m.type==='event')return; const p=pend.get(m.id); pend.delete(m.id); m.ok?p.res(m.data):p.rej(new Error(m.error)); });
await new Promise(r => ws.on('open', r));
await req('join');

const { producers } = await req('listProducers');
const vp = producers.find(p => p.kind === 'video' && p.appData?.stream === 'screen')
        || producers.find(p => p.kind === 'video');
if (!vp) { console.error('no video producer'); process.exit(1) }

// crypto context (same HKDF as Rust + worker)
const ikm = await crypto.subtle.importKey('raw', te.encode('laira-m0-sframe!'), 'HKDF', false, ['deriveBits']);
const keyBits = await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:te.encode('SFrame 1.0'),info:te.encode('key')}, ikm, 128);
const saltBits = await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:te.encode('SFrame 1.0'),info:te.encode('salt')}, ikm, 96);
const key = await crypto.subtle.importKey('raw', keyBits, {name:'AES-GCM'}, false, ['decrypt']);
const salt = new Uint8Array(saltBits);
const nonceFor = (ctr) => { const n = new Uint8Array(salt); let c = BigInt(ctr); for (let i=11;i>=4&&c>0n;i--){n[i]^=Number(c&0xffn);c>>=8n;} return n; };

// RTP depacketizer: group by ts -> ordered NALs (FU-A reassembly)
const frames = new Map(); // ts -> {seqs: Map, order}
const recv = dgram.createSocket('udp4');
await new Promise(r => recv.bind(0, '127.0.0.1', r));
let pkts = 0;
recv.on('message', m => {
  if (m.length < 13) return;
  // skip RTCP: PT 72-76 are RTCP on muxed sockets; also RTP hdr ext unlikely here
  const pt = m[1] & 0x7f;
  if (pt >= 72 && pt <= 76) return;
  pkts++;
  const seq = m.readUInt16BE(2), ts = m.readUInt32BE(4);
  // payload offset: CSRC count + ext
  let off = 12 + (m[0] & 0x0f) * 4;
  if (m[0] & 0x10) { const extLen = m.readUInt16BE(off + 2) * 4; off += 4 + extLen; }
  const pay = m.subarray(off);
  if (!frames.has(ts)) frames.set(ts, []);
  frames.get(ts).push({ seq, pay });
});

const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: recv.address().port});
const c = await req('consumePlain', {transportId: tr.transportId, producerId: vp.producerId});
console.log(`consuming ${vp.producerId.slice(0,8)} pt=${c.rtpParameters.codecs[0].payloadType}`);
await new Promise(r => setTimeout(r, secs * 1000));
ws.close();
console.log(`rtp pkts=${pkts} frames=${frames.size}`);

// depacketize each frame's NALs in seq order
let ok = 0, dropped = 0, firstErr = '';
const annexb = [];
for (const [ts, parts] of [...frames.entries()].sort((a,b)=>a[0]-b[0])) {
  parts.sort((a,b) => ((a.seq - b.seq + 65536) % 65536) - 32768 > 0 ? 1 : -1);
  const nals = [];
  let cur = null;
  for (const { pay } of parts) {
    const t = pay[0] & 0x1f;
    if (t === 28 || t === 29) { // FU-A
      const fu = pay[1];
      if (fu & 0x80) cur = Buffer.concat([Buffer.from([(pay[0] & 0xe0) | (fu & 0x1f)]), pay.subarray(2)]);
      else if (cur) cur = Buffer.concat([cur, pay.subarray(2)]);
      if (fu & 0x40 && cur) { nals.push(cur); cur = null; }
    } else {
      nals.push(Buffer.from(pay));
    }
  }
  let data = Buffer.concat(nals); // == frame.data in the browser transform
  if (data[0] !== 0x67) { dropped++; firstErr ||= 'no 0x67 prefix: first=' + data[0]?.toString(16); continue }
  const blob = data.subarray(1);
  const cfg = blob[0], ctrLen = (cfg & 0x0f) + 1;
  let ctr = 0; for (let i = 0; i < ctrLen; i++) ctr = ctr * 256 + blob[1 + i];
  try {
    const pt = Buffer.from(await crypto.subtle.decrypt(
      { name:'AES-GCM', iv:nonceFor(ctr), additionalData:blob.subarray(0, 1+ctrLen), tagLength:128 },
      key, blob.subarray(1 + ctrLen)));
    ok++;
    annexb.push(Buffer.concat([Buffer.from([0,0,0,1]), pt]));
  } catch (e) { dropped++; firstErr ||= String(e); }
}
console.log(`decrypt ok=${ok} dropped=${dropped} ${firstErr}`);
if (!ok) process.exit(1);

writeFileSync('/tmp/sframe-decoded.h264', Buffer.concat(annexb));
// decode with ffmpeg — counts real video frames
const ff = spawn('ffmpeg', ['-hide_banner','-loglevel','error','-f','h264','-i','/tmp/sframe-decoded.h264','-f','null','-']);
ff.stderr.on('data', d => process.stderr.write(d));
ff.on('exit', code => {
  console.log(code === 0 ? 'DECODED OK — plaintext is valid H264' : `ffmpeg exit=${code}`);
  process.exit(code === 0 ? 0 : 1);
});

// Checks whether mediasoup forwards SFrame-encrypted video (fake-IDR wire
// format) to a consumer. Run `laira-desktop test-video --e2ee` first, then:
//   node tests/m1/sframe-forward.mjs
// Counts RTP packets arriving on a PlainTransport consumer for ~4s.
import WebSocket from 'ws';
import dgram from 'node:dgram';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (m, p={}) => new Promise((res, rej) => { const i=++id; pend.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p})); });
ws.on('message', d => { const m=JSON.parse(d); if(m.type==='event')return; const p=pend.get(m.id); pend.delete(m.id); m.ok?p.res(m.data):p.rej(new Error(m.error)); });
await new Promise(r => ws.on('open', r));
await req('join');

const { producers } = await req('listProducers');
const vp = producers.find(p => p.kind === 'video' && p.appData?.stream === 'test-video')
        || producers.find(p => p.kind === 'video');
if (!vp) { console.error('no video producer'); process.exit(1) }
console.log('consuming', vp.producerId);

const recv = dgram.createSocket('udp4');
await new Promise(r => recv.bind(0, '127.0.0.1', r));
const rport = recv.address().port;
let got = 0, bytes = 0, keyframes = 0;
recv.on('message', m => {
  got++; bytes += m.length;
  // consumer-side payload: first payload byte at offset 12 (no hdr exts here)
  const t = m[12] & 0x1f;
  if (t === 7 || ((t === 28 || t === 29) && (m[13] & 0x1f) === 7 && (m[13] & 0x80))) keyframes++;
});
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: rport});
const c = await req('consumePlain', {transportId: tr.transportId, producerId: vp.producerId});
console.log(`consumer pt=${c.rtpParameters.codecs[0].payloadType}`);

await new Promise(r => setTimeout(r, 4000));
console.log(`received=${got} bytes=${bytes} keyframe-marked=${keyframes}`);
console.log(got > 50 ? 'SFU FORWARDS ENCRYPTED VIDEO' : 'STILL GATED — mediasoup not forwarding');
ws.close(); process.exit(got > 50 ? 0 : 1);

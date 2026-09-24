import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (method, params={}) => new Promise((res, rej) => {
  const i = ++id; pend.set(i, {res, rej});
  ws.send(JSON.stringify({id: i, method, params}));
});
ws.on('message', d => {
  const m = JSON.parse(d);
  if (m.type === 'event') { console.log('  event:', m.event, JSON.stringify(m.data)); return; }
  const p = pend.get(m.id); pend.delete(m.id);
  m.ok ? p.res(m.data) : p.rej(new Error(m.error));
});
await new Promise(r => ws.on('open', r));
const join = await req('join');
console.log('join ok, peer', join.peerId.slice(0,8), '| router codecs:', join.rtpCapabilities.codecs.map(c=>c.mimeType).join(', '));

// native: video plain send
const ts = await req('createPlainSend');
console.log('plainSend video ->', ts.ip + ':' + ts.port);
const pv = await req('producePlain', {transportId: ts.transportId, kind: 'video',
  rtpParameters: {
    mid: '0',
    codecs: [{mimeType:'video/VP8', payloadType:101, clockRate:90000,
      rtcpFeedback:[{type:'nack'},{type:'nack',parameter:'pli'},{type:'ccm',parameter:'fir'}]}],
    encodings: [{ssrc: 424242}],
    headerExtensions: [], rtcp: {cname:'t', reducedSize:true, mux:true},
  }, appData: {stream: 'screen'}});
console.log('producePlain video ok:', pv.producerId.slice(0,8));

// native: audio plain send
const ta = await req('createPlainSend');
const pa = await req('producePlain', {transportId: ta.transportId, kind: 'audio',
  rtpParameters: {
    mid: '1',
    codecs: [{mimeType:'audio/opus', payloadType:111, clockRate:48000, channels:2}],
    encodings: [{ssrc: 424243}],
    headerExtensions: [], rtcp: {cname:'t', reducedSize:true, mux:true},
  }, appData: {stream: 'mic'}});
console.log('producePlain audio ok:', pa.producerId.slice(0,8));

// native: consume own audio back over plain recv (loopback test)
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip: '127.0.0.1', port: 45555});
const c = await req('consumePlain', {transportId: tr.transportId, producerId: pa.producerId});
console.log('consumePlain ok, pt:', c.rtpParameters.codecs[0].payloadType, 'ssrc:', c.rtpParameters.encodings[0].ssrc);

const st = await req('producerStats', {producerId: pv.producerId});
console.log('producerStats:', JSON.stringify(st.stats));
console.log('ALL SIGNALING OK');
ws.close(); process.exit(0);

import WebSocket from 'ws';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (m, p={}) => new Promise((res, rej) => { const i=++id; pend.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p})); });
ws.on('message', d => { const m=JSON.parse(d); if(m.type==='event')return; const p=pend.get(m.id); pend.delete(m.id); m.ok?p.res(m.data):p.rej(new Error(m.error)); });
await new Promise(r => ws.on('open', r));
await req('join');

const SSRC = 1234567, PT = 101;
const ts = await req('createPlainSend');
const { producerId } = await req('producePlain', {transportId: ts.transportId, kind:'video',
  rtpParameters: { mid:'0', codecs:[{mimeType:'video/H264',payloadType:PT,clockRate:90000,
    parameters:{'packetization-mode':1,'profile-level-id':'42e01f','level-asymmetry-allowed':1},
    rtcpFeedback:[{type:'nack'},{type:'nack',parameter:'pli'},{type:'ccm',parameter:'fir'}]}],
    encodings:[{ssrc:SSRC}], headerExtensions:[], rtcp:{cname:'t',reducedSize:true,mux:true} },
  appData:{stream:'screen'}});
console.log('producer', producerId.slice(0,8), '-> rtp', ts.ip+':'+ts.port);

// consumer side first so no packets are lost
const rport = 47111;
const sdp = `v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=laira\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=video ${rport} RTP/AVP 96\r\n`;
// placeholder sdp; real one after consume (mediasoup picks consumer pt)
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: rport});
const c = await req('consumePlain', {transportId: tr.transportId, producerId});
const cpt = c.rtpParameters.codecs[0].payloadType;
console.log('consumer pt', cpt, '-> udp', rport);

const sdp2 = `v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=laira\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=video ${rport} RTP/AVP ${cpt}\r\na=rtpmap:${cpt} H264/90000\r\n`;
writeFileSync('/tmp/recv.sdp', sdp2);
const dec = spawn('ffmpeg', ['-hide_banner','-loglevel','error','-protocol_whitelist','file,udp,rtp',
  '-f','sdp','-i','/tmp/recv.sdp','-frames:v','1','-y','/tmp/laira-frame.png']);
dec.stderr.on('data', d => process.stderr.write(d));

// producer: lavfi testsrc -> libx264 -> rtp to SFU
const enc = spawn('ffmpeg', ['-hide_banner','-loglevel','error','-re',
  '-f','lavfi','-i','testsrc2=size=640x360:rate=30',
  '-an','-c:v','libx264','-preset','veryfast','-tune','zerolatency','-g','60','-bf','0',
  '-pix_fmt','yuv420p','-b:v','800k',
  '-f','rtp','-payload_type',String(PT),'-ssrc',String(SSRC),`rtp://${ts.ip}:${ts.port}`]);
enc.stderr.on('data', d => process.stderr.write('[enc] '+d));

dec.on('exit', async (code) => {
  const st = await req('producerStats',{producerId});
  console.log('decoder exit', code, '| producer byteCount:', JSON.stringify(st.stats.map(s=>s.byteCount)));
  enc.kill(); ws.close();
  process.exit(code === 0 ? 0 : 1);
});
setTimeout(() => { console.log('TIMEOUT waiting for decoded frame'); dec.kill(); enc.kill(); process.exit(1); }, 15000);

// laira M0 browser client: watches producers over mediasoup-client and can
// send mic audio back. Signaling shapes must match services/sfu/server.mjs
// and crates/protocol.

import { Device } from 'mediasoup-client';
import type { Transport, Consumer, Producer } from 'mediasoup-client/lib/types';
import type { RtpCapabilities, RtpParameters } from 'mediasoup-client/lib/RtpParameters';

const statusEl = document.getElementById('status')!;
const logEl = document.getElementById('log')!;
const videosEl = document.getElementById('videos')!;
const watchBtn = document.getElementById('watch') as HTMLButtonElement;
const micBtn = document.getElementById('mic') as HTMLButtonElement;
const muteBtn = document.getElementById('mute') as HTMLButtonElement;

function log(msg: string) {
  const line = `[${new Date().toLocaleTimeString()}] ${msg}\n`;
  logEl.textContent = line + logEl.textContent;
  console.log(msg);
}

// ---- signaling ----

let reqId = 0;
const pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
const eventHandlers = new Map<string, (data: any) => void>();
let ws: WebSocket;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}`);
  ws.onopen = () => { statusEl.textContent = 'connected'; watchBtn.disabled = false; };
  ws.onclose = () => {
    statusEl.textContent = 'disconnected — retrying';
    for (const p of pending.values()) p.reject(new Error('ws closed'));
    pending.clear();
    setTimeout(connect, 2000);
  };
  ws.onerror = () => statusEl.textContent = 'ws error';
  ws.onmessage = async (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'event') {
      eventHandlers.get(msg.event)?.(msg.data);
    } else {
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);
      msg.ok ? p.resolve(msg.data) : p.reject(new Error(msg.error));
    }
  };
}

function req(method: string, params: any = {}): Promise<any> {
  const id = ++reqId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

// ---- mediasoup ----

// M1 E2EE vector: ?e2ee attaches the SFrame transform (RFC 9605 AES-GCM) to
// every receiver and to the mic sender. Key is the fixed test vector shared
// with the native client; real key management arrives with MLS in M2.
const e2ee = new URLSearchParams(location.search).has('e2ee');
let sframeWorker: Worker | undefined;
function sframeTransform(mode: 'encrypt' | 'decrypt'): any {
  if (!sframeWorker) {
    sframeWorker = new Worker(new URL('./sframe-worker.ts', import.meta.url), { type: 'module' });
    sframeWorker.onmessage = (e) => {
      if (e.data?.sframeFormat) log(e.data.sframeFormat);
      const s = e.data?.sframe;
      if (s) log(`sframe: ${s.ok} ok / ${s.dropped} dropped${s.firstErr ? ' err=' + s.firstErr : ''}`);
    };
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return new (window as any).RTCRtpScriptTransform(sframeWorker, { mode });
}

const device = new Device();
let myPeerId = '';
let recvTransport: Transport | undefined;
let sendTransport: Transport | undefined;
let micProducer: Producer | undefined;
let micStream: MediaStream | undefined;
const consumers = new Map<string, Consumer>();

interface ProducerInfo { producerId: string; kind: string; appData: any; peerId: string }

async function makeTransport(kind: 'send' | 'recv'): Promise<Transport> {
  const info = await req(kind === 'send' ? 'createSendTransport' : 'createRecvTransport');
  const t = kind === 'send'
    ? device.createSendTransport({ ...info, id: info.transportId })
    : device.createRecvTransport({ ...info, id: info.transportId });
  t.on('connect', ({ dtlsParameters }, cb, errb) => {
    req('connect', { transportId: info.transportId, dtlsParameters }).then(cb as any, errb);
  });
  return t;
}

async function consume(p: ProducerInfo) {
  if (consumers.has(p.producerId)) return;
  if (p.peerId === myPeerId) return; // never hear our own mic back
  if (!recvTransport) recvTransport = await makeTransport('recv');
  const c = await req('consume', {
    transportId: recvTransport!.id,
    producerId: p.producerId,
    rtpCapabilities: device.rtpCapabilities,
  });
  const consumer = await recvTransport!.consume({
    id: c.consumerId, producerId: c.producerId, kind: c.kind, rtpParameters: c.rtpParameters,
  });
  // M1 vector is video-only: audio still goes through ffmpeg's muxer on the
  // native side (no SFrame there yet) and the native receiver can't decrypt.
  if (e2ee && consumer.kind === 'video' && (consumer as any).rtpReceiver) {
    (consumer as any).rtpReceiver.transform = sframeTransform('decrypt');
    log(`sframe decrypt on ${p.kind}`);
  }
  consumers.set(p.producerId, consumer);
  await req('resumeConsumer', { consumerId: c.consumerId });
  attach(consumer, p);
  log(`consuming ${p.kind} producer=${p.producerId.slice(0, 8)} from peer=${p.peerId.slice(0, 8)}`);
}

interface PeerMedia {
  box: HTMLElement; video: HTMLVideoElement; audio: HTMLAudioElement; stats: HTMLElement;
  videoStream: MediaStream; audioStream: MediaStream;
}
const mediaEls = new Map<string, PeerMedia>();

function attach(consumer: Consumer, info: ProducerInfo) {
  let entry = mediaEls.get(info.peerId);
  if (!entry) {
    const box = document.createElement('div');
    box.className = 'stream';
    const label = document.createElement('div');
    label.className = 'label';
    label.textContent = `peer ${info.peerId.slice(0, 8)}`;
    const stats = document.createElement('div');
    stats.className = 'stats';
    const video = document.createElement('video');
    video.autoplay = true; video.playsInline = true; video.controls = false;
    const audio = document.createElement('audio');
    audio.autoplay = true;
    box.append(video, label, stats, audio);
    videosEl.append(box);
    entry = {
      box, video, audio, stats,
      videoStream: new MediaStream(), audioStream: new MediaStream(),
    };
    mediaEls.set(info.peerId, entry);
    video.srcObject = entry.videoStream;
    audio.srcObject = entry.audioStream;
  }
  // Video and audio go to separate elements — a <video> element would also
  // play audio tracks in its stream, doubling them with the <audio> element.
  const target = consumer.kind === 'video' ? entry.videoStream : entry.audioStream;
  target.addTrack(consumer.track);
}

function detachProducer(producerId: string) {
  const consumer = consumers.get(producerId);
  if (!consumer) return;
  consumers.delete(producerId);
  consumer.close();
  log(`producer ${producerId.slice(0, 8)} closed`);
}

async function watch() {
  const { peerId, rtpCapabilities, producers } = await req('join');
  myPeerId = peerId;
  await device.load({ routerRtpCapabilities: rtpCapabilities as RtpCapabilities });
  for (const p of producers) await consume(p);
  eventHandlers.set('newProducer', (p: ProducerInfo) => consume(p).catch(e => log(`consume failed: ${e}`)));
  eventHandlers.set('producerClosed', ({ producerId }: any) => detachProducer(producerId));
  startStats();
}

// ---- mic ----

async function toggleMic() {
  if (micProducer) {
    micStream?.getTracks().forEach(t => t.stop());
    micProducer.close(); micProducer = undefined; micStream = undefined;
    micBtn.textContent = 'Mic: off'; muteBtn.disabled = true;
    log('mic off');
    return;
  }
  try {
    micStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    });
  } catch (e) { log(`getUserMedia failed: ${e}`); return; }
  if (!sendTransport) {
    sendTransport = await makeTransport('send');
    sendTransport.on('produce', async ({ kind, rtpParameters, appData }, cb, errb) => {
      try {
        const { producerId } = await req('produce', {
          transportId: sendTransport!.id, kind, rtpParameters, appData,
        });
        cb({ id: producerId });
      } catch (e) { errb(e as Error); }
    });
  }
  const track = micStream.getAudioTracks()[0];
  micProducer = await sendTransport.produce({ track });
  // mic stays plaintext in the M1 vector — the native receiver has no SFrame
  // decrypt path yet.
  micBtn.textContent = 'Mic: on'; muteBtn.disabled = false;
  log('mic on');
}

let muted = false;
async function toggleMute() {
  if (!micProducer) return;
  muted = !muted;
  await req(muted ? 'pauseProducer' : 'resumeProducer', { producerId: micProducer.id });
  muteBtn.textContent = muted ? 'Unmute' : 'Mute';
}

// ---- stats ----

function startStats() {
  setInterval(async () => {
    for (const [producerId, consumer] of consumers) {
      if (consumer.kind !== 'video') continue;
      const stats = await consumer.getStats();
      let bitrate = 0, rtt: number | undefined, jitter: number | undefined;
      let pkts = 0, fRecv = 0, fDec = 0, fDrop = 0;
      for (const s of stats.values() as any) {
        if (s.type === 'inbound-rtp') {
          bitrate = (s.bitrate || 0) / 1000;
          pkts = s.packetsReceived || 0;
          fRecv = s.framesReceived || 0;
          fDec = s.framesDecoded || 0;
          fDrop = s.framesDropped || 0;
        }
        if (s.type === 'candidate-pair' && s.nominated) rtt = s.currentRoundTripTime;
        if (s.type === 'remote-inbound-rtp') jitter = s.jitter;
      }
      const peerBox = [...mediaEls.values()].find(e =>
        e.videoStream.getTracks().includes(consumer.track));
      const statsEl = peerBox?.stats;
      if (statsEl) {
        statsEl.textContent =
          `${bitrate.toFixed(0)} kbps rtt=${rtt ? (rtt * 1000).toFixed(0) + 'ms' : '—'} jit=${jitter ? (jitter * 1000).toFixed(0) + 'ms' : '—'}` +
          ` pkts=${pkts} fRecv=${fRecv} fDec=${fDec} fDrop=${fDrop}`;
      }
    }
  }, 2000);
}

watchBtn.onclick = async () => {
  watchBtn.disabled = true;
  try { await watch(); micBtn.disabled = false; statusEl.textContent = 'watching'; }
  catch (e) { log(`watch failed: ${e}`); watchBtn.disabled = false; }
};
micBtn.onclick = () => toggleMic().catch(e => log(`mic error: ${e}`));
muteBtn.onclick = () => toggleMute().catch(e => log(`mute error: ${e}`));

connect();

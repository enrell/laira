// laira M0 browser client: watches producers over mediasoup-client and can
// send mic audio back. Signaling shapes must match services/sfu/server.mjs
// and crates/protocol.

import { Device } from 'mediasoup-client';
import type { Transport, Consumer, Producer } from 'mediasoup-client/lib/types';
import type { RtpCapabilities } from 'mediasoup-client/lib/RtpParameters';
import { Member, EpochKeys, unhex, parseAttachment, type InviteBundle } from './laira';

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

// E2EE: every receiver gets an SFrame decrypt transform whose per-sender keys
// come from the community epoch (laira.ts). There is no fixed key any more.
let sframeWorker: Worker | undefined;
function getWorker(): Worker {
  if (!sframeWorker) {
    sframeWorker = new Worker(new URL('./sframe-worker.ts', import.meta.url), { type: 'module' });
    sframeWorker.onmessage = (e) => {
      if (e.data?.sframeFormat) log(e.data.sframeFormat);
      const s = e.data?.sframe;
      if (s) {
        log(`sframe ${s.kind}: ${s.ok} ok / ${s.dropped} dropped${s.firstErr ? ' first=' + s.firstErr : ''}${s.lastErr ? ' last=' + s.lastErr : ''}`);
        ((window as any).__sframeStats ??= {})[s.kind] = s;
      }
    };
  }
  return sframeWorker;
}
function sframeTransform(mode: 'encrypt' | 'decrypt', kind: 'video' | 'audio' = 'video'): any {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return new (window as any).RTCRtpScriptTransform(getWorker(), { mode, kind });
}
// Chromium only applies a receiver transform that is set while the remote
// description is being applied (the `track` event); assigning it after
// consume() returns is silently ignored. mediasoup-client owns its
// RTCPeerConnection, so wrap the constructor to attach the decrypt transform
// to every incoming video receiver at that moment.
(() => {
  const Native = window.RTCPeerConnection;
  if (!(window as any).RTCRtpScriptTransform) return;
  window.RTCPeerConnection = class extends Native {
    constructor(...args: ConstructorParameters<typeof RTCPeerConnection>) {
      super(...args);
      this.addEventListener('track', (ev) => {
        const kind = ev.track.kind as 'video' | 'audio';
        (ev.receiver as any).transform = sframeTransform('decrypt', kind);
        log(`sframe decrypt transform attached to ${kind} receiver`);
      });
    }
    // Outgoing mic: encrypt at the sender, set at creation (same timing rule).
    addTransceiver(...args: Parameters<RTCPeerConnection['addTransceiver']>) {
      const t = super.addTransceiver(...args);
      const kind = typeof args[0] === 'string' ? args[0] : args[0].kind;
      if (kind === 'audio') (t.sender as any).transform = sframeTransform('encrypt', 'audio');
      return t;
    }
  } as typeof RTCPeerConnection;
})();

function pushKeys(k: EpochKeys) {
  getWorker().postMessage({ type: 'keys', kid: k.kid, senders: k.senders() });
}

// ---- community membership ----

const STORE = 'laira.member.v1';
let member: Member | undefined;

function loadMember(): Member | undefined {
  try { const j = localStorage.getItem(STORE); return j ? Member.restore(JSON.parse(j)) : undefined; }
  catch { return undefined; }
}

/** Invite links look like `#c=<control url>&i=<hex of InviteBundle JSON>`. */
async function joinFromHash(): Promise<void> {
  const h = new URLSearchParams(location.hash.slice(1));
  const c = h.get('c'), i = h.get('i');
  if (!c || !i) return;
  history.replaceState(null, '', location.pathname + location.search); // don't leave the secret in the URL bar
  const invite: InviteBundle = JSON.parse(new TextDecoder().decode(unhex(i)));
  member = await Member.join(c, invite);
  try { localStorage.setItem(STORE, JSON.stringify(member.export())); } catch { /* private mode */ }
  log(`joined community ${member.communityId.slice(0, 8)} as ${member.pubHex.slice(0, 8)}`);
}

const EPOCH_POLL_MS = 3000, GRACE_MS = 15000, TOKEN_REFRESH_MS = 120000;
let removed = false;

function startEpochPoller(m: Member, first: EpochKeys) {
  let epoch = first.epoch;
  setInterval(async () => {
    if (removed) return;
    try {
      const k = await m.latestEpoch();
      if (k.epoch > epoch) {
        epoch = k.epoch; pushKeys(k);
        log(`sframe: rekeyed to epoch ${epoch}`);
        setTimeout(() => getWorker().postMessage({ type: 'forget-previous' }), GRACE_MS);
      }
    } catch (e) {
      if (String(e).includes('cannot open')) leave('removed from the community');
      else log(`epoch poll failed: ${e}`);
    }
  }, EPOCH_POLL_MS);
}

function leave(why: string) {
  removed = true;
  statusEl.textContent = why;
  log(why);
  for (const c of consumers.values()) c.close();
  consumers.clear();
  ws.close();
}

const device = new Device();
let myPeerId = '';
let recvTransport: Transport | undefined;
let sendTransport: Transport | undefined;
let micProducer: Producer | undefined;
let micStream: MediaStream | undefined;
const consumers = new Map<string, Consumer>();
(window as any).__consumers = { [Symbol.iterator]: () => consumers.values() }; // test hook

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

const consuming = new Set<string>(); // in-flight: join() and newProducer can race for the same producer

async function consume(p: ProducerInfo) {
  if (consumers.has(p.producerId) || consuming.has(p.producerId)) return;
  consuming.add(p.producerId);
  try { await consumeOnce(p); } finally { consuming.delete(p.producerId); }
}

async function consumeOnce(p: ProducerInfo) {
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
  (window as any).__pc = (recvTransport as any)._handler?._pc; // test hook
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
  if (!member) throw new Error('no membership — open an invite link first');
  const first = await member.latestEpoch();
  pushKeys(first);
  const { peerId, rtpCapabilities, producers } = await req('join', { token: await member.sessionToken() });
  const m = member;
  setInterval(() => {
    if (removed) return;
    m.sessionToken().then((token) => req('refreshToken', { token }))
      .catch((e) => { if (String(e).includes('403')) leave('session refused: removed'); else log(`token refresh failed: ${e}`); });
  }, TOKEN_REFRESH_MS);
  startEpochPoller(m, first);
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
          (window as any).__inbound = s; // test hook
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

// ---- chat ----

const chatEl = document.getElementById('chat')!;
const channelSel = document.getElementById('channel') as HTMLSelectElement;
const messagesEl = document.getElementById('messages')!;
const chatForm = document.getElementById('chatform') as HTMLFormElement;
const chatInput = document.getElementById('chatinput') as HTMLInputElement;
let chatAfter = 0, chatChannel = '';

function addMessage(m: { sender: string; text: string; ok: boolean; ts: number }) {
  const row = document.createElement('div');
  row.className = 'm' + (m.ok ? '' : ' bad');
  const who = document.createElement('span');
  who.className = 'who'; who.textContent = m.sender.slice(0, 8);
  const body = document.createElement('span');
  const att = m.ok ? parseAttachment(m.text) : undefined;
  if (att) {
    const a = document.createElement('a');
    a.className = 'file';
    a.textContent = `📎 ${att.name} (${att.size} bytes)`; // untrusted name: textContent only
    a.onclick = async () => {
      try {
        const bytes = await member!.downloadFile(att);
        const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))].map((x) => x.toString(16).padStart(2, '0')).join('');
        (window as any).__lastDownload = { name: att.name, size: bytes.length, sha256: digest }; // test hook
        const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
        const dl = document.createElement('a');
        dl.href = url; dl.download = att.name.replace(/[\\/]/g, '_'); dl.click();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      } catch (e) { log(`download failed: ${e}`); }
    };
    body.append(a);
  } else {
    body.textContent = m.text; // textContent: messages are untrusted, never HTML
  }
  row.append(who, body);
  messagesEl.append(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function refreshChannels() {
  if (!member) return;
  const list = await member.channels();
  const cur = channelSel.value;
  channelSel.replaceChildren(...list.map((c) => { const o = document.createElement('option'); o.value = c.id; o.textContent = '#' + c.name; return o; }));
  if (list.some((c) => c.id === cur)) channelSel.value = cur;
  if (channelSel.value !== chatChannel) { chatChannel = channelSel.value; chatAfter = 0; messagesEl.replaceChildren(); }
}

async function pollChat() {
  if (!member || removed || !chatChannel) return;
  try {
    for (const m of await member.readChat(chatChannel, chatAfter)) { chatAfter = Math.max(chatAfter, m.seq); addMessage(m); }
  } catch (e) { if (String(e).includes('403') || String(e).includes('401')) leave('removed from the community'); }
}

function startChat() {
  if (!member) return;
  chatEl.hidden = false;
  refreshChannels().catch((e) => log(`channels failed: ${e}`));
  setInterval(() => { refreshChannels().then(pollChat).catch(() => {}); }, 2000);
  channelSel.onchange = () => { chatChannel = channelSel.value; chatAfter = 0; messagesEl.replaceChildren(); pollChat(); };
  chatForm.onsubmit = async (ev) => {
    ev.preventDefault();
    const text = chatInput.value.trim();
    if (!text || !chatChannel) return;
    chatInput.value = '';
    try { await member!.sendChat(chatChannel, text); await pollChat(); } catch (e) { log(`send failed: ${e}`); }
  };
  (document.getElementById('fileinput') as HTMLInputElement).onchange = async (ev) => {
    const input = ev.target as HTMLInputElement;
    const f = input.files?.[0];
    input.value = '';
    if (!f || !chatChannel) return;
    try { await member!.sendFile(chatChannel, f); await pollChat(); } catch (e) { log(`file upload failed: ${e}`); }
  };
  document.getElementById('newchan')!.onclick = async () => {
    const name = prompt('Channel name');
    if (!name) return;
    try { await member!.createChannel(name); await refreshChannels(); } catch (e) { log(`create channel failed: ${e}`); }
  };
}

joinFromHash().catch((e) => log(`join failed: ${e}`)).finally(() => { member ??= loadMember(); connect(); startChat(); });

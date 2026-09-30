// Browser port of crates/identity's member side: join by invite, verify and
// open the sealed epoch bundle, derive SFrame keys, request session tokens.
// The canonical encoding and JSON shapes MUST match crates/identity/src/lib.rs
// (Canon, hexser serde); tests/web drives this against the real control
// service.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf, expand as hkdfExpand } from '@noble/hashes/hkdf.js';

const te = new TextEncoder();
export const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

function u64(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

/** Canon: u32-BE length prefix per field; first field is the domain label. */
function canon(domain: string, ...fields: Uint8Array[]): Uint8Array {
  const parts = [te.encode(domain), ...fields];
  const out = new Uint8Array(parts.reduce((s, p) => s + 4 + p.length, 0));
  const dv = new DataView(out.buffer);
  let o = 0;
  for (const p of parts) { dv.setUint32(o, p.length); out.set(p, o + 4); o += 4 + p.length; }
  return out;
}

export interface Genesis {
  admin: string; recovery: string[]; recovery_threshold: number; created_at: number; signature: string;
}
export interface AdminRecovery {
  community_id: string; previous_head: string; generation: number; new_admin: string;
  signatures: { guardian: string; signature: string }[];
}
export interface Trust { communityId: string; admin: string }

function recoveryBody(r: AdminRecovery): Uint8Array {
  return canon('laira/admin-recovery/v1', unhex(r.community_id), unhex(r.previous_head), u64(r.generation), unhex(r.new_admin));
}

/** Guardian-signed chain of admin replacements; mirrors RecoveryChain in Rust. */
export function trustFromChain(g: Genesis, recoveries: AdminRecovery[]): Trust {
  const communityId = verifyGenesis(g);
  let admin = g.admin, head = communityId, generation = 0;
  for (const r of recoveries) {
    if (r.community_id !== communityId) throw new Error('recovery for a different community');
    const body = recoveryBody(r);
    const rHead = hex(sha256(body));
    if (rHead === head) continue; // already applied
    if (r.previous_head !== head || r.generation !== generation + 1) {
      throw new Error(r.generation <= generation ? 'conflicting recoveries: chain frozen' : 'recovery out of order');
    }
    const seen = new Set<string>();
    for (const s of r.signatures) {
      if (!g.recovery.includes(s.guardian) || seen.has(s.guardian)) continue;
      if (!ed25519.verify(unhex(s.signature), body, unhex(s.guardian))) throw new Error('recovery signature invalid');
      seen.add(s.guardian);
    }
    if (seen.size < Math.max(1, g.recovery_threshold)) throw new Error('recovery has too few guardian signatures');
    admin = r.new_admin; head = rHead; generation = r.generation;
  }
  return { communityId, admin };
}

export interface EpochBundle {
  community_id: string; epoch: number;
  roster: [number, string][];
  sealed: [string, { ephemeral: string; ciphertext: string }][];
  signature: string;
}
export interface InviteBundle {
  invite: { community_id: string; invite_id: string; expires_at: number; max_uses: number; role: string; secret_commit: string; signature: string };
  secret: string;
}
export interface SessionToken { community_id: string; member: string; expires_at: number; signature: string }

function genesisBody(g: Genesis): Uint8Array {
  return canon('laira/genesis/v1', unhex(g.admin), u64(g.created_at), Uint8Array.of(g.recovery_threshold), ...g.recovery.map(unhex));
}
export function verifyGenesis(g: Genesis): string {
  const body = genesisBody(g);
  if (!ed25519.verify(unhex(g.signature), body, unhex(g.admin))) throw new Error('genesis signature invalid');
  return hex(sha256(body)); // community id
}

function epochBody(b: EpochBundle): Uint8Array {
  const f: Uint8Array[] = [];
  for (const [kid, pk] of b.roster) f.push(Uint8Array.of(kid), unhex(pk));
  for (const [pk, s] of b.sealed) f.push(unhex(pk), unhex(s.ephemeral), unhex(s.ciphertext));
  return canon('laira/epoch-bundle/v1', unhex(b.community_id), u64(b.epoch), ...f);
}

export class Member {
  readonly seed: Uint8Array;
  readonly control: string;
  readonly genesis: Genesis;
  readonly communityId: string;
  private constructor(seed: Uint8Array, control: string, genesis: Genesis, communityId: string) {
    this.seed = seed; this.control = control; this.genesis = genesis; this.communityId = communityId;
  }
  get pub(): Uint8Array { return ed25519.getPublicKey(this.seed); }
  get pubHex(): string { return hex(this.pub); }

  private static async http(url: string, init?: RequestInit) {
    const r = await fetch(url, init);
    const text = await r.text();
    if (!r.ok) throw new Error(`${r.status} ${text}`);
    return JSON.parse(text);
  }

  /** Join with an invite; verifies genesis, invite binding and epoch before returning. */
  static async join(control: string, invite: InviteBundle): Promise<Member> {
    const genesis: Genesis = await Member.http(`${control}/v1/genesis`);
    const cid = verifyGenesis(genesis);
    if (invite.invite.community_id !== cid) throw new Error('invite is for a different community');
    const seed = ed25519.utils.randomSecretKey();
    const pub = ed25519.getPublicKey(seed);
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const proof = hmac(sha256, unhex(invite.secret), canon('laira/join-proof/v1', pub, nonce));
    const body = canon('laira/join/v1', unhex(cid), unhex(invite.invite.invite_id), pub, nonce, proof);
    const req = {
      community_id: cid, invite_id: invite.invite.invite_id, member: hex(pub),
      nonce: hex(nonce), proof: hex(proof), signature: hex(ed25519.sign(body, seed)),
    };
    const reply = await Member.http(`${control}/v1/join`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req),
    });
    const m = new Member(seed, control, genesis, cid);
    await m.openEpoch(reply.epoch); // fail early if the bundle doesn't open
    return m;
  }

  static restore(json: { seed: string; control: string; genesis: Genesis }): Member {
    return new Member(unhex(json.seed), json.control, json.genesis, verifyGenesis(json.genesis));
  }
  export(): { seed: string; control: string; genesis: Genesis } {
    return { seed: hex(this.seed), control: this.control, genesis: this.genesis };
  }

  /** Verify the admin signature, unseal our copy, return the epoch keys. */
  async trust(): Promise<Trust> {
    const recs: AdminRecovery[] = await Member.http(`${this.control}/v1/recoveries`);
    return trustFromChain(this.genesis, recs);
  }

  async openEpoch(b: EpochBundle, trust?: Trust): Promise<EpochKeys> {
    const t = trust ?? await this.trust();
    if (b.community_id !== this.communityId) throw new Error('epoch for a different community');
    if (!ed25519.verify(unhex(b.signature), epochBody(b), unhex(t.admin))) throw new Error('epoch signature invalid');
    const mine = b.sealed.find(([pk]) => pk === this.pubHex);
    if (!mine) throw new Error('cannot open epoch: not in roster');
    const [, s] = mine;
    const scalar = sha512(this.seed).slice(0, 32); // == dalek to_scalar_bytes
    const shared = x25519.getSharedSecret(scalar, unhex(s.ephemeral));
    const okm = hkdf(sha256, shared, te.encode('laira/seal/v1'),
      canon('laira/seal-info/v1', unhex(s.ephemeral), this.pub), 44);
    const aad = canon('laira/epoch-seal-aad/v1', unhex(b.community_id), u64(b.epoch));
    const key = await crypto.subtle.importKey('raw', okm.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    let secret: Uint8Array;
    try {
      secret = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: okm.slice(32, 44), additionalData: aad, tagLength: 128 }, key, unhex(s.ciphertext)));
    } catch { throw new Error('cannot open epoch: unseal failed'); }
    const kid = b.roster.find(([, pk]) => pk === this.pubHex)?.[0];
    if (kid === undefined) throw new Error('cannot open epoch: no kid');
    return new EpochKeys(secret, b.epoch, kid, b.roster.map(([k]) => k));
  }

  async latestEpoch(): Promise<EpochKeys> {
    return this.openEpoch(await Member.http(`${this.control}/v1/epoch/latest`));
  }

  private async authed(path: string, init: RequestInit = {}) {
    const token = hex(te.encode(JSON.stringify(await this.sessionToken())));
    return Member.http(`${this.control}${path}`, { ...init, headers: { ...(init.headers ?? {}), 'x-laira-token': token, ...(init.body ? { 'content-type': 'application/json' } : {}) } });
  }

  private async tokenHeader(): Promise<string> {
    return hex(te.encode(JSON.stringify(await this.sessionToken())));
  }

  /** Encrypt in the browser, upload ciphertext chunks, announce in the channel. */
  async sendFile(channel: string, file: File): Promise<Attachment> {
    const { att, chunks } = await encryptFile(file.name, new Uint8Array(await file.arrayBuffer()));
    const token = await this.tokenHeader();
    for (let i = 0; i < chunks.length; i++) {
      const r = await fetch(`${this.control}/v1/blob/${att.id}/${i}`, { method: 'PUT', headers: { 'x-laira-token': token }, body: chunks[i] as BufferSource });
      if (!r.ok) throw new Error(`upload chunk ${i}: ${r.status} ${await r.text()}`);
    }
    await this.sendChat(channel, FILE_PREFIX + JSON.stringify(att));
    return att;
  }

  async downloadFile(att: Attachment): Promise<Uint8Array> {
    const token = await this.tokenHeader();
    const out = new Uint8Array(att.size);
    let off = 0;
    for (let i = 0; i < att.chunks; i++) {
      const r = await fetch(`${this.control}/v1/blob/${att.id}/${i}`, { headers: { 'x-laira-token': token } });
      if (!r.ok) throw new Error(`download chunk ${i}: ${r.status}`);
      const pt = await decryptChunk(att, i, new Uint8Array(await r.arrayBuffer()));
      out.set(pt, off); off += pt.length;
    }
    if (off !== att.size) throw new Error('size mismatch');
    return out;
  }

  /** Admin-signed SFU list (most preferred first), or [] if none is published. */
  async route(): Promise<string[]> {
    const r = await fetch(`${this.control}/v1/route`);
    if (r.status === 404) return [];
    if (!r.ok) throw new Error(`route: ${r.status}`);
    const route: { community_id: string; revision: number; sfus: string[]; issued_at: number; signature: string } = await r.json();
    const trust = await this.trust();
    const body = canon('laira/route/v1', unhex(route.community_id), u64(route.revision), u64(route.issued_at), ...route.sfus.map((u) => te.encode(u)));
    if (route.community_id !== trust.communityId || !ed25519.verify(unhex(route.signature), body, unhex(trust.admin))) throw new Error('route signature invalid');
    return route.sfus.filter((u) => /^wss?:\/\//.test(u));
  }

  async channels(): Promise<Channel[]> {
    const trust = await this.trust();
    const list: Channel[] = await this.authed('/v1/channels');
    return list.filter((c) => {
      // Only accept channels the current admin signed.
      const body = canon('laira/channel/v1', unhex(c.community_id), te.encode(c.id), te.encode(c.name), unhex(c.created_by), u64(c.created_at));
      try { return c.community_id === trust.communityId && ed25519.verify(unhex(c.signature), body, unhex(trust.admin)); } catch { return false; }
    });
  }

  async createChannel(name: string): Promise<Channel> {
    return this.authed('/v1/channels', { method: 'POST', body: JSON.stringify({ name }) });
  }

  async sendChat(channel: string, text: string): Promise<number> {
    const keys = await this.latestEpoch();
    const e: ChatEnvelope = {
      community_id: this.communityId, channel, epoch: keys.epoch, sender: this.pubHex,
      ts: Math.floor(Date.now() / 1000), nonce: hex(crypto.getRandomValues(new Uint8Array(12))), ciphertext: '', signature: '',
    };
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: unhex(e.nonce), additionalData: chatAad(e), tagLength: 128 },
      await chatKey(keys, channel, ['encrypt']), te.encode(text));
    e.ciphertext = hex(new Uint8Array(ct));
    e.signature = hex(ed25519.sign(chatBody(e), this.seed));
    return this.authed(`/v1/chat/${encodeURIComponent(channel)}`, { method: 'POST', body: JSON.stringify(e) });
  }

  private epochCache = new Map<number, EpochKeys | null>();

  async readChat(channel: string, after: number): Promise<ChatLine[]> {
    const msgs: { seq: number; envelope: ChatEnvelope }[] = await this.authed(`/v1/chat/${encodeURIComponent(channel)}?after=${after}`);
    const trust = await this.trust();
    const out: ChatLine[] = [];
    for (const { seq, envelope: e } of msgs) {
      let text = '', ok = false;
      try {
        if (!ed25519.verify(unhex(e.signature), chatBody(e), unhex(e.sender))) throw new Error('bad signature');
        if (!this.epochCache.has(e.epoch)) {
          try { this.epochCache.set(e.epoch, await this.openEpoch(await Member.http(`${this.control}/v1/epoch/${e.epoch}`), trust)); }
          catch { this.epochCache.set(e.epoch, null); }
        }
        const keys = this.epochCache.get(e.epoch);
        if (!keys) { text = `[unreadable: you were not a member during epoch ${e.epoch}]`; }
        else {
          const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(e.nonce), additionalData: chatAad(e), tagLength: 128 },
            await chatKey(keys, e.channel, ['decrypt']), unhex(e.ciphertext));
          text = new TextDecoder().decode(pt); ok = true;
        }
      } catch (err) { text = `[invalid message: ${err}]`; }
      out.push({ seq, sender: e.sender, ts: e.ts, text, ok });
    }
    return out;
  }

  async sessionToken(): Promise<SessionToken> {
    const ts = Math.floor(Date.now() / 1000);
    const body = canon('laira/token-request/v1', unhex(this.communityId), this.pub, u64(ts));
    return Member.http(`${this.control}/v1/token`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ community_id: this.communityId, member: this.pubHex, ts, signature: hex(ed25519.sign(body, this.seed)) }),
    });
  }
}

export interface Channel { community_id: string; id: string; name: string; created_by: string; created_at: number; signature: string }
export interface ChatEnvelope {
  community_id: string; channel: string; epoch: number; sender: string; ts: number;
  nonce: string; ciphertext: string; signature: string;
}
export interface ChatLine { seq: number; sender: string; ts: number; text: string; ok: boolean }

function chatAad(e: { community_id: string; channel: string; epoch: number; sender: string; ts: number }): Uint8Array {
  return canon('laira/chat-aad/v1', unhex(e.community_id), te.encode(e.channel), u64(e.epoch), unhex(e.sender), u64(e.ts));
}
function chatBody(e: ChatEnvelope): Uint8Array {
  return canon('laira/chat/v1', chatAad(e), unhex(e.nonce), unhex(e.ciphertext));
}
async function chatKey(k: EpochKeys, channel: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', k.export('chat-message-key', te.encode(channel), 32), 'AES-GCM', false, usage);
}

// ---- encrypted file attachments (mirror of Attachment in crates/identity) ----

export const FILE_PREFIX = 'laira-file:v1:';
const FILE_CHUNK = 64 * 1024;
export const FILE_MAX_SIZE = 64 * 1024 * 1024;
export interface Attachment { v: number; id: string; name: string; size: number; chunks: number; key: string }

export function parseAttachment(text: string): Attachment | undefined {
  if (!text.startsWith(FILE_PREFIX)) return undefined;
  try {
    const a = JSON.parse(text.slice(FILE_PREFIX.length)) as Attachment;
    const ok = a.v === 1 && /^[0-9a-f]{32}$/.test(a.id) && /^[0-9a-f]{64}$/.test(a.key) && a.size <= FILE_MAX_SIZE
      && a.chunks === Math.max(1, Math.ceil(a.size / FILE_CHUNK)) && typeof a.name === 'string';
    return ok ? a : undefined;
  } catch { return undefined; }
}

function chunkParams(a: Attachment, index: number) {
  const iv = new Uint8Array(12); new DataView(iv.buffer).setUint32(8, index);
  const last = index + 1 === a.chunks ? 1 : 0;
  return { name: 'AES-GCM', iv, additionalData: canon('laira/file-chunk/v1', te.encode(a.id), u64(index), Uint8Array.of(last)), tagLength: 128 };
}

export async function encryptFile(name: string, data: Uint8Array): Promise<{ att: Attachment; chunks: Uint8Array[] }> {
  if (data.length > FILE_MAX_SIZE) throw new Error('file too large (max 64 MiB)');
  const att: Attachment = {
    v: 1, id: hex(crypto.getRandomValues(new Uint8Array(16))), name: name.slice(0, 120), size: data.length,
    chunks: Math.max(1, Math.ceil(data.length / FILE_CHUNK)), key: hex(crypto.getRandomValues(new Uint8Array(32))),
  };
  const key = await crypto.subtle.importKey('raw', unhex(att.key), 'AES-GCM', false, ['encrypt']);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < att.chunks; i++) {
    chunks.push(new Uint8Array(await crypto.subtle.encrypt(chunkParams(att, i), key, data.subarray(i * FILE_CHUNK, (i + 1) * FILE_CHUNK))));
  }
  return { att, chunks };
}

export async function decryptChunk(a: Attachment, index: number, ct: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', unhex(a.key), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt(chunkParams(a, index), key, ct));
}

export class EpochKeys {
  private secret: Uint8Array;
  readonly epoch: number;
  readonly kid: number;
  readonly kids: number[];
  constructor(secret: Uint8Array, epoch: number, kid: number, kids: number[]) {
    this.secret = secret; this.epoch = epoch; this.kid = kid; this.kids = kids;
  }
  /** Same construction as EpochSecret::export in crates/identity. */
  export(label: string, ctx: Uint8Array, len: number): Uint8Array {
    return hkdfExpand(sha256, this.secret, canon('laira/export/v1', te.encode(label), u64(this.epoch), ctx), len);
  }
  /** SFrame base key for a roster slot: HKDF-Expand(PRK=secret, canon(label, epoch, ctx), 16). */
  sframeBaseKey(kid: number): Uint8Array {
    return hkdfExpand(sha256, this.secret, canon('laira/export/v1', te.encode('sframe-base-key'), u64(this.epoch), Uint8Array.of(kid)), 16);
  }
  senders(): [number, Uint8Array][] { return this.kids.map((k) => [k, this.sframeBaseKey(k)]); }
}

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
  async openEpoch(b: EpochBundle): Promise<EpochKeys> {
    if (b.community_id !== this.communityId) throw new Error('epoch for a different community');
    if (!ed25519.verify(unhex(b.signature), epochBody(b), unhex(this.genesis.admin))) throw new Error('epoch signature invalid');
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

  async sessionToken(): Promise<SessionToken> {
    const ts = Math.floor(Date.now() / 1000);
    const body = canon('laira/token-request/v1', unhex(this.communityId), this.pub, u64(ts));
    return Member.http(`${this.control}/v1/token`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ community_id: this.communityId, member: this.pubHex, ts, signature: hex(ed25519.sign(body, this.seed)) }),
    });
  }
}

export class EpochKeys {
  private secret: Uint8Array;
  readonly epoch: number;
  readonly kid: number;
  readonly kids: number[];
  constructor(secret: Uint8Array, epoch: number, kid: number, kids: number[]) {
    this.secret = secret; this.epoch = epoch; this.kid = kid; this.kids = kids;
  }
  /** SFrame base key for a roster slot: HKDF-Expand(PRK=secret, canon(label, epoch, ctx), 16). */
  sframeBaseKey(kid: number): Uint8Array {
    return hkdfExpand(sha256, this.secret, canon('laira/export/v1', te.encode('sframe-base-key'), u64(this.epoch), Uint8Array.of(kid)), 16);
  }
  senders(): [number, Uint8Array][] { return this.kids.map((k) => [k, this.sframeBaseKey(k)]); }
}

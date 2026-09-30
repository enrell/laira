// Admin recovery chain verification for the SFU (mirror of RecoveryChain in
// crates/identity and trustFromChain in apps/web/src/laira.ts). The SFU pins
// the community id (hash of the genesis) and learns the *current* admin only
// from guardian-signed recoveries — never from the control service's word.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
export const pubKey = (hexKey) =>
  createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(hexKey, 'hex')]), format: 'der', type: 'spki' });

export function canon(domain, ...fields) {
  const parts = [domain, ...fields].map((f) => (Buffer.isBuffer(f) ? f : Buffer.from(f)));
  return Buffer.concat(parts.flatMap((b) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(b.length); return [len, b];
  }));
}
export function u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
const sha256 = (b) => createHash('sha256').update(b).digest();
const hexb = (h) => Buffer.from(h, 'hex');

function genesisBody(g) {
  return canon('laira/genesis/v1', hexb(g.admin), u64(g.created_at), Buffer.from([g.recovery_threshold]), ...g.recovery.map(hexb));
}

/** Verifies the genesis signature; returns its community id (hex). */
export function verifyGenesis(g) {
  const body = genesisBody(g);
  if (!edVerify(null, body, pubKey(g.admin), hexb(g.signature))) throw new Error('genesis signature invalid');
  return sha256(body).toString('hex');
}

/** Returns { communityId, admin } after applying the recovery chain. */
export function trustFromChain(g, recoveries) {
  const communityId = verifyGenesis(g);
  let admin = g.admin, head = communityId, generation = 0;
  for (const r of recoveries) {
    if (r.community_id !== communityId) throw new Error('recovery for a different community');
    const body = canon('laira/admin-recovery/v1', hexb(r.community_id), hexb(r.previous_head), u64(r.generation), hexb(r.new_admin));
    const rHead = sha256(body).toString('hex');
    if (rHead === head) continue;
    if (r.previous_head !== head || r.generation !== generation + 1) {
      throw new Error(r.generation <= generation ? 'conflicting recoveries: chain frozen' : 'recovery out of order');
    }
    const seen = new Set();
    for (const s of r.signatures) {
      if (!g.recovery.includes(s.guardian) || seen.has(s.guardian)) continue;
      if (!edVerify(null, body, pubKey(s.guardian), hexb(s.signature))) throw new Error('recovery signature invalid');
      seen.add(s.guardian);
    }
    if (seen.size < Math.max(1, g.recovery_threshold)) throw new Error('recovery has too few guardian signatures');
    admin = r.new_admin; head = rHead; generation = r.generation;
  }
  return { communityId, admin };
}

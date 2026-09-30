# Security policy

laira is **pre-alpha research software**. It has not been audited, and it must
not be relied on to protect sensitive communication yet. Please read
[Known limitations](#known-limitations) before trusting it with anything.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

- Use GitHub's **private vulnerability reporting**: open the repository's
  **Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it (a failing test or a short script
is ideal), the commit you tested, and the impact as you understand it. You
should get an acknowledgement within a few days. This is a small project with
no bug bounty; coordinated disclosure and credit in the fix are offered.

Only the `main` branch is supported. There are no released versions yet.

## What the design tries to guarantee

- **Media confidentiality against the SFU.** Video and audio are protected
  end to end with SFrame (RFC 9605, AES-128-GCM); the SFU forwards ciphertext
  and never holds a key.
- **Membership-gated keys.** Group keys are per-epoch secrets sealed
  (X25519 + HKDF + AES-256-GCM) to each member's identity key and signed by
  the community admin. A member who is removed is excluded from the next
  epoch and cannot open it.
- **Authenticated joins.** Invites are admin-signed, single-use by default,
  expiring, and prove knowledge of a secret (HMAC). The SFU only accepts
  peers holding a short-lived admin-signed session token.
- **Signatures over canonical, domain-separated encodings**, not JSON.

Cryptography lives in `crates/identity` (Rust) with a browser port in
`apps/web/src/laira.ts`; wire-level SFrame code is in `crates/media`. Review
of those files is the most valuable kind of contribution.

## Known limitations

These are known and documented; reports about them are welcome but are not
surprises.

- **No audit and no formal protocol analysis.** The key schedule is
  hand-composed from standard primitives. It is *not* MLS: the admin acts as
  the single controller that generates and seals each epoch secret, so a
  compromised admin key or control service compromises the community. Moving
  to OpenMLS is planned.
- **Admin recovery is not implemented.** The genesis records recovery
  guardians, but nothing executes a recovery. Losing the admin key loses the
  community.
- **Revocation is not instantaneous.** A removed member keeps the old epoch
  secret they already hold (forward secrecy for *future* media only), and an
  existing SFU connection lasts until its session token expires (5 minutes).
  Native viewers stop on the next epoch poll (about 3 seconds).
- **The SFU and control service see metadata**: IP addresses, who is
  connected, packet sizes and timing, RTP headers, and roster membership.
  laira does not provide anonymity.
- **Browser E2EE trusts the code you are served.** A malicious web host can
  ship JavaScript that leaks keys. The browser stores its identity seed in
  `localStorage`; any script running on that origin can read it.
- **Partial protection on the wire.** SPS/PPS parameter sets and RTP headers
  are sent in the clear (the SFU and browser depacketizers need them).
- **No transport hardening yet.** The control API and SFU signaling are plain
  HTTP/WebSocket unless you put TLS in front. The control service's mailbox is
  unauthenticated and only bounded by size/TTL limits. Run it on localhost or
  behind TLS; do not expose the admin token.
- **The SFrame counter is 32-bit and the key ID is 3 bits**, which limits a
  domain to 8 senders and requires re-keying before 2^32 frames.
- **Test-vector fallback.** If no community profile or `LAIRA_EPOCH_SECRET` is
  configured, the desktop client falls back to a *public* test key and prints
  a warning. That mode provides no confidentiality.

## Handling secrets

Never commit or paste: `admin.json`, `admin.token`, `profile.json`, invite
links (the invite secret is in the URL fragment), or `LAIRA_EPOCH_SECRET`.
`laira-control` and `laira-desktop` create these files with mode `0600`.

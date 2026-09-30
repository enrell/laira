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
- **Admin recovery trusts the guardians.** A community created with
  `--guardian` keys can replace a lost admin with a threshold (default 2-of-3)
  of guardian signatures; members, browsers and the SFU verify the chain against
  the genesis. This is not Byzantine consensus: colluding guardians can take
  over the community, and conflicting recoveries freeze the chain until
  resolved out of band. Guardians must persist what they signed and never sign
  two recoveries extending the same head. A community created without
  guardians has **no recovery**: losing `admin.json` loses it.
- **Chat history follows epochs.** A member can read messages from the epochs
  in which they were in the roster; someone who joins later cannot read earlier
  messages (the UI says so), and a removed member keeps what they already
  fetched. Deleting or editing messages is not implemented.
- **Revocation is not instantaneous.** A removed member keeps the old epoch
  secret they already hold (forward secrecy for *future* media only), and an
  existing SFU connection lasts until its session token expires (5 minutes).
  Native viewers stop on the next epoch poll (about 3 seconds).
- **The SFU and control service see metadata**: IP addresses, who is
  connected, packet sizes and timing, RTP headers, roster membership, channel
  names, who posted in which channel and when, message sizes, and file sizes.
  Messages and files are ciphertext; the relay keeps chat for the last 10,000
  messages per channel and files for 7 days (1 GiB quota).
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
- **SFrame limits.** The key ID is 3 bits, so a domain has at most 8 members.
  Each sender uses a 64-bit counter (random 32-bit prefix per process/tab so
  a member's several senders never share a nonce space, plus a 32-bit frame
  counter) and must re-key before 2^32 frames.
- **Failover trusts the admin's route.** The SFU list is admin-signed and
  verified, but a compromised admin can point clients at a hostile SFU (which
  still only sees ciphertext and metadata). There is no automatic controller
  failover: the control service is a single point of availability.
- **Test-vector fallback.** If no community profile or `LAIRA_EPOCH_SECRET` is
  configured, the desktop client falls back to a *public* test key and prints
  a warning. That mode provides no confidentiality.

## Handling secrets

Never commit or paste: `admin.json`, `admin.token`, `profile.json`, invite
links (the invite secret is in the URL fragment), or `LAIRA_EPOCH_SECRET`.
`laira-control` and `laira-desktop` create these files with mode `0600`.

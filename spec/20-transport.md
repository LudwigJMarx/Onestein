# Transport, draft 0

Version 1, bound into every key derived here.

Carries a stream of bytes between two devices over anything that moves bytes,
and gives that stream confidentiality, integrity, authenticity and forward
secrecy. It has no handshake of its own, no timeouts, and nothing in
plaintext.

Answers R1, R3 and R4.

## 1 Origin

The construction is **Bramble Transport Protocol version 4**'s, published in
[briar-spec](https://code.briarproject.org/briar/briar-spec/-/blob/master/protocols/BTP.md)
(CC BY-SA 4.0). Time-based key rotation, pseudo-random tags, an encrypted
stream header, fixed-size frames with deterministic nonces, reordering
windows. The labels are this project's and the differences are listed in §8.

Followed rather than redesigned, deliberately. A transport that keeps forward
secrecy where one peer can only send, over latencies from milliseconds to
days, without a handshake to give it away, is the part of a messaging stack
that a fresh design gets wrong. This one is at version 4, which is three
rounds of being wrong in public.

## 2 What it is given

A **root key** of KEY_LEN bytes with full entropy, and a **timestamp T** in
the past according to both peers' clocks. Both come from `30-handshake.md`.

Nothing else. The transport does not know what an identity is, does not
negotiate, and cannot tell which peer it is talking to except by which key
works.

## 3 Modes

**Rotation mode** is the normal case: the peers delete the root key after
deriving the initial keys, and forward secrecy follows from the one-way
derivation.

**Handshake mode** protects the handshake itself, which cannot use rotation
mode because rotation mode is what the handshake produces. Its root key is
derived from the two identities' static contact keys (`40-identity.md` §2):

- handshake_root = HASH("org.onestein.transport/HANDSHAKE_ROOT",
  int_8(transport_version), DH(contact_priv_own, contact_pub_peer),
  identity_id_a, identity_id_b)

Handshake mode gives no forward secrecy and is not meant to. It carries
public keys, and its purpose is concealment: without it, the one exchange
that every contact begins with would be the one exchange a censor can
recognise on sight.

A stream secured in handshake mode MUST carry nothing but handshake records.

## 4 Time periods

Time is divided into numbered periods per transport, period zero starting at
the Unix epoch. Each period has its own keys.

A period lasts **D + L** seconds, where D is the largest expected difference
between the two clocks and L is the largest expected latency of the
transport. This guarantees that a stream begun in period P by the sender is
received in period P-1, P or P+1 by the recipient, so three periods of
incoming keys are enough.

| Transport | Identifier | D | L | Period |
|---|---|---|---|---|
| Tor, or any routed network | `org.onestein.transport.tor` | 24 h | 1 h | 25 h |
| Local network | `org.onestein.transport.lan` | 24 h | 1 h | 25 h |
| Bluetooth | `org.onestein.transport.bluetooth` | 24 h | 1 h | 25 h |
| Removable media | `org.onestein.transport.media` | 24 h | 30 d | 30 d 24 h |
| Relay | `org.onestein.transport.relay` | 24 h | 30 d | 30 d 24 h |

**These values are normative and they are the reason this table exists.**
Bramble leaves the period length to the implementation, which is safe while
there is one implementation and becomes an interoperability failure the day
there are two: peers that disagree about the period length derive different
keys, and the failure looks like a broken network rather than a mismatched
constant. A transport that is not in this table is not used until it is.

D is generous on purpose. A phone without a network has no one to ask what
time it is, and the cost of a large D is that a key lives longer, not that
anything breaks.

## 5 Key derivation

Each transport gets four keys per peer, derived from the root key. The device
whose identity_id sorts earlier is A, as in `30-handshake.md`.

A derives:

- outgoing_tag_key = KDF(root_key, "org.onestein.transport/A_TAG_KEY", transport_id)
- outgoing_header_key = KDF(root_key, "org.onestein.transport/A_HEADER_KEY", transport_id)
- incoming_tag_key = KDF(root_key, "org.onestein.transport/B_TAG_KEY", transport_id)
- incoming_header_key = KDF(root_key, "org.onestein.transport/B_HEADER_KEY", transport_id)

B derives the same four with A and B exchanged, so that each peer's outgoing
keys are the other's incoming keys.

These are the keys of the period **before** the one containing T. Rotation to
period P:

- key := KDF(key, "org.onestein.transport/ROTATE", int_64(P))

Each rotation is one-way, which is where forward secrecy comes from. After
deriving the initial keys, both peers MUST delete the root key. Outgoing keys
for period P are deleted at the end of P; incoming keys at the end of P+1.

Rotation costs one derivation per period, so a device that has been away must
catch up. An implementation MUST bound how many periods it will rotate in one
step, and the bound MUST be at least 1024, which is about three years on a
25-hour period. Beyond the bound the keys are treated as lost and the contact
is established again.

The bound is not a performance concern. The period a device rotates towards
comes from a clock, and a clock is something an adversary may be able to
move; without a bound, one wrong number turns into an unbounded loop inside
the layer that has not authenticated anything yet.

## 6 Wire

A stream is a **tag**, a **stream header**, and one or more **frames**.
Nothing is in plaintext and nothing is a fixed byte a classifier can match.

**Tag**, 16 bytes: the first 16 bytes of
PRF(outgoing_tag_key, int_16(transport_version) || int_64(stream_number)).
Streams are counted from zero within each period. The recipient precomputes
the tags it expects and recognises a stream by lookup.

**Stream header**, 82 bytes:

- nonce = R(24)
- plaintext = int_16(transport_version) || int_64(stream_number) || ephemeral_cipher_key
- header = nonce || ENC(outgoing_header_key, nonce, plaintext)

The ephemeral cipher key protects the rest of the stream. The nonce is random
so that a reused stream number cannot produce a reused nonce.

**Frames**, at most 1024 bytes encrypted including the header. The plaintext
frame header is four bytes: bit 0 marks the final frame, bits 0 to 15 are the
data length, bits 16 to 31 the padding length. Data and padding together are
at most 988 bytes. Header and body are encrypted separately under the
ephemeral cipher key with deterministic nonces: bit 0 is one for the header
and zero for the body, bits 0 to 63 are the frame number, the rest zero.

The final-frame flag exists so that the end of a stream can be recognised
without reading to EOF, which not every transport offers.

Frames are the same size regardless of content, and padding is how they stay
that way.

## 7 Reordering and replay

The recipient keeps a **reordering window** of W tags for each of the
previous, current and next periods, each tag marked seen or unseen. W MUST be
at least 32.

When a previously unseen tag is marked seen, the window slides: first until
the top half is all unseen, then until the lowest tag is unseen. A stream
whose tag the window has passed can no longer be recognised.

Two things MUST survive a restart, and they are the reason `00-overview.md`
§5.6 says this library never opens a file:

| State | If it is lost |
|---|---|
| Number of streams sent to this peer in this period | Tags repeat, and a repeated tag is the one thing on this wire that is recognisably not random |
| The reordering windows | Replayed streams are accepted |

The library hands both to the caller and takes them back. Where they are
stored, and whether they can be wiped, is the application's decision and only
the application can carry it out.

## 8 Differences from BTP 4

| Change | Why |
|---|---|
| Period lengths are normative, per transport, in §4 | BTP leaves them to the implementation. Two implementations then derive different keys and the failure looks like a broken network |
| W has a floor of 32 rather than being free | A window smaller than the sender's burst silently drops streams. The floor is the one value that cannot be chosen wrong |
| Labels carry `org.onestein` | A Bramble label in this stack could let two protocols derive one key from one input |
| The transport version is bound into the handshake's root key | `30-handshake.md` §5. In BTP the version appears in the tag and the header but not in what produced the root key |
| Handshake mode is keyed from identity contact keys | BTP leaves the establishment of its handshake-mode root key to the caller. Ours has an answer, and it is in §3 |

## 9 Open questions

| Question | Why it is open |
|---|---|
| Is 25 hours right for a routed network? | It is a choice, not a measurement. Too short and a device that sleeps for a weekend loses keys; too long and a seized device reads further back |
| What does a peer do when its window has passed a tag it later receives? | It cannot recognise the stream. Whether it should notice and say so, or stay silent, is a metadata decision this document does not make |
| Padding policy | The format allows padding; nothing here says when to use it. A protocol that can pad and never does has a format with a comment where a defence should be |
| One stream counter per transport, or per transport and peer? | §7 says per peer and period. Two transports to the same peer are two counters, and nothing checks that |

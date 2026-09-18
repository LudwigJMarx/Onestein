# Handshake, draft 0

Version 1, bound into the key it produces.

Establishes a shared root key between two **devices** whose **identities**
already know each other (`40-identity.md`). The transport layer
(`20-transport.md`) takes that root key and derives everything else from it.

Answers R4 (forward secrecy) and R5 (post-quantum confidentiality), and
carries the post-quantum authentication that `40-identity.md` §7 promises.

## 1 What it assumes

Both sides already hold the other's identity root public keys. How they came
to hold them is contact establishment, a separate document that does not
exist yet, and the caveat every protocol in this class carries applies: if an
adversary replaced the keys during that first exchange, nothing here detects
it.

Both sides can send bytes to each other, eventually. Not a connection: four
messages that may cross days and different transports. There are no timeouts
and no session. A handshake begun over Bluetooth can finish over Tor, or on a
memory card carried by hand, and neither side has to be awake when the other
speaks. That is R1, and it is why the state of a half-finished handshake is
something the caller stores rather than something a socket holds.

Roles: the device whose identity_id sorts earlier, compared as byte strings,
is **A**. The other is **B**. The roles differ only in the order of steps.

## 2 The idea

Authentication is proved by **decapsulation, not by signature**.

A signature-based handshake that resists a quantum adversary costs 3309 bytes
of ML-DSA per side, per handshake. Instead each side encapsulates to the
other's *static* ML-KEM key, which is in the device certificate the identity
root signed. Only the holder of that device's decapsulation key can recover
the secret, so deriving the right key is the proof. The approach is the one
KEMTLS takes, for the same reason.

The identity root still signs, once, in the device certificate. That
signature is ML-DSA and it is what makes the whole chain post-quantum. It is
made once per device, not once per conversation.

Four encapsulations in total:

| Encapsulation | To | Provides |
|---|---|---|
| A to B's ephemeral | fresh key | forward secrecy |
| B to A's ephemeral | fresh key | forward secrecy |
| A to B's static | certified device key | authenticates B |
| B to A's static | certified device key | authenticates A |

Both directions of each pair, so that neither the forward secrecy nor the
authentication rests on one device's random number generator alone.

Alongside, three X25519 agreements as the classical half: ephemeral to
ephemeral, ephemeral to static, static to ephemeral. Static to static is
omitted; it adds nothing that the other three do not already give.

Hybrid means both halves are always present. If ML-KEM falls, the handshake
is as strong as X25519 alone. If X25519 falls, it is as strong as ML-KEM
alone.

## 3 Records

Records are framed as `05-primitives.md` §4 defines, with the handshake
version in the version byte.

| Type | Name | Payload |
|---|---|---|
| 0 | `EPHEMERAL_KEYS` | ephemeral X25519 public key (32) and ephemeral ML-KEM encapsulation key (1184) |
| 1 | `DEVICE_CERTIFICATE` | the certificate from `40-identity.md` §4, canonical BDF with both root signatures |
| 2 | `CERTIFICATE_ID` | HASH of the certificate, sent instead of it when the sender believes the peer already holds it |
| 3 | `CERTIFICATE_REQUEST` | empty. Sent when a `CERTIFICATE_ID` names a certificate the peer does not hold |
| 4 | `ENCAPSULATIONS` | two ML-KEM ciphertexts (1088 each): to the peer's ephemeral key, then to the peer's static key |
| 5 | `CONFIRMATION` | MAC over the transcript, proving the sender derived the same root key |

## 4 Steps

1. **A sends** `EPHEMERAL_KEYS`, and `DEVICE_CERTIFICATE` or `CERTIFICATE_ID`
2. **B sends** `EPHEMERAL_KEYS`, and `DEVICE_CERTIFICATE` or `CERTIFICATE_ID`,
   and `ENCAPSULATIONS` (B can already encapsulate: it holds A's ephemeral key
   and A's static key from the certificate)
3. **A sends** `ENCAPSULATIONS` and `CONFIRMATION`
4. **B sends** `CONFIRMATION`

Two round trips, as few as mutual authentication allows.

If either side sent a `CERTIFICATE_ID` the other does not know, that side
answers `CERTIFICATE_REQUEST` and the certificate follows in the next
message. This costs one round trip and saves about 4.6 KB on every handshake
after the first. A peer that keeps no record of what its contacts hold simply
always sends the certificate and is never wrong, only larger.

Sizes, for the transports where this matters: about 7 KB in each direction
including one certificate, about 2.4 KB without. A BTP frame carries 988
bytes, so a handshake message spans frames. It does not fit in a QR code,
which is why in-person contact establishment needs its own answer and does
not get one here.

## 5 Key schedule

Every value below is public except the secrets. The order is fixed and the
framing is the one in `05-primitives.md` §2, so no field boundary can be
moved.

- root_key = HASH(
  "org.onestein.handshake/ROOT_KEY",
  int_8(handshake_version), int_8(identity_version), int_8(primitives_version),
  dh_ephemeral, dh_ephemeral_static, dh_static_ephemeral,
  kem_ephemeral_a, kem_ephemeral_b, kem_static_a, kem_static_b,
  identity_id_a, identity_id_b,
  device_signing_pub_a, device_signing_pub_b,
  dh_static_pub_a, dh_static_pub_b,
  kem_static_pub_a, kem_static_pub_b,
  dh_ephemeral_pub_a, dh_ephemeral_pub_b,
  kem_ephemeral_pub_a, kem_ephemeral_pub_b,
  ct_ephemeral_a, ct_ephemeral_b, ct_static_a, ct_static_b)

- confirmation_a = KDF(root_key, "org.onestein.handshake/CONFIRMATION_A")
- confirmation_b = KDF(root_key, "org.onestein.handshake/CONFIRMATION_B")

A peer that receives a confirmation differing from the one it expects aborts
and keeps nothing.

Three versions are inside the hash, not beside it. A peer cannot be talked
down to an older handshake, an older identity format or an older algorithm
set, because a rewritten version byte produces two different root keys and
the confirmation fails. This is the rule from `00-overview.md` §5.4, and it
exists because Bramble's own handshake does not do it: BHP 0.1 leaves its
minor version out of the master key, which is harmless while only one version
exists and stops being harmless the day a second one does.

After deriving the root key both sides delete: the ephemeral private keys,
the ephemeral decapsulation key, and every raw shared secret. What remains is
the root key, which the transport layer immediately replaces with rotated
keys of its own.

## 6 What this gives, and what it does not

| Property | Against a classical adversary | Against a quantum adversary |
|---|---|---|
| Confidentiality of the root key | yes | yes, from either half alone |
| Forward secrecy | yes | yes |
| Mutual authentication of the two devices | yes | yes, by decapsulation against certified static keys |
| Binding of each device to its identity | yes | yes, the root ML-DSA signature on the certificate |
| Protection if the first key exchange was intercepted | no | no |
| Protection if a device is seized with its keys intact | no | no |

The second to last row is the one every protocol in this class shares. The
last one is what `40-identity.md` §5 answers with revocation, imperfectly and
openly.

## 7 Open questions

| Question | Why it is open |
|---|---|
| Contact establishment | The whole document assumes the identity keys arrived. QR, link, introduction: none designed. Sizes rule out putting a raw ML-KEM key in a QR code, so it will have to carry identity keys and fetch the rest |
| Is a static ML-KEM key per device safe to reuse indefinitely? | ML-KEM is IND-CCA2 and designed for it. Reuse still means one key answers every encapsulation ever sent to that device, and an implementation flaw in decapsulation becomes a long-lived oracle |
| Does the half-finished state need an expiry? | There are no timeouts by design. A handshake that never completes leaves state on both sides, which is a small leak and a place to grow garbage |
| Certificate distribution outside the handshake | `CERTIFICATE_ID` assumes both sides can look a certificate up. Where they store it is the caller's, but the lookup key is ours |

# Contact establishment, draft 0

Version 1, bound into every derivation here.

How two identities first learn each other's root keys, which is what
`30-handshake.md` assumes has already happened.

## 1 What has to cross

The **contact bundle**, a canonical BDF dictionary:

| Key | Type | Bytes |
|---|---|---|
| `v` | integer | identity version |
| `ed` | raw | root Ed25519 public key, 32 |
| `pq` | raw | root ML-DSA-65 public key, 1952 |
| `x` | raw | contact X25519 public key, 32 |

About 2 KB, and the ML-DSA key is all of it. That single number decides the
shape of this document: a bundle does not fit in a QR code that a phone reads
across a table, so the visual channel carries a promise and the bytes come
over a second one.

## 2 Commitment

- commitment = HASH("org.onestein.contact/BUNDLE", int_8(contact_version), bundle)

32 bytes. The commitment is what travels over a channel an adversary can
watch but not alter; the bundle itself may travel anywhere.

This is Bramble's QR code protocol turned to a new purpose and credited: BQP
commits to keys over the visual channel for the same reason, that a camera
pointed at a screen is hard to get between.

## 3 In person

Each device shows a QR code and each device scans the other's. Both, not one.

The code carries version, commitment, and a transport hint: enough to open a
short-range connection, for example a Bluetooth address or a network name and
key. Around 70 bytes, which is a sparse code that scans at arm's length in
poor light, unlike the 2 KB version that does not.

Then, over the short-range transport:

1. Each side sends its bundle
2. Each side hashes the bundle it received and compares with the commitment
   it scanned. A mismatch aborts, loudly, and the pairing is not retried on
   that connection
3. Both run `30-handshake.md` in handshake mode, which is now possible
   because each holds the other's contact key

**Both sides must scan.** If only one scans, only one bundle is committed to,
and the other side has accepted keys that arrived over a channel an adversary
can rewrite. A device with no camera does not get a degraded pairing here; it
uses section 4 and the person is told which one they are doing.

## 4 At a distance

A **contact link**, meant to be pasted into whatever channel two people
already use:

```
onestein:1:<base32(contact_x25519_pub || commitment)>
```

64 bytes of payload, about 104 characters of base32, plus the prefix. The
link carries the contact key in the clear on purpose: without it there is no
shared secret, and without a shared secret two devices that have never met
cannot find each other at all (§5).

Both people send their link. Neither side is authenticated by the link
itself: whoever controls the channel the link crossed can replace it. What
the link does provide is that everything afterwards is bound to it, so an
adversary has to be present at that moment rather than at any later one.

Then each side fetches the other's bundle over the rendezvous connection and
checks it against the commitment from the link.

## 5 Rendezvous

Two devices that have exchanged links share a secret and nothing else. No
address, no name, no server to ask.

- rendezvous_key = HASH("org.onestein.contact/RENDEZVOUS",
  int_8(contact_version), DH(contact_priv_own, contact_pub_peer),
  commitment_a, commitment_b)

with the commitments in the order of the identities they belong to, A first,
as everywhere else in this stack.

For each transport and each time period P of `20-transport.md` §4:

- seed_a = KDF(rendezvous_key, "org.onestein.contact/ADDRESS_A", transport_id, int_64(P))
- seed_b = KDF(rendezvous_key, "org.onestein.contact/ADDRESS_B", transport_id, int_64(P))

Each side derives both, publishes its own address and connects to the other's.
For Tor the seed is the private key of an Ed25519 pair whose public key is the
hidden service address, as the Tor v3 specification defines. This is Bramble's
rendezvous protocol, credited.

The addresses change each period, so an address observed once does not
identify a relationship later.

Rendezvous stops once the contact has been established: from then on the
devices exchange addresses through the identity group (`50-sync.md` §4), which
is authenticated and does not need a derivation the adversary could also run
if it ever learned the contact keys.

## 6 Introduction

An existing contact can hand two of its contacts each other's bundles. The
bundles travel over channels that are already authenticated, so nothing can
be rewritten in flight.

The introducer can still lie. It can send each side a bundle of its own
making and stand in the middle of the result, and nothing in this protocol
detects that. Bramble's introduction has the same property, and so does every
introduction anywhere: an introduction is a statement by the introducer, and
it is worth what the introducer is worth.

Both introducees are shown who introduced them, and that is recorded, not
discarded after the fact.

## 7 Verification afterwards

Two people who paired at a distance can check later, over a channel they
trust more, that they hold the right keys:

- The fingerprint is the identity_id (`40-identity.md` §3), 32 bytes.
- It is shown as 24 groups of four base32 characters, or read aloud from a
  word list, which does not exist yet.

A mismatch means the first exchange was intercepted. There is no recovery
from that inside this protocol: the contact is deleted and established again
over a different channel.

## 8 What none of this prevents

| Attack | Prevented? |
|---|---|
| An adversary who watches the QR code | yes, it can read the commitment and gains nothing |
| An adversary who rewrites the short-range traffic during pairing | yes, the bundle will not match the commitment |
| An adversary who controls the channel a link crossed, at that moment | **no** |
| A lying introducer | **no** |
| An adversary who learns the contact keys later and wants past rendezvous addresses | **no**, the derivation is deterministic and the contact key does not rotate |

The last row is the price of `40-identity.md`'s contact key being derived
from the recovery seed, and it is bounded: the addresses are for finding a
peer, not for reading anything.

## 9 Open questions

| Question | Why it is open |
|---|---|
| The word list for fingerprints | A fingerprint people will not read is a fingerprint that verifies nothing. Which list, which language, is unanswered |
| Can the QR carry the whole bundle on devices that manage it? | Some cameras read a 2 KB code fine. A protocol with two pairing paths that look the same to the user and differ in security is worse than one |
| Does the transport hint leak? | A Bluetooth address in a QR code is on a screen in a public place, and it identifies the device afterwards |
| Link revocation | A link that leaks stays usable until someone connects. Nothing here expires it |

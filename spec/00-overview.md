# Onestein, draft 0

A messaging protocol stack for networks that are slow, intermittent,
censored, or absent. It carries the same messages over Tor, Bluetooth, a
local network or a memory card, needs no server to exist, and assigns no
identifier that anyone hands out.

Status: draft. Nothing in this stack has been implemented or reviewed. Where
a section says a thing is decided, it means decided and written down, not
decided and proven.

## 1 Where this comes from

Briar's Bramble stack answered the hard question well: a delay-tolerant
transport that keeps forward secrecy even where one peer can only send, with
no plaintext header for a censor to match on. Everything in section 4 that
resembles Bramble resembles it on purpose and says so.

It also has limits that no implementation removes. They are listed with
evidence in [../docs/protocol-gaps.md](../docs/protocol-gaps.md), and they
are the requirements below. Briar entered maintenance mode in 2026, so those
limits are not going to move upstream.

This stack does not interoperate with Briar. That is a cost, and it is
deliberate: three of the five limits are in the design, not in the code.

## 2 Requirements

| # | Requirement | Comes from |
|---|---|---|
| R1 | Any best-effort byte channel, including one that only carries bytes in one direction, and latency from milliseconds to days | Bramble's strength, kept |
| R2 | No infrastructure has to exist. Optional relays must never become a precondition | Bramble's strength, kept |
| R3 | No plaintext header, nothing on the wire a classifier can match | Bramble's strength, kept |
| R4 | Forward secrecy, including on send-only transports | Bramble's strength, kept |
| R5 | Post-quantum confidentiality in the first handshake | Limit: Bramble is X25519 throughout |
| R6 | One identity, several devices | Limit: identity is bound to a device |
| R7 | An identity survives the loss of a device | Limit: no backup exists |
| R8 | Delivery when the peers are not online together, without owning a second device | Limit: needs a spare Android phone |
| R9 | A group that does not require every member to store everything | Limit: BSP floods within a group |
| R10 | A contact learns as little as possible about a peer's other contacts | Limit: introductions and sharing expose the graph |

R1 to R4 are the reason this is not a new messenger on top of an existing
transport. R5 to R10 are the reason it is not another implementation of
Bramble.

## 3 Threat model

The adversary can observe, block, delay, replay and modify traffic on every
transport, can run relays, can be a contact, and can seize a device.

Assumed, and stated because the rest depends on it:

- The adversary records traffic today and may hold a quantum computer later.
  Therefore confidentiality is hybrid from the first handshake, while
  authentication stays classical until identity keys are replaced. The
  asymmetry is deliberate: retroactive decryption attacks what is being
  recorded now, impersonation needs the machine at the time.
- A relay is untrusted. It sees ciphertext, timing and volume, and it must
  not learn who talks to whom, or hold anything that identifies a user.
- A seized device gives up what it stores. What it deletes must be gone, and
  deletion is the application's job, not the library's.

Out of scope: an adversary who has replaced the keys during the first, out of
band contact exchange. That is unsolvable here and every protocol in this
class says so.

## 4 Layers

Each layer gets its own document, its own version number, and its version
bound into the keys derived below it. Nothing negotiates in the clear.

| Layer | Document | What it does | Origin |
|---|---|---|---|
| Primitives | `05-primitives.md` | Notation, the hash and key derivation construction, the algorithm list | HASH and KDF follow Bramble's framing, credited there. The algorithm list is ours |
| Encoding | `10-encoding.md` | Canonical, length-framed binary encoding | **BDF version 1**, unchanged, as published in briar-spec. It is compact, unambiguous and already implemented here. Inventing a fourth binary encoding would be novelty for its own sake |
| Transport | `20-transport.md` | Tag, stream header, frames; keys rotated per time period; reordering windows | Follows **BTP version 4**'s construction, with this project's labels and an added version binding. Credited, not copied: the design is published and it is the part a green-field attempt is most likely to get wrong |
| Handshake | `30-handshake.md` | Hybrid X25519 and ML-KEM key agreement between two identities | Our draft in `hybrid-handshake.md`, to be rewritten as the native handshake rather than an extension |
| Identity | `40-identity.md` | An identity, its devices, and recovery. New | Nothing to inherit. R6 and R7 |
| Sync | `50-sync.md` | Message graph, offers and requests, retention, and a record type for "I no longer have it" | BSP's graph model, with the flooding assumption removed and the silence we found filled. R9 |
| Relay | `60-relay.md` | Optional store-and-forward queues addressed by pairwise pseudonymous identifiers. New | R8. Closest prior art is SimpleX's queue model and Briar's Mailbox |

Layers below Handshake do not know about identities. Layers above Transport
do not know about transports. A relay sees neither.

## 5 Decisions already taken

Written here so they are arguable rather than implicit. Each is reversible
until the layer's document is finished.

1. **Namespace `org.onestein/`.** Every label in every key derivation carries
   it. A Bramble label must never appear in this stack, or two protocols can
   derive the same key from the same inputs.
2. **No new cryptographic primitives.** BLAKE2b, X25519, ML-KEM-768,
   XSalsa20/Poly1305, all from reviewed implementations.
3. **Hybrid, never replacement.** Post-quantum material is added to classical
   material. If ML-KEM fails, the handshake is as strong as X25519 alone.
4. **Every version is bound into the keys it protects.** The one finding our
   Bramble work produced: BHP 0.1 does not cover its minor version in the
   master key, so once a second version exists a rewritten version record is
   undetectable. This stack binds versions everywhere from draft 0.
5. **Relays are optional and identity-free.** A relay that has to exist is a
   server, and a server is the thing this stack is for avoiding.
6. **The library never opens a file.** State goes in and comes out. Where it
   lives, and whether it can be wiped, is the application's decision.

## 6 Not built

| Not | Why |
|---|---|
| A user interface, an app, a messenger | The stack is the work. An app is how the stack never gets finished |
| Our own anonymity network | Tor and the other transports are given, not rebuilt |
| Our own cryptographic primitives | We cannot audit them, so we must not write them |
| A directory, a discovery service, a registry | Anything that answers "who is out there" is the metadata leak the design exists to avoid |
| Interoperability with Briar | Decided against in draft 0. It is the price of R5 to R10, and it is not paid back by half measures |

## 7 What has to be true before this is worth using

Stated now, while it is cheap to be honest.

- **A single implementation proves nothing.** There is no second party to
  disagree with us. Until there is, every conformance test is a conversation
  with ourselves. The partial answers: independent implementations of the
  primitives as oracles, property tests over the wire formats, and a second
  implementation of each format in another language, written from the
  document and not from the code.
- **No review has happened.** Nothing here has been seen by a cryptographer.
  A protocol at draft 0 is a hypothesis.
- **Nobody uses it.** A messaging stack with no users has no metadata to
  hide, and no evidence that its assumptions survive contact with a network.

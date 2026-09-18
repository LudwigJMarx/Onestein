# Relay, draft 0

Version 1, bound into every derivation here.

Lets a device hand a stream to a third party that keeps it until the other
device collects it. Answers R8: delivery when the peers are never online at
the same time, without either of them owning a second device.

Optional. A stack in which a relay has to exist is a stack with a server, and
that is the thing this one is for avoiding. With no relay configured,
everything works exactly as before, when both peers are reachable at once.

## 1 A relay is a transport

It is not a new layer of trust, a new key, or a new kind of message. It is a
byte channel with very high latency and only one direction at a time, which
is precisely what `20-transport.md` is built for. A relayed stream is an
ordinary stream: same tags, same headers, same frames, same rotation.

The relay therefore sees what any transport sees, which is bytes it cannot
distinguish from random, and it has no place to hold a key even if it wanted
one.

| Transport | Identifier | D | L | Period |
|---|---|---|---|---|
| Relay | `org.onestein.transport.relay` | 24 h | 30 d | 30 d 24 h |

L is the time a blob may sit in a queue, so the period follows the expiry in
§5 and not the other way round.

## 2 Queues

A queue is one directional pipe between two devices at one relay. Two
contacts have two queues per relay, one each way.

- queue_id = KDF(root_key, "org.onestein.relay/QUEUE_A", relay_id, int_64(P))

and `QUEUE_B` for the other direction, with P the time period of §1. The root
key is the pairwise one from `30-handshake.md`; the relay never sees it and
cannot derive anything from what it does see.

Queue identifiers change every period. A relay watching one identifier
therefore watches one month of one direction of one relationship, and cannot
join it to the month before or after by the identifier alone. It can still
join them by who connects and when, which §7 is honest about.

There is no account, no registration and no name. A queue exists because
somebody wrote to it and stops existing when it expires.

## 3 Writing and reading

Knowing a queue identifier must not be enough to read it, or a relay operator
who watches a write could read the answer.

Each direction gets two signing key pairs, derived from the pairwise root key
like the queue identifier:

- write_seed = KDF(root_key, "org.onestein.relay/WRITE", relay_id, int_64(P))
- read_seed = KDF(root_key, "org.onestein.relay/READ", relay_id, int_64(P))

Each seed is the private key of an Ed25519 pair. On first use the relay is
handed the two **public** keys along with the queue identifier, and it keeps
them for as long as it keeps the queue.

To write or read, the peer asks the relay, the relay answers with a random
challenge of at least 16 bytes, and the peer signs

- proof = Ed25519(seed, "org.onestein.relay/WRITE_PROOF" || challenge)

with `READ_PROOF` for reading. The relay verifies against the public key it
stored. A challenge is good once.

**Signatures rather than shared secrets, and this is the second version of
this section.** The first had the relay store a hash of a MAC key and verify
a MAC computed under that key, which it cannot do: a hash of a key does not
verify anything made with the key. The relay would have had to hold the key
itself, and then a relay that leaked its storage would leak the ability to
write into every queue it holds and to drain them. With public keys, a leaked
store leaks the ability to check proofs and not to make them, which is what
this section claimed all along and now earns.

The asymmetry between the two pairs is what matters either way: the writer
cannot read its own queue and the reader cannot write to it.

## 4 Delivery

1. The sender opens a stream as usual and, instead of a socket, writes the
   bytes to the queue at one or more relays
2. The relay stores the blob and answers with nothing but an acknowledgement
3. The recipient polls, or holds an open connection, and collects whatever is
   there
4. The recipient acknowledges, with the read proof, and the relay deletes

Nothing about this is reliable and nothing has to be. Streams may be lost,
duplicated across relays or arrive out of order, which is what the sync layer
already handles and what `20-transport.md` reordering windows already expect.
A sender that writes to three relays is a sender using three transports.

## 4a The relay's own protocol

Everything above describes what a relay does. This is what it says, framed as
`05-primitives.md` §4 defines, with the relay version in the version byte.

A blob is named by its content: blob_id = HASH("org.onestein.relay/BLOB",
int_8(relay_version), blob). The name is what a reader deletes by, and
deriving it from the content means a relay cannot hand out a name for a blob
it does not have.

| Type | Name | Direction | Payload |
|---|---|---|---|
| 0 | `REGISTER` | to relay | queue_id (32), write_public (32), read_public (32) |
| 1 | `CHALLENGE_REQUEST` | to relay | queue_id (32), right (1: 0 write, 1 read) |
| 2 | `CHALLENGE` | from relay | challenge (32) |
| 3 | `WRITE` | to relay | queue_id (32), proof (64), blob |
| 4 | `READ` | to relay | queue_id (32), proof (64) |
| 5 | `BLOB` | from relay | blob_id (32), blob |
| 6 | `DELETE` | to relay | queue_id (32), proof (64), blob_id (32) |
| 7 | `OK` | from relay | empty |
| 8 | `EMPTY` | from relay | empty |
| 9 | `REFUSED` | from relay | reason (1) |

A challenge is good for one operation on one queue, and the relay forgets it
when it is used or when the connection ends. Reading does not delete: the
reader deletes, with a proof, once it has the bytes. A relay that deleted on
read would lose a message whose reader crashed while receiving it.

`REFUSED` carries a number and not a sentence: 0 unknown queue, 1 bad proof,
2 too large, 3 queue full, 4 unknown challenge. A relay that explained itself
in prose would be a relay whose replies differ by version and locale, which is
one more thing for a censor to match on.

## 5 Limits and expiry

Set by the relay and told to its users, not negotiated:

| Limit | Default |
|---|---|
| Blob size | 64 KiB |
| Queue size | 16 MiB |
| Blob expiry | 30 days |
| Queue expiry after last write | 60 days |

A blob past its expiry is deleted whether it was collected or not. A relay
that kept a blob to be helpful would be a relay that keeps a record of a
conversation nobody can read but everybody can subpoena.

## 6 Waking a device

A relay may be given an opaque **wake token** per queue and use it to send a
contentless push when the queue becomes non-empty.

This is the feature that makes the stack usable on a phone that the operating
system puts to sleep, and on iOS it is the only way at all. It is also the
sharpest privacy cost in this document, so it is off unless the user turns it
on, and what it costs is written next to the switch:

- The push service learns that a device received something, and when
- The relay learns that this queue belongs to a device that wants waking, and
  can join queue to token across periods even though the queue identifier
  rotated

A user who wants the second property back turns the wake token off and polls.

## 7 What the relay learns

| Sees | Does not see |
|---|---|
| Queue identifiers, sizes, times | Anything inside a blob |
| The IP address of whoever connects, unless that is Tor | Which identity either side is |
| That two queues are polled by the same connection | Which queues are the two halves of one relationship, by content |
| With wake tokens on, that a queue belongs to a wakeable device | |

The relay is assumed hostile. What it can do with what it sees: correlate
timing, count, and go on doing so for as long as its users keep the habit.
The defence against a relay is not that it behaves; it is that a relay can be
swapped, run by the user, or left out entirely.

Peers SHOULD reach a relay over Tor. A relay reached directly learns two IP
addresses and, from the pattern, that they belong together.

## 8 Running one

A relay is a small daemon with storage and no state that survives its
queues. Anyone can run one: a user, a collective, a person with a spare
server. It has no notion of who its users are, so it cannot have a user list
to lose.

That also means it cannot tell abuse from use, which is §9.

## 9 Open questions

| Question | Why it is open |
|---|---|
| Abuse | A relay with no accounts cannot say no to a stranger filling its disk. Quotas per queue bound one queue, not ten thousand queues. The ways out, invitations, payment, proof of work, all reintroduce something a relay is supposed not to have, and none is chosen here |
| Does queue rotation help as much as it looks? | Identifiers rotate monthly; the reader's polling pattern does not. A relay that watches connections may link periods without touching an identifier |
| Should the sender know its message was collected? | The relay knows. Telling the sender is a delivery receipt, which is metadata the recipient did not agree to give |
| How does a peer learn which relays the other uses? | Through the identity group, which is authenticated. Not written down anywhere yet |
| Wake tokens and multiple relays | One token per relay means several services learn of the same device. One token shared across relays means relays can recognise each other's user |

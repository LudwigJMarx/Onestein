# Sync, draft 0

Version 1, bound into every identifier and into the handshake's root key.

Synchronises immutable messages between devices that may never be online at
the same time, over any transport, in any order.

Answers R9 (a group that does not require every member to store everything)
and closes the silence recorded in `../docs/protocol-gaps.md`: what a device
says when it is asked for a message it no longer has.

## 1 Model

Data is organised into **groups**. A group is an independent scope holding a
**message graph** of immutable messages. Each message points to its
**dependencies**; the graph is acyclic because messages cannot be changed.

Each group belongs to a **client**: an application component that decides
which peers a group is shared with, what a valid message is, and what is kept
or dropped. The sync layer carries those decisions out and has no opinion
about content.

A message on a device is **shared** or **deleted**. A deleted message leaves
its identifier and its edges behind, so the graph stays whole while the body
is gone.

The model is Bramble's (BSP 0, CC BY-SA 4.0). Sections 5, 6 and 8 are where
it changes.

## 2 Identifiers

- group_id = HASH("org.onestein.sync/GROUP_ID", int_8(sync_version),
  client_id, int_32(client_major_version), group_descriptor)
- body_hash = HASH("org.onestein.sync/MESSAGE_BLOCK", int_8(sync_version), body)
- message_id = HASH("org.onestein.sync/MESSAGE_ID", int_8(sync_version),
  group_id, int_64(timestamp), author_identity_id, author_device_key, body_hash)

A group descriptor is at most 16 KiB, a body at most 32 KiB.

The client identifier is a namespaced string and its major version is inside
the group identifier, so a breaking change to a client puts it in different
groups instead of putting it in the same group speaking differently.

The body is hashed separately because a device that deletes a message keeps
its position in the graph, and that position needs the identifier without the
body.

## 3 Authorship

Every message carries its author and a signature. The author is an identity;
the signature is made by one of that identity's devices.

- to_sign = HASH("org.onestein.sync/MESSAGE_SIGNATURE", int_8(sync_version), message_id)
- signature = Ed25519 over to_sign, by the device signing key named in message_id

A verifier needs the author's device certificate to check it. Certificates
arrive two ways: in the handshake (`30-handshake.md` §3) and in the identity
group (§4).

This is a departure from Bramble, where signing is left to each client.
Uniform authorship costs about 128 bytes per message and removes a decision
that every client would otherwise make separately, and get wrong separately.
A group where a third party must verify who wrote what cannot work without
it, and a group is the case this stack exists to make work.

The signature is classical (Ed25519). What that means against a quantum
adversary is written down in `40-identity.md` §7 rather than here, because it
is a property of the identity layer and not a footnote of this one.

## 4 The identity group

One group per contact relationship is reserved: client
`org.onestein.identity`, major version 1, descriptor empty. It carries device
certificates and revocations (`40-identity.md` §4, §5) and nothing else.

It is shared automatically with every contact. It is the answer to the open
question at the end of `40-identity.md`: a new device becomes usable to a
contact as soon as this group syncs, without a handshake, without either
person doing anything.

Messages in this group are validated by the rules in `40-identity.md`, so a
certificate from a lower epoch is refused there and never reaches the graph.

## 5 Delivery, and the horizon

A message is **delivered** to its client when all its dependencies have been
delivered. On every device this produces the same order, which is what makes
causal consistency possible.

Taken literally, that rule is also what makes a group unable to outgrow its
smallest member: a new member cannot be given anything until it has been
given everything.

So each member keeps a **horizon** per group: a set of message identifiers
that are treated as delivered without ever having been received. A member
joining a group sets its horizon to the messages named by whoever invited it.
Dependencies inside the horizon are satisfied by definition.

A message delivered with any dependency satisfied by the horizon is marked
**ancestry incomplete** when it reaches the client. The client decides what
that is worth: a conversation shows the messages, a ledger refuses them. The
sync layer does not decide, it reports.

This is the answer to R9, and its cost is stated plainly: a member with a
horizon cannot verify the history before it, and must not claim to.

## 6 Retention

A group may declare a **retention policy**, which is advice to members rather
than a rule enforced against them:

| Policy | Meaning |
|---|---|
| `all` | keep everything |
| `count(n)` | keep at least the most recent n messages |
| `age(d)` | keep at least the messages of the last d days |

A member may keep more, and nothing detects a member that keeps less. A
retention policy that claimed to bind other people's devices would be a
promise about a device the promiser does not own, which `40-identity.md` §5
already refuses to make about revocation and this document refuses to make
here.

The policy is a canonical BDF value. A client that wants every member to see
the same advice puts it in the group descriptor, which is the only thing that
travels with a group; the sync layer does not look inside a descriptor (§1),
and it applies a policy only to the device's own store, when the client asks.

**Age counts from when this device received a message, not from the timestamp
in it.** A timestamp is what the author wrote. A message dated next year would
never be dropped, and one dated 1970 would be dropped on arrival, both at the
sender's choosing. The time a device received something is the one clock in
this stack that nobody else writes to.

## 7 Records

Framed as `05-primitives.md` §4 defines, with the sync version in the version
byte.

| Type | Name | Payload |
|---|---|---|
| 0 | `ACK` | one or more message identifiers the sender has seen |
| 1 | `MESSAGE` | see below |
| 2 | `OFFER` | one or more identifiers the sender holds and is sharing |
| 3 | `REQUEST` | one or more identifiers the sender wants |
| 4 | `UNAVAILABLE` | one or more identifiers the sender cannot supply |

A MESSAGE payload has a fixed layout, not an encoded dictionary. Every field
but the last has a fixed length, so there is nothing for an encoding to
describe, and the body is the only thing whose length has to be known, which
the record header already gives:

- payload = group_id (32) || int_64(timestamp) || author (32) ||
  device_key (32) || signature (64) || body

168 bytes before the body. A body is at most 32 KiB (§2), so a message record
is at most 32,936 bytes and fits the 48 KiB a record may carry.

The signature covers `to_sign` from §3, which covers the message identifier,
which covers every other field including the body. Nothing in this payload is
outside what was signed.

There is no version negotiation record. Bramble has one; here the versions
were agreed when the root key was derived (`30-handshake.md` §5), and a peer
that speaks a version this one does not know cannot have completed a
handshake with it.

`UNAVAILABLE` is the record Bramble lacks. Without it a peer that requests a
deleted message waits, retries, and receives silence, which is
indistinguishable from a slow transport: the requester keeps a pending
request forever and the holder keeps refusing to answer a question it has no
way to answer. A device sends `UNAVAILABLE` when it is asked for a message it
has deleted, has never held, or will not share.

`UNAVAILABLE` is not a promise. A device may later hold the message again,
and the requester may ask again. It closes a wait, not a door.

## 8 Per-peer state

For each message it shares with a peer, a device keeps:

| State | Meaning |
|---|---|
| `seen` | the peer is known to hold the message |
| `ack_pending` | the peer has offered or sent it since we last acknowledged, so an acknowledgement is owed |
| `requested` | the peer has asked for it since we last offered or sent it |
| `send_count` | how often it has been offered or sent to this peer |
| `next_send_time` | the earliest time it may be offered or sent again |
| `max_latency` | the latency of the transport last used for it |

`next_send_time` is named for what it is. Bramble calls the column `expiry`,
which reads like a lifetime and is a retransmission backoff; a reader who
takes it at face value builds a disappearing-message feature on a field that
has nothing to do with message lifetime.

The same trap was in this table until 18.09.2026: the ack flag was called
`acked`, which reads as "we have acknowledged it" and means the opposite, that
an acknowledgement is owed. It is `ack_pending` now. Criticising a name in
someone else's protocol and then writing the same kind of name is how a
document teaches its reader to distrust it.

Retransmission uses exponential backoff: `next_send_time` grows with
`send_count`. How fast is the implementation's business, that it grows is not.

## 9 Modes

Each time a device can send, it chooses per peer:

| Mode | Behaviour | Suits |
|---|---|---|
| Interactive | offer first, send what is requested | short round trips, scarce bandwidth |
| Batch | send without offering | long round trips, low loss |
| Eager | send without offering, resend without waiting | long round trips, high loss |

Peers need not agree, and need not use the same method to choose.

## 10 Open questions

| Question | Why it is open |
|---|---|
| Who sets a new member's horizon, and can it lie? | §5 says the inviter names it. An inviter who names a horizon that hides messages has rewritten history for the newcomer, undetectably |
| Is one identity group per contact right, or one per identity? | Per contact is simple and duplicates every certificate once per contact. Per identity needs a group every contact can share, which is a different trust question |
| Does `UNAVAILABLE` leak? | It tells a peer that a message was deleted, which tells it something about the sender's retention, and possibly about a deletion the sender would rather not announce |
| Message size against frame size | A 32 KiB body crosses 34 frames. On a transport where a stream may be cut, a large message may never complete, and nothing here notices |

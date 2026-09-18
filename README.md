# Onestein

A messaging protocol stack for networks that are slow, intermittent, censored
or absent, and its implementation in Rust.

The same message travels over Tor, Bluetooth, a local network or a memory
card. No server has to exist. Nobody hands out an identifier. An identity can
live on several devices and can be rebuilt from a seed after the last one is
gone.

Onestein is the protocol and the library. It is not a messenger, and it will
not become one.

## Build a messenger on it

That is what it is for. The library computes; the application keeps.

| Onestein does | You do |
|---|---|
| Key agreement, hybrid X25519 and ML-KEM-768 | Supply randomness, as an argument |
| Transport security: rotating keys, tags, frames with no plaintext header | Store what must survive a restart, and be able to wipe it |
| Identities, device certificates, revocation, recovery | Open sockets, files, radios |
| Contact establishment: commitments, links, rendezvous addresses | Read the clock and pass the time in |
| The message graph, signed authorship, delivery decisions | Decide what a user sees and when things are deleted |

It opens no file, no socket, and reads no clock. Not an omission: the one
thing a library cannot do for a messenger is make a secret disappear. Whoever
owns the storage owns that, so the state goes out to the caller in plain
numbers and comes back.

```toml
[dependencies]
onestein = { git = "https://github.com/LudwigJMarx/Onestein", tag = "v0.1.0" }
```

Every layer is also its own crate, and can be taken alone.

## Two devices agreeing on a key

The full example is the crate documentation of `onestein`, and it runs as a
test on every build. The shape of it:

```rust
let (ciphertext, secret) = encapsulate(&peer.kem_encapsulation_key(), &randomness)?;

let secrets = Secrets {
    dh_ephemeral: ephemeral_a.agree(&ephemeral_b.x25519_public())?,
    dh_ephemeral_static: ephemeral_a.agree(&static_b.x25519_public())?,
    dh_static_ephemeral: static_a.agree(&ephemeral_b.x25519_public())?,
    kem_ephemeral_a, kem_ephemeral_b, kem_static_a, kem_static_b,
};

let key = root_key(&secrets, &transcript);
```

Both sides reach the same `key`, one by encapsulating where the other
decapsulated. The transport layer takes it from there and neither side ever
sends a key.

## The stack

| Layer | Document | Crate |
|---|---|---|
| Primitives | [spec/05-primitives.md](spec/05-primitives.md) | `onestein-crypto` |
| Encoding | [spec/10-encoding.md](spec/10-encoding.md) | `onestein-bdf` |
| Records | [spec/05-primitives.md §4](spec/05-primitives.md) | `onestein-record` |
| Transport | [spec/20-transport.md](spec/20-transport.md) | `onestein-transport` |
| Handshake | [spec/30-handshake.md](spec/30-handshake.md) | `onestein-handshake` |
| Contact | [spec/35-contact.md](spec/35-contact.md) | `onestein-contact` |
| Identity | [spec/40-identity.md](spec/40-identity.md) | `onestein-identity` |
| Sync | [spec/50-sync.md](spec/50-sync.md) | `onestein-sync` |
| Relay | [spec/60-relay.md](spec/60-relay.md) | `onestein-relay`, `onestein-relayd` |

[spec/00-overview.md](spec/00-overview.md) has the requirements, the threat
model and the decisions the rest follows from.

## Running a relay

A relay holds ciphertext for peers that are never awake at the same time. It
is optional, it has no accounts, and it can be swapped or left out.

```bash
cargo run -p onestein-relayd -- --listen 127.0.0.1:9000
```

It binds the loopback unless told otherwise. A relay meant for other people
goes behind Tor or a proxy, which is the operator's decision and not this
program's.

## What it does not do

| Not | Why |
|---|---|
| A user interface, an app, a messenger | The stack is the work. An app is how the stack never gets finished |
| Its own anonymity network | Tor and the other transports are given, not rebuilt |
| Its own cryptographic primitives | We cannot audit them, so we must not write them |
| A directory, a search, a registry | Anything that answers "who is out there" is the metadata leak this exists to avoid |
| Interoperability with Briar | Decided against in draft 0. It is the price of post-quantum keys, multiple devices, recovery, delivery while offline, and groups that do not require everyone to store everything |

## Where it comes from

Briar's Bramble stack answered the hard question well: a delay-tolerant
transport that keeps forward secrecy even where one peer can only send, with
no plaintext header for a censor to match on. The encoding is Bramble's BDF,
unchanged. The transport follows BTP version 4's construction. The rendezvous
and the pairing commitment follow BRP and BQP. Every one of those is credited
in the document that uses it.

What is not inherited are five limits that sit in that design rather than in
its code, listed with evidence in
[docs/protocol-gaps.md](docs/protocol-gaps.md). Briar entered maintenance mode
in 2026, so they were not going to move upstream.

Not affiliated with the Briar Project.

## State

Draft 0. Tagged v0.1.0 and published as a **prerelease**, which is what it
is: nothing here is stable and nothing has been reviewed. GitHub therefore
reports no latest release, deliberately.

Every layer has a document and an implementation. The version is the crates',
not the protocol's: every layer in the specification is still at version 1 and
every document is still a draft.

```
229 tests, clippy clean, 64 third-party packages named
```

Three things are true and are not going to be hidden further down:

- **No second implementation.** Every conformance test here is a conversation
  with ourselves. The partial answers are foreign oracles for the primitives
  (CPython's `hashlib`, RFC 4648's vectors), property tests over the formats,
  and a generator in another language written from the documents.
- **No review.** Nothing here has been seen by a cryptographer. A protocol at
  draft 0 is a hypothesis.
- **No users.** A messaging stack with nobody on it has no metadata to hide
  and no evidence that its assumptions survive a network.

## Build

```bash
cargo test --workspace --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
python3 scripts/pruefer-verdrahtet.py   # is every checker actually called?
python3 scripts/pruefe-verweise.py      # do the documents' references resolve?
python3 scripts/pruefe-notices.py       # are the third-party notices current?
```

How this repository is written, and why the document comes before the code:
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache-2.0 OR MIT, at your option, for the code. The documents under `spec/`
are CC BY-SA 4.0, to match the specifications they cite.

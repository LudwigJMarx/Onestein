# Onestein

A messaging protocol stack for networks that are slow, intermittent, censored
or absent, and a Rust implementation of it.

It carries the same messages over Tor, Bluetooth, a local network or a memory
card. It needs no server to exist. It assigns no identifier that anyone hands
out. An identity can live on more than one device and can survive the loss of
one.

Briar's Bramble stack answered the transport question well, and this stack
keeps that answer and credits it. It does not keep the limits that sit in
Bramble's design rather than in its code: no post-quantum key agreement, one
device per identity, no delivery while a peer is offline, and groups that
require every member to store everything. Those four are the reason this is
its own protocol and not another implementation of Bramble.

It does not interoperate with Briar.

## State

Draft 0. Every layer has a document and none has been reviewed by anyone. The
implementation covers the encoding, the identifiers, the transport layer and
the handshake's cryptography. The handshake's records are framed and parsed, and
devices can be certified and verified. Contact establishment, sync, the relay
and revocation are written down and not built.

| Document | Layer | State |
|---|---|---|
| [spec/00-overview.md](spec/00-overview.md) | requirements, threat model, layering, decisions | written |
| [spec/05-primitives.md](spec/05-primitives.md) | notation, hash and key derivation, algorithms | written |
| [spec/10-encoding.md](spec/10-encoding.md) | canonical binary encoding | written. BDF version 1 unchanged, plus three rules BDF leaves open |
| [spec/20-transport.md](spec/20-transport.md) | tags, stream headers, frames, key rotation | written |
| [spec/30-handshake.md](spec/30-handshake.md) | hybrid key agreement, authentication by decapsulation | written |
| [spec/35-contact.md](spec/35-contact.md) | how two identities first meet | written |
| [spec/40-identity.md](spec/40-identity.md) | identity, devices, recovery | written |
| [spec/50-sync.md](spec/50-sync.md) | message graph, offers, requests, retention | written |
| [spec/60-relay.md](spec/60-relay.md) | optional store-and-forward | written |

| Crate | Layer | State |
|---|---|---|
| `onestein-bdf` | encoding | reader, writer, strict mode for anything that gets hashed. 35 tests |
| `onestein-crypto` | hash, PRF and key derivation over BLAKE2b | 9 tests, checked against CPython's `hashlib` |
| `onestein-identity` | identity identifiers, device certificates signed twice | 12 tests |
| `onestein-sync` | group and message identifiers | 10 tests |
| `onestein-transport` | the whole transport layer: periods, rotation, tags, headers, frames, reordering windows | 39 tests |
| `onestein-record` | the record framing both layers share | 9 tests |
| `onestein-handshake` | hybrid X25519 and ML-KEM-768 key agreement, key schedule, confirmations, records | 16 tests |

130 tests, all derived from a written specification, none of them involving a
second implementation. They show that the code does what the documents say,
which is not the same as the documents being right.

Working rules for anyone touching this: [CONTRIBUTING.md](CONTRIBUTING.md).

## How this is written

**The document comes before the code.** Where an implementation question has
no answer in the specification, the specification gets the answer first. A
constant that only exists in a source file is a decision nobody made.

**Briar's Java source is not read.** It is GPL-3.0 and this project is
Apache-2.0 OR MIT. The Bramble *specifications* are CC BY-SA 4.0, public, and
cited wherever this stack follows them.

## Build

```bash
cargo test --workspace --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
python3 scripts/pruefer-verdrahtet.py
python3 scripts/pruefe-verweise.py
python3 scripts/pruefe-notices.py
```

## Licence

Apache-2.0 OR MIT, at your option, for the code. The documents under `spec/`
are CC BY-SA 4.0, to match the specifications they cite.

Not affiliated with the Briar Project.

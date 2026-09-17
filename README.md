# Onestein

A second implementation of the Bramble protocol stack, in Rust, written from
the specification.

Bramble is the protocol family under [Briar](https://briarproject.org): a
messaging stack that carries the same messages over Tor, Bluetooth, local
Wi-Fi or a memory card, with no server anywhere. One implementation of it
exists, in Java, on Android. A specification with one implementation is a
description of that implementation; the second one is what turns it into a
specification, and it is also what makes the stack reachable from platforms
the first one cannot run on.

## State

Early. One crate, no release.

| Crate | Layer | State |
|---|---|---|
| `onestein-bdf` | Binary Data Format, version 1 | reader, writer, canonical form. 28 spec-derived tests. No vectors from the Java implementation yet |

Planned, bottom up: the hash constructions (group and message identifiers,
BLAKE2b), then BTP (key rotation, frames without a plaintext header), then BSP
(records and sync sessions). The measure of each layer is not that its tests
pass but that it agrees with Briar on the wire.

## How this is written

**The specification is the source, not the other implementation.** Briar's
Java code is GPL-3.0; this crate is Apache-2.0 OR MIT, so the source is not
read. Where the specification is silent, the gap is marked as an open question
in the code rather than filled in by guessing. Test vectors produced by
running the Java implementation are a different matter and are welcome.

Specification: <https://code.briarproject.org/briar/briar-spec>, CC BY-SA 4.0.

## Build

```bash
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
python3 scripts/pruefer-verdrahtet.py
```

## Licence

Apache-2.0 OR MIT, at your option. See `LICENSE-APACHE` and `LICENSE-MIT`.

Not affiliated with the Briar Project.

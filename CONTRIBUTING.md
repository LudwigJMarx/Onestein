# Contributing

This repository holds a protocol specification and its implementation. The
specification is in `spec/`, the code is in `crates/`, and the order between
them is the first rule below.

## The document decides, not the code

Where an implementation question has no answer in `spec/`, the specification
gets the answer first, with its reason, and the code follows. A constant that
exists only in a source file is a decision nobody made and nobody can argue
with.

This is not bureaucracy. Two of the rules currently in the specification, the
bound on key rotation and the strict reading mode for canonical encodings,
exist because writing them down forced the question of what an adversary
would do with the alternative.

## Every test quotes the sentence it holds to

Tests in `crates/*/tests/spec_vectors.rs` carry the sentence of the
specification they test, as a comment above the test. A test without one is
an opinion about the format.

Expected values come from `scripts/vektoren.py`, which computes them with
CPython's `hashlib`. That is a second implementation of the primitives, not of
this protocol: when Rust and CPython disagree the fault is ours, and when they
agree it says nothing about whether the specification is right.

## There is no second implementation

Nobody else speaks this protocol yet. Every conformance test is therefore a
conversation with ourselves, and the substitutes for a real counterparty are
named rather than assumed:

1. foreign oracles for the primitives, as above
2. property tests over the formats: round trip, refusal, framing
3. a second implementation of each format in another language, written from
   the document and not from the code

Where a test has none of the three, it says so.

## No new cryptographic primitives

BLAKE2b, X25519, ML-KEM, ML-DSA, XSalsa20/Poly1305 come from reviewed
libraries and are pinned in `Cargo.lock`. A primitive written here would need
an audit this project cannot pay for, and a subtly wrong one produces output
that looks exactly right.

## Checkers say what they looked at

Every checker in `scripts/` prints its scope: how many things it examined and
how many findings it had. An empty result and a failed run must never look
alike. `scripts/pruefer-verdrahtet.py` checks that every checker is actually
called by the workflow, because a checker nobody runs is a file.

## Commits

`type(area): subject`, under 72 characters, lower case. The body carries the
evidence: what was claimed, what the evidence supports, why this way, and
which obvious alternative does not work. Not a list of changed files; that is
the diff.

Commits name their human authors and nobody else.

## Before opening anything

```bash
cargo test --workspace --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
python3 scripts/pruefer-verdrahtet.py
python3 scripts/pruefe-verweise.py
```

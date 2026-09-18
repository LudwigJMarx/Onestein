# Encoding, draft 0

Version 1. Bound into every key derivation that covers encoded data.

## 1 The format

The encoding is **BDF version 1**, as published in
[briar-spec](https://code.briarproject.org/briar/briar-spec/-/blob/master/BDF.md)
(CC BY-SA 4.0), without modification. Six primitive types, two container
types, a type in the first four bits of every object.

Adopted rather than replaced. It is compact, self-delimiting, and already
implemented here with 28 conformance tests. A fourth binary encoding in the
world would be novelty at the cost of a year.

Considered and rejected: deterministic CBOR (RFC 8949 §4.2). It is
standardised and has tooling, which is a real advantage, and its determinism
rules are a known source of disagreement between implementations. BDF's
canonical rules fit on one line. Where this stack needs an encoding to be
exactly reproducible, that matters more than tooling.

## 2 What BDF leaves open, and what we decide

BDF is a format, not a parser. Three questions it does not answer are
answered here, normatively, because the alternative is that each of them gets
answered inside a source file where nobody sees it.

### 2.1 Nesting

A reader MUST refuse input that nests containers more than **64** deep, and
MUST refuse it without having recursed that far.

Input arrives from the network. A reader that recurses as deep as the sender
says is a crash waiting for a sender who cares, and a crash in a parser is
reachable before any authentication has happened.

64 is chosen as far beyond any structure this stack defines (the deepest is
four) and far below any stack limit.

### 2.2 Lexicographic order

Where BDF requires dictionary keys to be "unique and sorted in lexicographic
order", the order is over the **UTF-8 bytes** of the keys.

BDF does not say, and the two obvious readings differ: comparing UTF-16 code
units, as Java's `String.compareTo` does, sorts the supplementary planes
before U+E000 to U+FFFF rather than after. Any implementation that picks the
other reading computes different hashes for the same dictionary, and the
disagreement only appears once someone uses an emoji as a key.

### 2.3 Canonical form is required where it is hashed

A reader MUST offer a strict mode that refuses any object which is not in
canonical form: integers and lengths in the fewest bytes that hold them,
dictionary keys unique and sorted.

Any data that is hashed, signed, or used to derive an identifier MUST be
parsed in strict mode.

BDF phrases canonical form as a requirement on the writer ("if data is to be
hashed or signed"). That is enough when both ends are honest and not enough
against an adversary: a non-minimal length is a second encoding of the same
value, so a message can be altered without changing what it means, while
changing its identifier. Refusing on the reading side closes it.

Non-canonical input remains readable in the default mode, because refusing it
everywhere would break nothing today and cost the ability to read a
well-formed message from a future writer that is merely sloppy.

## 3 Limits

BDF names no maximum size for anything. Sizes are the business of the layer
that uses the encoding, and every such layer states its own.

## 4 Test vectors

`crates/bdf/tests/spec_vectors.rs`, each case quoting the sentence it holds
to. The oracle problem is real and is stated in `00-overview.md` section 7:
the vectors show that the code matches this document, not that this document
is right.

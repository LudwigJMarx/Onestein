# Primitives, draft 0

Version 1. Every other document uses the notation and the algorithms fixed
here, and every key derivation in the stack binds this version.

## 1 Notation

- `||` denotes concatenation
- Double quotes denote an ASCII string
- `len(x)` is the length of `x` in bytes
- `int_n(x)` is `x` as an unsigned, big-endian, n-bit integer

## 2 Hash

A cryptographic hash function `H(m)` with an output of HASH_LEN bytes, and
from it a multi-argument function:

- HASH(x_1, ..., x_n) = H(int_32(len(x_1)) || x_1 || ... || int_32(len(x_n)) || x_n)

The length prefixes are the construction, not packaging. Without them
HASH("a", "bc") and HASH("ab", "c") are one value, and an adversary can move
the boundary between two fields of a signed structure without changing what
is signed.

Taken unchanged from Bramble (BSP 1.4, CC BY-SA 4.0). Implemented in
`crates/crypto`, with vectors against CPython's `hashlib`.

An argument longer than `u32::MAX` cannot be framed and is a programming
error, not an input error: every caller in this stack is bounded in its own
document.

## 3 Key derivation

A message authentication code `MAC(k, m)`, which must be a pseudo-random
function, and from it:

- KDF(k, x_1, ..., x_n) = MAC(k, int_32(len(x_1)) || x_1 || ... || int_32(len(x_n)) || x_n)

HASH and KDF use the same framing on purpose. One framing means one thing to
get right.

## 4 Algorithms

| Role | Algorithm | Sizes in bytes | Note |
|---|---|---|---|
| Hash | BLAKE2b, 32-byte output | HASH_LEN = 32 | |
| MAC, KDF | keyed BLAKE2b, 32-byte output | KEY_LEN = MAC_LEN = 32 | HASH_LEN = KEY_LEN = MAC_LEN, as Bramble requires and for the same reason: fewer conversions, fewer mistakes |
| Authenticated cipher | XSalsa20/Poly1305 | key 32, nonce 24, tag 16 | The 24-byte nonce is what makes random nonces safe in `20-transport.md` |
| Key agreement, classical | X25519 | public 32, shared 32 | An all-zero shared secret aborts the protocol |
| Key encapsulation, post-quantum | ML-KEM-768 (FIPS 203) | ek 1184, ct 1088, ss 32 | |
| Signature, classical | Ed25519 | public 32, signature 64 | |
| Signature, post-quantum | ML-DSA-65 (FIPS 204) | public 1952, signature 3309 | Only where a handshake or a certificate carries it, never per message |
| Randomness | CSPRNG of the host | | The library takes randomness as an argument; see §6 |

Parameter sets are chosen at the 128-bit-classical level throughout, so no
single algorithm is the weak one. ML-KEM-1024 and ML-DSA-87 are drop-in
replacements if a parameter set is later judged short; both change sizes and
nothing else, and both mean a new version of the document that uses them.

## 5 No own primitives

Nothing in this list is implemented in this project. Not the hash, not the
curve, not the KEM. A primitive written here would need an audit this project
cannot pay for, and a subtly wrong one produces output that looks exactly
right.

Implementations are taken from reviewed libraries, named in the crate that
uses them, and pinned in `Cargo.lock`.

## 6 What the library does not do

**It does not gather randomness.** Randomness is passed in. A library that
reaches for the system generator on its own cannot be tested against known
vectors, and cannot be used on a platform whose generator the caller distrusts.

**It does not decide where secrets live.** Keys go in and come out. Whether
they reach a disk, and whether they can be wiped, is the application's
decision, and only the application can carry it out. This stack can mark
which bytes are secret; it cannot make them disappear.

**It does not truncate.** No hash, no MAC, no shared secret is shortened to
save bytes anywhere in this stack. Where a shorter value is needed, it is
derived, not cut.

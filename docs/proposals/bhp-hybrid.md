# Hybrid Post-Quantum Key Agreement for BHP, draft 0

A proposal by the Onestein project for **Briar's** Bramble stack. It is not
part of Onestein's own stack and not part of Bramble either: the Briar
Project has neither reviewed nor adopted it.

Kept because it stands on its own and could still be offered upstream. Where
Onestein's own handshake goes further, see `spec/30-handshake.md`: this
proposal signs, that one authenticates by decapsulation, because Bramble has
no per-device static KEM key to encapsulate to and Onestein's identity layer
does. Licensed CC BY-SA 4.0 to
match `briar-spec`, so that adopting it upstream raises no licence question.

Status: unimplemented, unreviewed. No part of this has been run.

## 1 Problem

BHP 0.1 derives the ephemeral master key from three X25519 shared secrets. An
adversary who records a handshake today and acquires a cryptographically
relevant quantum computer later can compute all three from the recorded
public keys, derive the master key, and read everything that was secured with
it.

This matters more here than in a session-based messenger. Bramble contacts are
long-lived, BTP rotates its keys from a root key established by exactly this
handshake, and the traffic is carried over Tor, where recording is cheap for
anyone positioned to do it. The material an adversary needs is already being
written down.

## 2 Scope

In scope: BHP, the handshake between two peers that have already exchanged
long-term public keys.

Out of scope, and each for its own reason:

- **BQP** establishes a key by QR code and short-range transport. ML-KEM
  public keys do not fit a QR code at the sizes a phone camera reads
  reliably. A separate problem, not a harder version of this one.
- **BRP** derives Tor v3 hidden service addresses from the peers' keys. A
  v3 address *is* an Ed25519 public key; that is Tor's format, not Bramble's
  choice, and it cannot be made post-quantum from this side.
- **Long-term identity keys** stay X25519. Changing them means every contact
  relationship is re-established. See section 7.

## 3 What this does and does not protect

| Property | Against a classical adversary | Against a future quantum adversary |
|---|---|---|
| Confidentiality of the master key | yes, as today | **yes, this is the change** |
| Authentication, man in the middle | yes, as today | no |

The asymmetry is deliberate and it is the standard shape of a hybrid upgrade.
Retroactive decryption is an attack that succeeds against traffic recorded
today, so it has to be stopped today. Impersonation requires the quantum
computer at the time of the handshake, which is a threat that arrives with
warning and can be answered later by replacing the long-term keys.

Do not read this document as making Bramble post-quantum. It makes recorded
Bramble traffic useless to a later quantum adversary, and nothing else.

## 4 Primitives

Added to those in BHP 1.4:

4. **A key encapsulation mechanism**, (ek, dk) = KEM.KeyGen(), (ct, ss) =
   KEM.Encaps(ek), ss = KEM.Decaps(dk, ct)

(*Note:* This version uses ML-KEM-768 as specified in FIPS 203, giving
len(ek) = 1184, len(ct) = 1088 and len(ss) = 32 bytes. ML-KEM-1024 is a
drop-in at 1568 and 1568 bytes if the parameter set is later judged too
small; the protocol does not depend on the sizes.)

The KEM is used **in addition to** X25519, never instead of it. If ML-KEM or
its implementation turns out to be broken, the handshake is exactly as strong
as BHP 0.1 is today. That is the entire argument for a hybrid rather than a
replacement, and it is why the X25519 secrets stay in the derivation
unchanged.

## 5 Records

Two record types are added to those in BHP 2.1:

**3: PQ_ENCAPSULATION_KEY** - The payload consists of the sender's ephemeral
KEM encapsulation key.

**4: PQ_CIPHERTEXT** - The payload consists of the sender's KEM ciphertext,
encapsulated to the recipient's ephemeral encapsulation key.

The minor version for this variant is **2**. BHP 2.1 already requires a peer
to abort when no minor version is received.

A record payload may be up to 48 KiB, so both records fit. Note for
implementers that a BTP frame carries at most 988 bytes of data and padding,
so either record spans two frames. BTP is a stream and does not care; a
transport with a small fixed message size would.

## 6 Protocol steps

Unchanged in number: two round trips, four steps. The KEM fits into the
existing ones because the second peer to speak already holds the first peer's
encapsulation key.

1. Alice sends EPHEMERAL_PUBLIC_KEY, PQ_ENCAPSULATION_KEY, MINOR_VERSION
2. Bob sends EPHEMERAL_PUBLIC_KEY, PQ_ENCAPSULATION_KEY, MINOR_VERSION, and
   PQ_CIPHERTEXT: (ct_b, ss_b) = KEM.Encaps(ek_a)
3. Alice computes (ct_a, ss_a) = KEM.Encaps(ek_b), decapsulates ss_b =
   KEM.Decaps(dk_a, ct_b), derives the master key, and sends PQ_CIPHERTEXT
   and PROOF_OF_OWNERSHIP
4. Bob decapsulates ss_a = KEM.Decaps(dk_b, ct_a), derives the master key,
   verifies Alice's proof and sends his own

Both peers encapsulate. One encapsulation would be enough for confidentiality
and would save 1088 bytes, and it was rejected: the shared secret would then
depend on one peer's random number generator alone, and a device whose
generator is weak would hand the adversary the post-quantum half of the key
without the other peer being able to notice.

## 7 Key derivation

Replacing the derivation in BHP 2.3. The three X25519 raw secrets are
computed exactly as before.

- ephemeral_master_key = HASH(
  "org.onestein.handshake/HYBRID_MASTER_KEY",
  raw_ephemeral, raw_static_ephemeral, raw_ephemeral_static,
  ss_a, ss_b,
  pub_long_term_a, pub_long_term_b,
  pub_ephemeral_a, pub_ephemeral_b,
  ek_a, ek_b, ct_a, ct_b,
  int_8(minor_version_a), int_8(minor_version_b))

Three things about this construction are not decoration:

**A new label.** A peer running this variant and a peer running BHP 0.1 must
never derive the same key from the same inputs. The label is the domain
separation, and it carries this project's namespace because this is not an
adopted Bramble protocol. If it is ever adopted, the label changes to
`org.briarproject.bramble.handshake/...` and that is a breaking change on
purpose.

**Encapsulation keys and ciphertexts are hashed in.** HASH frames every
argument with its length (BHP 1.4), so the transcript cannot be reinterpreted
by moving a boundary. An adversary who alters any KEM material changes the
master key on one side, and the proof of ownership in step 3 or 4 fails.

**The minor versions are hashed in.** This is the downgrade defence, and it is
also a remark about BHP 0.1: the current derivation does not cover the minor
version. Today nothing can be downgraded, because there is exactly one
non-zero minor version. From the moment a second exists, an adversary can
rewrite a MINOR_VERSION record and both peers will still agree on a master
key, having silently agreed on the weaker of the two protocols. Binding the
version into the key makes that rewrite produce two different keys and a
failed proof.

The peers delete their ephemeral private keys, the decapsulation keys and all
raw secrets, as in BHP 2.3.

## 8 Compatibility

A peer implementing this variant remains able to talk to Briar 1.5. It offers
minor version 2 and sends the two new records; a peer that does not know them
ignores unrecognised record types, as BHP 2.1 requires, and answers with minor
version 1. Both then derive the BHP 0.1 master key with the BHP 0.1 label.

A peer that has received minor version 2 from its remote peer **must** abort
if the PQ records do not arrive. Fail closed, as BHP already does for a
missing minor version.

So the upgrade costs no interoperability. It is opt-in per connection and
invisible to peers that do not have it.

## 9 Open questions

| Question | Why it is open |
|---|---|
| Does Briar's implementation really ignore unknown record types here, as 2.1 says? | The rule is written down. Whether the Java code follows it is a measurement, and nobody has made it |
| Is ML-KEM-768 the right parameter set for a decade-long contact relationship? | 768 is the common choice for transport. A contact key is not a transport key |
| Which implementation of ML-KEM? | Candidates are the RustCrypto `ml-kem` crate and `libcrux-ml-kem`, the latter machine-checked. Neither has been evaluated here |
| Does the handshake stay within one BTP stream in practice? | 2272 extra bytes each way is nothing for TCP over Tor and is not nothing for a low-bandwidth transport |
| What does the added latency do on a very slow transport? | The steps do not increase, only the bytes. Unmeasured |

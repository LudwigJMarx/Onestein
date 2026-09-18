# Identity, draft 0

Version 1. Bound into every identifier and every key derivation below.

Answers R6 (one identity, several devices), R7 (an identity survives the loss
of a device) and part of R10 (a contact learns little about a peer's other
contacts).

## 1 What an identity is

An identity is a **root key pair** and the set of **devices** it has
certified. It is not an account, it is not registered anywhere, and nothing
issues it. A contact knows an identity by its root public keys and by nothing
else.

The root key signs certificates and revocations. It signs no messages and it
takes part in no handshake. That is what makes it possible to keep it out of
daily reach and to reconstruct it from a seed (section 6).

Devices do the work. Each device holds its own keys, and a contact accepts a
device because the root key said so, not because the contact met it.

## 2 Keys

| Key | Algorithm | Held by | Public size | Used for |
|---|---|---|---|---|
| Root signing, classical | Ed25519 | identity | 32 | signing device certificates and revocations |
| Root signing, post-quantum | ML-DSA-65 (FIPS 204) | identity | 1952 | the same, alongside |
| Device signing | Ed25519 | device | 32 | authorship of messages a third party must verify |
| Device agreement, classical | X25519 | device | 32 | the handshake |
| Device agreement, post-quantum | ML-KEM-768 (FIPS 203) | device | 1184 | the handshake |
| Contact, classical | X25519 | identity | 32 | keying handshake mode in `20-transport.md` §3, nothing else |

Both root signatures are always produced and both MUST verify. A certificate
that carries only one of them is refused. Hybrid means both, never either.

The contact key is the one identity-level key that is not a signing key, and
it is the exception to the paragraph below: it is derived from the recovery
seed and therefore exists on every device of the identity. It provides **no
forward secrecy** and is used for exactly one thing, concealing the handshake
that has not happened yet. It never protects a message. Without it the one
exchange every contact begins with would be the one a censor recognises on
sight, and a device that has just been recovered could not open a channel to
a contact at all.

Device keys are per device and never leave it. There is no key that, once
taken from one device, opens another.

## 3 Identity identifier

- identity_id = HASH("org.onestein.identity/IDENTITY_ID", int_8(version),
  root_ed25519_pub, root_mldsa_pub)

32 bytes, the full output of the hash construction in `05-primitives.md`.
Truncating it would save 16 bytes in a contact record and buy a collision
search, and contact records are not where this stack spends its bytes.

The version is inside the hash. An identity of version 2 is therefore a
different identity, with a different identifier, even with the same root
keys. That is the cost of the versioning rule from `00-overview.md` §5.4, and
it is paid here deliberately rather than discovered later: a stack that lets
two versions agree on one identifier lets an adversary choose which version
the peers believe they are speaking.

## 4 Devices and certificates

A device certificate is a BDF dictionary in canonical form (`10-encoding.md`
§2.3), signed by both root keys over its encoding:

| Key | Type | Meaning |
|---|---|---|
| `v` | integer | identity version |
| `id` | raw | identity_id |
| `dev` | raw | device signing public key |
| `dh` | raw | device X25519 public key |
| `kem` | raw | device ML-KEM encapsulation key |
| `epoch` | integer | device set epoch this certificate belongs to (section 5) |
| `from` | integer | milliseconds since the Unix epoch, when the device was certified |

- to_sign = HASH("org.onestein.identity/DEVICE_CERTIFICATE", canonical_bdf)
- signatures are over `to_sign`, one per root key

A certificate travels with its signatures in a canonical BDF dictionary:

| Key | Type | Meaning |
|---|---|---|
| `c` | raw | the certificate encoding, exactly as it was signed |
| `e` | raw | the Ed25519 signature, 64 bytes |
| `p` | raw | the ML-DSA-65 signature, 3309 bytes |

The certificate is carried as bytes rather than as a nested dictionary
because what was signed must be what is verified: a verifier that re-encoded
a parsed structure would be checking a signature over its own encoder.

ML-DSA takes a context string. It is **empty** here, in every signature this
stack makes. The domain separation lives in `to_sign`, where a label already
says which structure is being signed, and a second mechanism saying the same
thing is a second mechanism to get wrong. An implementation that passed the
label as the context would produce signatures no other implementation
verifies, and nothing in the bytes would show why.

A verifier MUST check that the `id` field equals the identifier derived from
the root keys it is verifying against (§3). Without that check, a certificate
signed by a trusted identity could name a different one, and every contact
would then hold two identities that disagree about which devices belong to
whom.

No name, no label, no device type. A field that describes the device to its
owner also describes it to whoever holds the device, and this certificate
travels to every contact.

There is no expiry field. An expiry that nobody can check without a
trustworthy clock is decoration, and a device that should stop being accepted
is revoked (section 5).

**Adding a device does not touch any contact relationship.** The new device
presents its certificate; a contact verifies it against the root keys it
already has. Nothing is re-established, nobody meets again, and no contact
has to be online at the time. That is R6, and it is the whole reason the root
key exists separately from the device keys.

## 5 Device set epoch and revocation

The identity keeps a **device set epoch**, an integer that only increases. A
certificate or revocation names the epoch it belongs to.

- revocation = canonical BDF over `{v, id, dev, epoch}`, carried and signed
  the same way, with its own label:
- to_sign = HASH("org.onestein.identity/DEVICE_REVOCATION", canonical_bdf)

The label differs from the certificate's on purpose. One label for both would
mean a signature keeps its meaning when the fields around it are reinterpreted,
and the two structures share four of their field names.

No reason field. A reason is written for a person, travels to every contact,
and says something about why a device was lost that the owner may not want to
have said.

Rules for a contact:

1. A contact records the highest epoch it has seen for that identity.
2. A certificate or revocation from a **lower** epoch is refused, silently.
3. A device that has been revoked is refused from that moment on.

Rule 2 is the one that matters. An adversary who holds a seized device can
stop a revocation from reaching the peers it talks to; nothing prevents that,
because there is no server to ask. What rule 2 prevents is worse: replaying
an old certificate to a contact who already learned of the revocation, and
thereby resurrecting a dead device.

**A revocation cannot be dated.** Timestamps in this stack are what the
sender wrote, and a seized device writes whatever its holder wants. So a
contact refuses a revoked device from the moment it learns of the revocation,
not from a claimed time, and messages it accepted earlier stay accepted. Any
rule of the form "reject what that device signed after Tuesday" would be a
rule about an attacker-supplied number.

## 6 Recovery

The root key pair is derived from a 32-byte **recovery seed**:

- root_ed25519_seed = KDF(seed, "org.onestein.identity/ROOT_ED25519")
- root_mldsa_seed = KDF(seed, "org.onestein.identity/ROOT_MLDSA")
- contact_x25519_seed = KDF(seed, "org.onestein.identity/CONTACT_KEY")

Both algorithms generate a key pair deterministically from a 32-byte seed, so
the same seed yields the same identity on any device, forever, with no server
and no backup file.

What recovery restores, and what it does not, is the part to be honest about:

| Restored from the seed alone | Not restored from the seed |
|---|---|
| The identity and its identifier | The contact list |
| The ability to certify a new device | Message history |
| The ability to revoke the lost device | The pairwise keys of existing contacts |

The pairwise keys are **deliberately** not recoverable. A seed that could
re-derive them would be a seed that undoes forward secrecy, and the whole
transport layer rests on old keys being gone. After recovery, a contact
relationship is re-established by running the handshake again, which works
because the handshake authenticates against the identity root keys that the
contact already holds. The contact sees a new device under a known identity,
which is the case section 4 is built for.

The contact list is a separate problem with a separate answer: an encrypted
export, or shares distributed among contacts. It belongs in its own document
and is not solved here. Saying "recovery" without saying which of the two is
meant is how a user ends up with an identity and no one to talk to.

## 7 What is post-quantum here, and what is not

Stated as a table because prose hides the gap.

| Property | Post-quantum? | Why |
|---|---|---|
| Confidentiality of a one-to-one conversation | **yes** | The handshake is hybrid and the transport keys descend from it |
| Authenticity of a one-to-one conversation | **yes** | It rides on the same channel, not on a signature |
| Authenticity of the handshake itself | **yes**, once `30-handshake.md` binds a transcript signature by the root ML-DSA key. A handshake happens once per contact, so 3309 bytes is affordable there | |
| Authorship of a message in a group, verified by a third party | **no** | Ed25519 device signature. An ML-DSA signature on every message is 3309 bytes, which is not affordable on a transport that carries 988 bytes per frame |

The last row is a real limitation and it is not hidden behind a version
number. An adversary with a quantum computer, at the time, can forge group
authorship. The same adversary cannot read one-to-one traffic, then or from a
recording. Raising the last row means either a signature scheme with small
signatures or a group design that does not need third-party verification, and
neither is decided here.

## 8 What a contact learns

A contact learns: the identity identifier, the root public keys, and the
certified devices. That is what it needs to verify anything at all.

A contact does not learn: how many contacts the identity has, who they are,
which device is in use, or where a device is.

Not attempted: unlinkability between contacts. Two contacts who compare notes
see the same identity_id and know they are talking about the same person. A
per-contact identity would prevent that and would also prevent introductions
and group membership, both of which need a name that more than one person can
verify. The trade is stated rather than pretended away.

## 9 Open questions

| Question | Why it is open |
|---|---|
| How does a contact first receive a device certificate? | Section 4 assumes it arrives. Whether it rides in the handshake, in the sync layer, or both, is `30-handshake.md` and `50-sync.md` |
| How is the recovery seed shown to a person? | Word list, and which one. A seed that gets written down wrong is not a backup |
| Should the epoch be a counter or a timestamp? | A counter cannot be forged forward by a clock, but two devices of the same identity can both increment it. That is a conflict this document does not resolve |
| What happens when two devices certify conflicting device sets? | The multi-device case creates a write conflict on the identity's own state. Undecided, and it is the hardest thing in this document |

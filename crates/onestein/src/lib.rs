//! Onestein: one crate that re-exports the whole stack.
//!
//! Each layer is its own crate and can be taken on its own. This one exists
//! so that an application can depend on `onestein` and reach all of them
//! under the names the specification uses.
//!
//! ```text
//! primitives  hash, key derivation, the algorithm list   spec/05-primitives.md
//! encoding    canonical binary encoding                  spec/10-encoding.md
//! transport   tags, headers, frames, key rotation        spec/20-transport.md
//! handshake   hybrid X25519 and ML-KEM key agreement     spec/30-handshake.md
//! contact     bundles, links, rendezvous                 spec/35-contact.md
//! identity    identities, devices, recovery              spec/40-identity.md
//! sync        message graph, records, delivery           spec/50-sync.md
//! relay       optional store and forward                 spec/60-relay.md
//! ```
//!
//! # What this crate does not do
//!
//! It opens no file, no socket, and reads no clock. Randomness is passed in,
//! time is passed in, and state goes out to the caller and comes back. An
//! application brings storage, a network and a user interface, and decides
//! what can be wiped. That is not an omission: the one thing a library cannot
//! do for a messenger is make a secret disappear.
//!
//! # Two devices agreeing on a key
//!
//! The seeds below stand in for randomness the caller would supply.
//!
//! ```
//! use onestein::handshake::{KeyPair, Role, Secrets, Transcript, confirmation, encapsulate, root_key};
//!
//! // Long-term device keys, which in practice come from a device certificate.
//! let static_a = KeyPair::from_seeds(&[0x11; 32], &[0x11; 64]);
//! let static_b = KeyPair::from_seeds(&[0x22; 32], &[0x22; 64]);
//! // Fresh per handshake.
//! let ephemeral_a = KeyPair::from_seeds(&[0x33; 32], &[0x33; 64]);
//! let ephemeral_b = KeyPair::from_seeds(&[0x44; 32], &[0x44; 64]);
//!
//! // B answers first: it holds A's keys and encapsulates to both.
//! let (ct_ephemeral_b, kem_ephemeral_b) =
//!     encapsulate(&ephemeral_a.kem_encapsulation_key(), &[0x55; 32])?;
//! let (ct_static_b, kem_static_b) = encapsulate(&static_a.kem_encapsulation_key(), &[0x66; 32])?;
//! // A answers in turn.
//! let (ct_ephemeral_a, kem_ephemeral_a) =
//!     encapsulate(&ephemeral_b.kem_encapsulation_key(), &[0x77; 32])?;
//! let (ct_static_a, kem_static_a) = encapsulate(&static_b.kem_encapsulation_key(), &[0x88; 32])?;
//!
//! let secrets = Secrets {
//!     dh_ephemeral: ephemeral_a.agree(&ephemeral_b.x25519_public())?,
//!     dh_ephemeral_static: ephemeral_a.agree(&static_b.x25519_public())?,
//!     dh_static_ephemeral: static_a.agree(&ephemeral_b.x25519_public())?,
//!     kem_ephemeral_a,
//!     kem_ephemeral_b: ephemeral_a.decapsulate(&ct_ephemeral_b),
//!     kem_static_a,
//!     kem_static_b: static_a.decapsulate(&ct_static_b),
//! };
//!
//! let (dh_static_pub_a, dh_static_pub_b) = (static_a.x25519_public(), static_b.x25519_public());
//! let (kem_static_pub_a, kem_static_pub_b) =
//!     (static_a.kem_encapsulation_key(), static_b.kem_encapsulation_key());
//! let (dh_ephemeral_pub_a, dh_ephemeral_pub_b) =
//!     (ephemeral_a.x25519_public(), ephemeral_b.x25519_public());
//! let (kem_ephemeral_pub_a, kem_ephemeral_pub_b) = (
//!     ephemeral_a.kem_encapsulation_key(),
//!     ephemeral_b.kem_encapsulation_key(),
//! );
//!
//! let transcript = Transcript {
//!     identity_id_a: &[0x01; 32],
//!     identity_id_b: &[0x02; 32],
//!     device_signing_pub_a: &[0x03; 32],
//!     device_signing_pub_b: &[0x04; 32],
//!     dh_static_pub_a: &dh_static_pub_a,
//!     dh_static_pub_b: &dh_static_pub_b,
//!     kem_static_pub_a: &kem_static_pub_a,
//!     kem_static_pub_b: &kem_static_pub_b,
//!     dh_ephemeral_pub_a: &dh_ephemeral_pub_a,
//!     dh_ephemeral_pub_b: &dh_ephemeral_pub_b,
//!     kem_ephemeral_pub_a: &kem_ephemeral_pub_a,
//!     kem_ephemeral_pub_b: &kem_ephemeral_pub_b,
//!     ct_ephemeral_a: &ct_ephemeral_a,
//!     ct_ephemeral_b: &ct_ephemeral_b,
//!     ct_static_a: &ct_static_a,
//!     ct_static_b: &ct_static_b,
//! };
//!
//! // The transport layer starts from this key; the confirmation is what each
//! // side sends to prove it got there.
//! let key = root_key(&secrets, &transcript);
//! assert_ne!(confirmation(&key, Role::A), confirmation(&key, Role::B));
//! # Ok::<(), onestein::handshake::Error>(())
//! ```

#![forbid(unsafe_code)]

pub use onestein_bdf as encoding;
pub use onestein_contact as contact;
pub use onestein_crypto as primitives;
pub use onestein_handshake as handshake;
pub use onestein_identity as identity;
pub use onestein_record as record;
pub use onestein_relay as relay;
pub use onestein_sync as sync;
pub use onestein_transport as transport;

//! Bundles, links, rendezvous and fingerprints.
//!
//! Spec: `spec/35-contact.md`.

use onestein_bdf::{Value, from_bytes_canonical};
use onestein_contact::{
    CONTACT_KEY_LEN, ContactBundle, ContactLink, Error, LINK_PREFIX, ROOT_MLDSA_LEN, Side,
    address_seed, fingerprint, rendezvous_key,
};

fn bundle() -> ContactBundle {
    ContactBundle {
        root_ed25519: [0x11; 32],
        root_mldsa: vec![0x22; ROOT_MLDSA_LEN],
        contact_key: [0x33; CONTACT_KEY_LEN],
    }
}

// "The contact bundle, a canonical BDF dictionary" with keys v, ed, pq, x.
#[test]
fn a_bundle_is_canonical_and_carries_four_fields() {
    let encoded = bundle().encode().expect("encodes");
    let parsed = from_bytes_canonical(&encoded).expect("strictly canonical");
    let entries = match parsed {
        Value::Dict(entries) => entries,
        _ => Vec::new(),
    };
    let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, vec!["ed", "pq", "v", "x"]);
    assert_eq!(ContactBundle::decode(&encoded), Ok(bundle()));
}

#[test]
fn a_bundle_with_a_wrong_sized_key_is_refused() {
    let mut wrong = bundle();
    wrong.root_mldsa = vec![0x22; 100];
    assert_eq!(
        wrong.encode(),
        Err(Error::WrongKeyLength {
            expected: ROOT_MLDSA_LEN,
            given: 100
        })
    );
}

// "Each side hashes the bundle it received and compares with the commitment
// it scanned. A mismatch aborts."
#[test]
fn a_bundle_checks_against_its_own_commitment_and_not_another() {
    let mine = bundle();
    let commitment = mine.commitment().expect("commits");
    assert_eq!(mine.check(&commitment), Ok(()));

    let mut other = bundle();
    other.root_ed25519 = [0x99; 32];
    assert_eq!(other.check(&commitment), Err(Error::CommitmentMismatch));
    assert_ne!(other.commitment(), Ok(commitment));
}

// "64 bytes of payload become 103 characters, plus the prefix."
#[test]
fn a_link_round_trips_and_has_the_length_the_document_claims() {
    let link = ContactLink {
        contact_key: [0x33; CONTACT_KEY_LEN],
        commitment: bundle().commitment().expect("commits"),
    };
    let text = link.to_text();
    assert!(text.starts_with(LINK_PREFIX));
    assert_eq!(text.len(), LINK_PREFIX.len() + 103);
    assert_eq!(ContactLink::parse(&text), Ok(link));
}

#[test]
fn a_link_survives_a_channel_that_reflows_it() {
    let link = ContactLink {
        contact_key: [0x44; CONTACT_KEY_LEN],
        commitment: [0x55; 32],
    };
    let text = link.to_text();
    assert_eq!(ContactLink::parse(&text.to_lowercase()), Ok(link));
    assert_eq!(ContactLink::parse(&format!("{text}\n")), Ok(link));
}

#[test]
fn something_that_is_not_a_link_is_refused() {
    assert_eq!(
        ContactLink::parse("https://example.invalid"),
        Err(Error::NotALink)
    );
    assert_eq!(ContactLink::parse("onestein:2:MZXW6"), Err(Error::NotALink));
    assert!(ContactLink::parse("onestein:1:MZXW6").is_err());
}

// Both sides must derive the same rendezvous key, one from its own secret and
// the peer's public key, the other the other way round. If they do not, two
// devices that exchanged links never find each other.
#[test]
fn both_sides_derive_the_same_rendezvous_key() {
    let secret_a = [0x01; CONTACT_KEY_LEN];
    let secret_b = [0x02; CONTACT_KEY_LEN];
    let public_a = x25519_public(&secret_a);
    let public_b = x25519_public(&secret_b);
    let commitment_a = [0xaa; 32];
    let commitment_b = [0xbb; 32];

    let from_a = rendezvous_key(&secret_a, &public_b, &commitment_a, &commitment_b);
    let from_b = rendezvous_key(&secret_b, &public_a, &commitment_a, &commitment_b);
    assert_eq!(from_a, from_b);
    assert!(from_a.is_ok());
}

// The commitments are in the key, so a link swapped in flight gives a
// different rendezvous and the peers simply never meet, rather than meeting
// whoever swapped it.
#[test]
fn the_commitments_are_part_of_the_rendezvous_key() {
    let secret_a = [0x01; CONTACT_KEY_LEN];
    let public_b = x25519_public(&[0x02; CONTACT_KEY_LEN]);
    let base = rendezvous_key(&secret_a, &public_b, &[0xaa; 32], &[0xbb; 32]);
    assert_ne!(
        base,
        rendezvous_key(&secret_a, &public_b, &[0xaa; 32], &[0xbc; 32])
    );
    // Order matters too: A first, always.
    assert_ne!(
        base,
        rendezvous_key(&secret_a, &public_b, &[0xbb; 32], &[0xaa; 32])
    );
}

#[test]
fn a_degenerate_public_key_is_refused() {
    assert_eq!(
        rendezvous_key(
            &[0x01; CONTACT_KEY_LEN],
            &[0u8; 32],
            &[0xaa; 32],
            &[0xbb; 32]
        ),
        Err(Error::DegenerateSharedSecret)
    );
}

// "The addresses change each period, so an address observed once does not
// identify a relationship later."
#[test]
fn an_address_seed_changes_with_side_transport_and_period() {
    let key = [0x77; 32];
    let base = address_seed(&key, Side::A, "org.onestein.transport.tor", 700);
    assert_ne!(
        base,
        address_seed(&key, Side::B, "org.onestein.transport.tor", 700)
    );
    assert_ne!(
        base,
        address_seed(&key, Side::A, "org.onestein.transport.lan", 700)
    );
    assert_ne!(
        base,
        address_seed(&key, Side::A, "org.onestein.transport.tor", 701)
    );
    assert_eq!(
        base,
        address_seed(&key, Side::A, "org.onestein.transport.tor", 700)
    );
}

// "It is shown as 13 groups of four base32 characters, 52 characters in all."
#[test]
fn a_fingerprint_is_thirteen_groups_of_four() {
    let text = fingerprint(&[0x5a; 32]);
    let groups: Vec<&str> = text.split(' ').collect();
    assert_eq!(groups.len(), 13);
    assert!(groups.iter().all(|group| group.len() == 4));
    assert_eq!(text.replace(' ', "").len(), 52);
    assert_ne!(text, fingerprint(&[0x5b; 32]));
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

//! What a relay holds and what it refuses.
//!
//! Spec: `spec/60-relay.md` §4a, §5.

use onestein_relay::{Direction, MAX_BLOB_LEN, MAX_QUEUE_LEN, QueueKeys, Refusal, Store, blob_id};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const RELAY: &str = "relay.example";
const DAY: u64 = 24 * 60 * 60 * 1000;

fn queue() -> [u8; 32] {
    onestein_relay::queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7)
}

fn registered() -> Store {
    let mut store = Store::new();
    let keys = QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 7);
    store.register(queue(), keys.registration(), 0);
    store
}

// "A blob is named by its content", so a relay cannot name what it lacks.
#[test]
fn a_blob_is_named_by_its_content() {
    assert_eq!(blob_id(b"one"), blob_id(b"one"));
    assert_ne!(blob_id(b"one"), blob_id(b"two"));
}

#[test]
fn a_blob_written_can_be_read_and_then_deleted() {
    let mut store = registered();
    let id = store
        .write(&queue(), b"ciphertext".to_vec(), DAY)
        .expect("writes");
    assert_eq!(id, blob_id(b"ciphertext"));

    let (read_id, bytes) = store.read(&queue()).expect("holds one");
    assert_eq!(read_id, id);
    assert_eq!(bytes, b"ciphertext");

    assert_eq!(store.delete(&queue(), &id), Ok(()));
    assert!(store.read(&queue()).is_none());
}

// "Reading does not delete", because a reader can crash halfway through.
#[test]
fn reading_twice_returns_the_same_blob() {
    let mut store = registered();
    store
        .write(&queue(), b"ciphertext".to_vec(), 0)
        .expect("writes");
    let first = store.read(&queue()).map(|(id, _)| id);
    let second = store.read(&queue()).map(|(id, _)| id);
    assert_eq!(first, second);
    assert!(first.is_some());
}

#[test]
fn the_oldest_blob_comes_first() {
    let mut store = registered();
    store.write(&queue(), b"first".to_vec(), 0).expect("writes");
    store
        .write(&queue(), b"second".to_vec(), 1)
        .expect("writes");
    assert_eq!(
        store.read(&queue()).map(|(_, bytes)| bytes),
        Some(b"first".as_slice())
    );
}

#[test]
fn an_unknown_queue_refuses_everything() {
    let mut store = Store::new();
    let unknown = [0x99; 32];
    assert_eq!(
        store.write(&unknown, b"x".to_vec(), 0),
        Err(Refusal::UnknownQueue)
    );
    assert_eq!(
        store.delete(&unknown, &blob_id(b"x")),
        Err(Refusal::UnknownQueue)
    );
    assert!(store.read(&unknown).is_none());
    assert!(store.registration(&unknown).is_none());
}

// "Blob size: 64 KiB. Queue size: 16 MiB."
#[test]
fn the_limits_from_the_table_are_enforced() {
    let mut store = registered();
    assert!(store.write(&queue(), vec![0u8; MAX_BLOB_LEN], 0).is_ok());
    assert_eq!(
        store.write(&queue(), vec![0u8; MAX_BLOB_LEN + 1], 0),
        Err(Refusal::TooLarge)
    );

    let mut filling = registered();
    let mut written = 0usize;
    while written + MAX_BLOB_LEN <= MAX_QUEUE_LEN {
        // Distinct blobs of exactly the maximum size: appending a counter
        // would push them over the blob limit instead of the queue limit,
        // and the test would then prove nothing.
        let mut unique = vec![0u8; MAX_BLOB_LEN];
        for (slot, byte) in unique.iter_mut().zip(written.to_be_bytes()) {
            *slot = byte;
        }
        filling
            .write(&queue(), unique, 0)
            .expect("each of these fits");
        written += MAX_BLOB_LEN;
    }
    assert_eq!(
        filling.write(&queue(), vec![0xff; MAX_BLOB_LEN], 0),
        Err(Refusal::QueueFull)
    );
}

// "A blob past its expiry is deleted whether it was collected or not."
#[test]
fn a_blob_older_than_thirty_days_goes() {
    let mut store = registered();
    store.write(&queue(), b"old".to_vec(), 0).expect("writes");
    store
        .write(&queue(), b"new".to_vec(), 29 * DAY)
        .expect("writes");

    store.expire(31 * DAY);
    assert_eq!(
        store.read(&queue()).map(|(_, bytes)| bytes),
        Some(b"new".as_slice())
    );
}

// "Queue expiry after last write: 60 days."
#[test]
fn a_queue_outlives_its_last_write_by_sixty_days_and_no_longer() {
    let mut store = registered();
    store.write(&queue(), b"x".to_vec(), DAY).expect("writes");

    store.expire(DAY + 59 * DAY);
    assert_eq!(store.queue_count(), 1);

    store.expire(DAY + 61 * DAY);
    assert_eq!(store.queue_count(), 0);
    assert!(store.registration(&queue()).is_none());
}

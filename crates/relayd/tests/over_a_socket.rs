//! The daemon, over a real socket.
//!
//! Everything that decides is tested in `onestein-relay` without a network.
//! What is tested here is the part that cannot be: that bytes go in and out
//! of a TCP connection in the framing the specification names, and that two
//! parties who have never shared anything but a root key can hand a blob to
//! each other through a relay that reads none of it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use onestein_relay::{
    Direction, QueueKeys, Request, Response, Right, blob_id, decode_response, encode_request,
    queue_id,
};
use onestein_relayd::{Shared, serve};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const RELAY: &str = "relay.example";

/// Starts a daemon on a port the operating system picks.
fn start() -> (String, Arc<Mutex<Shared>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
    let address = listener.local_addr().expect("has an address").to_string();
    let shared = Arc::new(Mutex::new(Shared::new()));
    let served = Arc::clone(&shared);
    std::thread::spawn(move || serve(&listener, &served));
    (address, shared)
}

fn ask(stream: &mut TcpStream, request: &Request) -> Vec<u8> {
    let encoded = encode_request(request).expect("encodes");
    stream.write_all(&encoded).expect("writes");
    stream.flush().expect("flushes");

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("reads a header");
    let length = usize::from(u16::from_be_bytes([
        header.get(2).copied().unwrap_or(0),
        header.get(3).copied().unwrap_or(0),
    ]));
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).expect("reads a payload");
    let mut reply = header.to_vec();
    reply.extend_from_slice(&payload);
    reply
}

#[test]
fn a_blob_crosses_a_relay_that_never_reads_it() {
    let (address, shared) = start();
    let queue = queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7);
    let keys = QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 7);
    let registration = keys.registration();

    // The writer registers and puts a blob in.
    let mut writer = TcpStream::connect(&address).expect("connects");
    let reply = ask(
        &mut writer,
        &Request::Register {
            queue_id: queue,
            write_public: registration.write_public,
            read_public: registration.read_public,
        },
    );
    assert_eq!(decode_response(&reply), Ok(Response::Ok));

    let reply = ask(
        &mut writer,
        &Request::ChallengeRequest {
            queue_id: queue,
            right: Right::Write,
        },
    );
    let Ok(Response::Challenge(challenge)) = decode_response(&reply) else {
        return assert_eq!(reply, Vec::new(), "expected a challenge");
    };
    let proof = keys.prove(Right::Write, &challenge).expect("proves");
    let reply = ask(
        &mut writer,
        &Request::Write {
            queue_id: queue,
            proof,
            blob: b"ciphertext",
        },
    );
    assert_eq!(decode_response(&reply), Ok(Response::Ok));

    // The reader, on its own connection, takes it out and deletes it.
    let mut reader = TcpStream::connect(&address).expect("connects");
    let reply = ask(
        &mut reader,
        &Request::ChallengeRequest {
            queue_id: queue,
            right: Right::Read,
        },
    );
    let Ok(Response::Challenge(challenge)) = decode_response(&reply) else {
        return assert_eq!(reply, Vec::new(), "expected a challenge");
    };
    let proof = keys.prove(Right::Read, &challenge).expect("proves");
    let reply = ask(
        &mut reader,
        &Request::Read {
            queue_id: queue,
            proof,
        },
    );
    assert_eq!(
        decode_response(&reply),
        Ok(Response::Blob {
            blob_id: blob_id(b"ciphertext"),
            blob: b"ciphertext"
        })
    );

    let reply = ask(
        &mut reader,
        &Request::ChallengeRequest {
            queue_id: queue,
            right: Right::Read,
        },
    );
    let Ok(Response::Challenge(challenge)) = decode_response(&reply) else {
        return assert_eq!(reply, Vec::new(), "expected a challenge");
    };
    let proof = keys.prove(Right::Read, &challenge).expect("proves");
    let reply = ask(
        &mut reader,
        &Request::Delete {
            queue_id: queue,
            proof,
            blob_id: blob_id(b"ciphertext"),
        },
    );
    assert_eq!(decode_response(&reply), Ok(Response::Ok));

    assert_eq!(shared.lock().expect("not poisoned").queue_count(), 1);
}

// Two challenges from the same relay must differ, or the replay defence is a
// constant.
#[test]
fn every_challenge_is_new() {
    let (address, _shared) = start();
    let queue = queue_id(&ROOT_KEY, Direction::AToB, RELAY, 9);
    let registration = QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 9).registration();

    let mut stream = TcpStream::connect(&address).expect("connects");
    ask(
        &mut stream,
        &Request::Register {
            queue_id: queue,
            write_public: registration.write_public,
            read_public: registration.read_public,
        },
    );

    let mut seen = Vec::new();
    for _ in 0..3 {
        let reply = ask(
            &mut stream,
            &Request::ChallengeRequest {
                queue_id: queue,
                right: Right::Write,
            },
        );
        if let Ok(Response::Challenge(challenge)) = decode_response(&reply) {
            assert!(!seen.contains(&challenge), "a challenge came round twice");
            seen.push(challenge);
        }
    }
    assert_eq!(seen.len(), 3);
}

// Nonsense on the wire closes the conversation and leaves the relay standing.
#[test]
fn a_connection_that_talks_rubbish_is_dropped_and_nothing_else() {
    let (address, shared) = start();
    let mut rude = TcpStream::connect(&address).expect("connects");
    rude.write_all(&[0xff; 64]).expect("writes");
    drop(rude);

    let queue = queue_id(&ROOT_KEY, Direction::AToB, RELAY, 11);
    let registration = QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 11).registration();
    let mut polite = TcpStream::connect(&address).expect("connects");
    let reply = ask(
        &mut polite,
        &Request::Register {
            queue_id: queue,
            write_public: registration.write_public,
            read_public: registration.read_public,
        },
    );
    assert_eq!(decode_response(&reply), Ok(Response::Ok));
    assert_eq!(shared.lock().expect("not poisoned").queue_count(), 1);
}

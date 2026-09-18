//! The relay's records, and the handler behind them.
//!
//! Spec: `spec/60-relay.md` §4a.

use onestein_relay::{
    Challenges, Direction, QueueKeys, Refusal, Request, Response, Right, Store, blob_id,
    decode_request, decode_response, encode_request, encode_response, handle, queue_id,
};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const RELAY: &str = "relay.example";
const CHALLENGE: [u8; 32] = [0x31; 32];

fn queue() -> [u8; 32] {
    queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7)
}

fn keys() -> QueueKeys {
    QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 7)
}

#[test]
fn every_request_and_response_round_trips() {
    let registration = keys().registration();
    let requests = [
        Request::Register {
            queue_id: queue(),
            write_public: registration.write_public,
            read_public: registration.read_public,
        },
        Request::ChallengeRequest {
            queue_id: queue(),
            right: Right::Read,
        },
        Request::Write {
            queue_id: queue(),
            proof: [0x11; 64],
            blob: b"ciphertext",
        },
        Request::Read {
            queue_id: queue(),
            proof: [0x22; 64],
        },
        Request::Delete {
            queue_id: queue(),
            proof: [0x33; 64],
            blob_id: blob_id(b"ciphertext"),
        },
    ];
    for request in requests {
        let encoded = encode_request(&request).expect("encodes");
        assert_eq!(decode_request(&encoded), Ok(request));
    }

    let responses = [
        Response::Challenge(CHALLENGE),
        Response::Blob {
            blob_id: blob_id(b"ciphertext"),
            blob: b"ciphertext",
        },
        Response::Ok,
        Response::Empty,
        Response::Refused(Refusal::QueueFull),
    ];
    for response in responses {
        let encoded = encode_response(&response).expect("encodes");
        assert_eq!(decode_response(&encoded), Ok(response));
    }
}

#[test]
fn garbage_is_refused_rather_than_guessed_at() {
    assert!(decode_request(b"").is_err());
    assert!(decode_request(&[9, 9, 9, 9]).is_err());
    // Right version, known type, payload one byte short.
    let short = onestein_record::encode(1, 4, &[0u8; 95]).expect("frames");
    assert!(decode_request(&short).is_err());
}

/// A relay that has taken the queue's public keys.
fn relay() -> (Store, Challenges) {
    let mut store = Store::new();
    let mut challenges = Challenges::new();
    let registration = keys().registration();
    let request = Request::Register {
        queue_id: queue(),
        write_public: registration.write_public,
        read_public: registration.read_public,
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &request, 0, CHALLENGE),
        Response::Ok
    );
    (store, challenges)
}

#[test]
fn a_write_needs_a_challenge_and_a_proof() {
    let (mut store, mut challenges) = relay();

    // Without a challenge outstanding there is nothing to prove against.
    let blind = Request::Write {
        queue_id: queue(),
        proof: [0u8; 64],
        blob: b"ciphertext",
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &blind, 0, CHALLENGE),
        Response::Refused(Refusal::UnknownChallenge)
    );

    let ask = Request::ChallengeRequest {
        queue_id: queue(),
        right: Right::Write,
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &ask, 0, CHALLENGE),
        Response::Challenge(CHALLENGE)
    );

    let proof = keys().prove(Right::Write, &CHALLENGE).expect("proves");
    let write = Request::Write {
        queue_id: queue(),
        proof,
        blob: b"ciphertext",
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &write, 0, CHALLENGE),
        Response::Ok
    );
}

// "A challenge is good once: it is taken out the moment it is used, whether
// the proof was good or not." Otherwise an attacker grinds against one
// challenge until something verifies.
#[test]
fn a_challenge_is_spent_even_by_a_bad_proof() {
    let (mut store, mut challenges) = relay();
    let ask = Request::ChallengeRequest {
        queue_id: queue(),
        right: Right::Write,
    };
    handle(&mut store, &mut challenges, &ask, 0, CHALLENGE);

    let wrong = Request::Write {
        queue_id: queue(),
        proof: [0xff; 64],
        blob: b"ciphertext",
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &wrong, 0, CHALLENGE),
        Response::Refused(Refusal::BadProof)
    );

    // The good proof for that challenge is now worthless.
    let proof = keys().prove(Right::Write, &CHALLENGE).expect("proves");
    let late = Request::Write {
        queue_id: queue(),
        proof,
        blob: b"ciphertext",
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &late, 0, CHALLENGE),
        Response::Refused(Refusal::UnknownChallenge)
    );
}

// A write proof must not open a read.
#[test]
fn a_challenge_belongs_to_one_right() {
    let (mut store, mut challenges) = relay();
    let ask = Request::ChallengeRequest {
        queue_id: queue(),
        right: Right::Write,
    };
    handle(&mut store, &mut challenges, &ask, 0, CHALLENGE);

    let proof = keys().prove(Right::Write, &CHALLENGE).expect("proves");
    let read = Request::Read {
        queue_id: queue(),
        proof,
    };
    assert_eq!(
        handle(&mut store, &mut challenges, &read, 0, CHALLENGE),
        Response::Refused(Refusal::UnknownChallenge)
    );
}

#[test]
fn a_blob_written_comes_back_and_then_can_be_deleted() {
    let (mut store, mut challenges) = relay();

    let write_proof = {
        let ask = Request::ChallengeRequest {
            queue_id: queue(),
            right: Right::Write,
        };
        handle(&mut store, &mut challenges, &ask, 0, CHALLENGE);
        keys().prove(Right::Write, &CHALLENGE).expect("proves")
    };
    handle(
        &mut store,
        &mut challenges,
        &Request::Write {
            queue_id: queue(),
            proof: write_proof,
            blob: b"ciphertext",
        },
        0,
        CHALLENGE,
    );

    let read_proof = {
        let ask = Request::ChallengeRequest {
            queue_id: queue(),
            right: Right::Read,
        };
        handle(&mut store, &mut challenges, &ask, 0, CHALLENGE);
        keys().prove(Right::Read, &CHALLENGE).expect("proves")
    };
    let response = handle(
        &mut store,
        &mut challenges,
        &Request::Read {
            queue_id: queue(),
            proof: read_proof,
        },
        0,
        CHALLENGE,
    );
    assert_eq!(
        response,
        Response::Blob {
            blob_id: blob_id(b"ciphertext"),
            blob: b"ciphertext"
        }
    );
}

#[test]
fn an_empty_queue_says_so() {
    let (mut store, mut challenges) = relay();
    let ask = Request::ChallengeRequest {
        queue_id: queue(),
        right: Right::Read,
    };
    handle(&mut store, &mut challenges, &ask, 0, CHALLENGE);
    let proof = keys().prove(Right::Read, &CHALLENGE).expect("proves");

    assert_eq!(
        handle(
            &mut store,
            &mut challenges,
            &Request::Read {
                queue_id: queue(),
                proof
            },
            0,
            CHALLENGE
        ),
        Response::Empty
    );
}

#[test]
fn an_unknown_queue_is_refused_before_anything_else() {
    let (mut store, mut challenges) = relay();
    let stranger = [0x99; 32];
    assert_eq!(
        handle(
            &mut store,
            &mut challenges,
            &Request::ChallengeRequest {
                queue_id: stranger,
                right: Right::Write
            },
            0,
            CHALLENGE
        ),
        Response::Refused(Refusal::UnknownQueue)
    );
}

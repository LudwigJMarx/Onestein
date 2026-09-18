//! Reordering windows.
//!
//! Spec: `spec/20-transport.md` §7.

use onestein_transport::{
    PeriodKeys, Role, StreamCounter, TOR, WINDOW_LEN, Window, WindowError, tag,
};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const TIMESTAMP_MS: u64 = 700 * 90_000 * 1_000 + 1;

fn tag_key() -> [u8; 32] {
    PeriodKeys::initial(&ROOT_KEY, &TOR, Role::A, TIMESTAMP_MS)
        .expect("derives")
        .incoming
        .tag_key
}

// The floor of 32 is a property of the constant and is asserted at compile
// time in the crate. What a test can show is where the window starts.
#[test]
fn a_fresh_window_starts_empty() {
    assert_eq!(Window::new().base(), 0);
    assert_eq!(Window::new().seen(), 0);
    assert!(!Window::new().is_seen(0));
}

#[test]
fn an_unseen_tag_inside_the_window_is_accepted_once() {
    let mut window = Window::new();
    assert!(!window.is_seen(5));
    assert_eq!(window.mark_seen(5), Ok(()));
    assert!(window.is_seen(5));
}

// A tag seen twice is a replayed stream, which is the thing the window exists
// to refuse.
#[test]
fn the_same_tag_twice_is_refused() {
    let mut window = Window::new();
    window.mark_seen(5).expect("first time");
    assert_eq!(
        window.mark_seen(5),
        Err(WindowError::AlreadySeen { stream_number: 5 })
    );
}

// "Slide the window until the lowest tag in the window is unseen."
#[test]
fn seeing_the_lowest_tag_slides_the_window_past_it() {
    let mut window = Window::new();
    window.mark_seen(0).expect("accepted");
    assert_eq!(window.base(), 1);
    assert!(!window.is_seen(0));
}

#[test]
fn a_contiguous_run_slides_the_window_to_its_end() {
    let mut window = Window::new();
    for number in 0..10 {
        window.mark_seen(number).expect("accepted");
    }
    assert_eq!(window.base(), 10);
    assert_eq!(window.seen(), 0);
}

// A gap holds the window where it is: the missing stream may still arrive.
#[test]
fn a_gap_keeps_the_window_in_place() {
    let mut window = Window::new();
    window.mark_seen(1).expect("accepted");
    window.mark_seen(2).expect("accepted");
    assert_eq!(window.base(), 0);
    assert!(window.is_seen(1));
    assert_eq!(window.mark_seen(0), Ok(()));
    assert_eq!(window.base(), 3);
}

// "Slide the window until all tags in the top half of the window are unseen."
#[test]
fn a_tag_in_the_top_half_slides_the_window() {
    let mut window = Window::new();
    let first_of_top_half = WINDOW_LEN / 2;
    window.mark_seen(first_of_top_half).expect("accepted");
    assert_eq!(window.base(), 1);
    assert!(window.is_seen(first_of_top_half));
}

// "If the window slides past a tag that has not been seen, the recipient can
// no longer recognise the corresponding stream."
#[test]
fn a_tag_the_window_has_passed_is_refused() {
    let mut window = Window::new();
    window.mark_seen(0).expect("accepted");
    assert_eq!(
        window.mark_seen(0),
        Err(WindowError::AlreadyPassed {
            stream_number: 0,
            base: 1
        })
    );
}

#[test]
fn a_tag_beyond_the_window_is_refused() {
    let mut window = Window::new();
    assert_eq!(
        window.mark_seen(WINDOW_LEN),
        Err(WindowError::OutsideWindow {
            stream_number: WINDOW_LEN,
            limit: WINDOW_LEN
        })
    );
    assert!(window.mark_seen(WINDOW_LEN - 1).is_ok());
}

// The caller stores two numbers and hands them back. Nothing else is state.
#[test]
fn a_window_survives_being_stored_and_restored() {
    let mut window = Window::new();
    window.mark_seen(3).expect("accepted");
    window.mark_seen(7).expect("accepted");
    let restored = Window::restore(window.base(), window.seen());
    assert_eq!(restored, window);
    assert!(restored.is_seen(3));
    assert!(restored.is_seen(7));
}

// The tags a recipient watches for are exactly the window's numbers under the
// incoming tag key.
#[test]
fn the_expected_tags_are_the_windows_numbers() {
    let key = tag_key();
    let mut window = Window::new();
    window.mark_seen(0).expect("accepted");

    let expected: Vec<(u64, [u8; 16])> = window.expected(&key).collect();
    assert_eq!(expected.len(), WINDOW_LEN as usize);
    assert_eq!(expected.first(), Some(&(1, tag(&key, 1))));
    assert_eq!(expected.last(), Some(&(WINDOW_LEN, tag(&key, WINDOW_LEN))));
}

// "the sender must persistently store the number of streams sent to the
// recipient in the current time period"
#[test]
fn the_stream_counter_never_repeats_a_number() {
    let mut counter = StreamCounter::new();
    assert_eq!(counter.peek(), 0);
    assert_eq!(counter.take(), Ok(0));
    assert_eq!(counter.take(), Ok(1));
    assert_eq!(counter.peek(), 2);

    let restored = StreamCounter::restore(counter.peek());
    assert_eq!(restored.peek(), 2);
}

#[test]
fn the_stream_counter_stops_rather_than_wrapping() {
    let mut counter = StreamCounter::restore(u64::MAX);
    assert_eq!(counter.take(), Ok(u64::MAX));
    assert!(counter.take().is_err());
}

//! Invariants the runtime depends on, tested in isolation.
//!
//! These exist because a shutdown bug hid behind a passing test suite: the runtime
//! returned `Ok(())` whether workers stopped promptly or only when the drain budget
//! expired. If any of these primitives misbehave, the accept loop cannot observe
//! shutdown at all, so they are worth asserting directly.

use std::net::TcpListener as StdListener;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;
use mio::{Events, Interest, Poll, Token, Waker};

#[test]
fn poll_honours_its_timeout_with_no_registered_sources() {
    let mut poll = Poll::new().expect("poll");
    let mut events = Events::with_capacity(16);

    let started = Instant::now();
    poll.poll(&mut events, Some(Duration::from_millis(100)))
        .expect("poll");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "poll blocked for {elapsed:?} despite a 100ms timeout"
    );
}

#[test]
fn poll_honours_its_timeout_with_a_listener_registered() {
    let std_listener = StdListener::bind("127.0.0.1:0").expect("bind");
    let mut listener = MioListener::from_std(std_listener);

    let mut poll = Poll::new().expect("poll");
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .expect("register");

    let mut events = Events::with_capacity(16);
    let started = Instant::now();
    poll.poll(&mut events, Some(Duration::from_millis(100)))
        .expect("poll");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "poll blocked for {elapsed:?} with an idle listener registered"
    );
}

#[test]
fn a_waker_unblocks_a_poll_waiting_indefinitely() {
    let mut poll = Poll::new().expect("poll");
    let waker = Waker::new(poll.registry(), Token(1)).expect("waker");

    let started = Instant::now();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        waker.wake().expect("wake");
    });

    let mut events = Events::with_capacity(16);
    // `None` means "wait forever": only the waker can end this.
    poll.poll(&mut events, None).expect("poll");
    let elapsed = started.elapsed();

    handle.join().expect("waker thread");
    assert!(
        elapsed < Duration::from_secs(2),
        "waker did not unblock poll ({elapsed:?})"
    );
}

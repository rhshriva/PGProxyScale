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
fn a_live_waker_unblocks_a_poll_before_its_watchdog() {
    let mut poll = Poll::new().expect("poll");
    let waker = std::sync::Arc::new(Waker::new(poll.registry(), Token(1)).expect("waker"));
    let thread_waker = std::sync::Arc::clone(&waker);

    let started = Instant::now();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        thread_waker.wake().expect("wake");
    });

    let mut events = Events::with_capacity(16);
    // Keep the registered waker alive until polling completes. On Linux, closing
    // its eventfd before epoll consumes the wake can remove the pending event.
    // A finite watchdog turns a missing wake into a failing test, never a hung suite.
    poll.poll(&mut events, Some(Duration::from_secs(2)))
        .expect("poll");
    assert!(
        events.iter().any(|event| event.token() == Token(1)),
        "waker event missing"
    );
    let elapsed = started.elapsed();

    handle.join().expect("waker thread");
    assert!(
        elapsed < Duration::from_secs(2),
        "waker did not unblock poll ({elapsed:?})"
    );
}

//! The loop around a driver: step, then sleep until a datagram may be waiting
//! or the step's deadline comes, whichever is first.
//!
//! One loop runs one driver on the calling thread. A server with a shard per
//! core runs one per thread, each over its own socket from
//! `linux::bind_group`, and the threads share nothing.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hex_net_core::{
    connector::State,
    time::{Clock, Timestamp},
};

use crate::{
    Socket, Wait, Wake,
    driver::{ClientApp, ClientDriver, ServerApp, ServerDriver},
};

/// Asks a loop on another thread to return.
#[derive(Clone)]
pub struct Stopper<W> {
    requested: Arc<AtomicBool>,
    waker: W,
}

impl<W: Wake> Stopper<W> {
    /// The loop returns after the step in progress, or at once if it is
    /// waiting.
    pub fn stop(&self) -> io::Result<()> {
        self.requested.store(true, Ordering::Release);
        self.waker.wake()
    }
}

/// What a loop checks between steps.
pub struct StopSignal {
    requested: Arc<AtomicBool>,
}

impl StopSignal {
    #[inline]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// A stopper and the signal it raises. `waker` must wake the socket the loop
/// waits on.
pub fn stop_pair<W: Wake>(waker: W) -> (Stopper<W>, StopSignal) {
    let requested = Arc::new(AtomicBool::new(false));
    (
        Stopper { requested: Arc::clone(&requested), waker },
        StopSignal { requested },
    )
}

/// Runs a server until `stop` is raised. Connections are left as they are:
/// `shutdown_server` closes them.
pub fn run_server<S, A, C>(driver: &mut ServerDriver<S>, app: &mut A, clock: &C, stop: &StopSignal) -> io::Result<()>
where
    S: Socket + Wait,
    A: ServerApp,
    C: Clock,
{
    while !stop.is_requested() {
        let deadline = driver.step(clock.now(), app)?;
        pause(driver.socket(), clock, deadline)?;
    }
    Ok(())
}

/// Closes every connection with a notice and keeps stepping until they have
/// all been retired or `linger` has passed, so the notices go out.
pub fn shutdown_server<S, A, C>(
    driver: &mut ServerDriver<S>,
    app: &mut A,
    clock: &C,
    linger: Duration,
) -> io::Result<()>
where
    S: Socket + Wait,
    A: ServerApp,
    C: Clock,
{
    driver.endpoint_mut().shutdown();
    let give_up = clock.now().saturating_add(linger);
    loop {
        let deadline = driver.step(clock.now(), app)?;
        if driver.endpoint().is_empty() || (clock.now() >= give_up) {
            return Ok(());
        }
        pause(
            driver.socket(),
            clock,
            Some(deadline.map_or(give_up, |at| at.min(give_up))),
        )?;
    }
}

/// Runs a client until its connection attempt fails, its connection closes,
/// or `stop` is raised. Returns the connector's state at that point.
pub fn run_client<S, A, C>(driver: &mut ClientDriver<S>, app: &mut A, clock: &C, stop: &StopSignal) -> io::Result<State>
where
    S: Socket + Wait,
    A: ClientApp,
    C: Clock,
{
    loop {
        let deadline = driver.step(clock.now(), app)?;
        let state = driver.connector().state();
        if ended(state) || stop.is_requested() {
            return Ok(state);
        }
        pause(driver.socket(), clock, deadline)?;
    }
}

/// Closes a client's connection with a notice and keeps stepping until it has
/// closed or `linger` has passed. Returns the state it finished in.
pub fn close_client<S, A, C>(
    driver: &mut ClientDriver<S>,
    app: &mut A,
    clock: &C,
    linger: Duration,
) -> io::Result<State>
where
    S: Socket + Wait,
    A: ClientApp,
    C: Clock,
{
    driver.connector_mut().close();
    let give_up = clock.now().saturating_add(linger);
    loop {
        let deadline = driver.step(clock.now(), app)?;
        let state = driver.connector().state();
        if ended(state) || (clock.now() >= give_up) {
            return Ok(state);
        }
        pause(
            driver.socket(),
            clock,
            Some(deadline.map_or(give_up, |at| at.min(give_up))),
        )?;
    }
}

#[inline]
fn ended(state: State) -> bool {
    matches!(state, State::Failed(_) | State::Closed(_))
}

/// Waits until `deadline`, or until the socket may have something to read.
/// Returns at once for a deadline already due, and waits without limit for
/// none.
fn pause(socket: &impl Wait, clock: &impl Clock, deadline: Option<Timestamp>) -> io::Result<()> {
    let timeout = match deadline {
        None => None,
        Some(at) => {
            let now = clock.now();
            if at <= now {
                return Ok(());
            }
            Some(at.saturating_since(now))
        }
    };
    socket.wait(timeout)
}

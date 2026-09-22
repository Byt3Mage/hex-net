//! The loop around a driver: step, then sleep until a datagram may be waiting
//! or the step's deadline comes, whichever is first. A server's steps are
//! also spaced by its step interval, so arrivals gather into batches.
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

/// Runs one server step at `clock`'s current time, then waits until the next
/// is due: the step's deadline, or the first arrival once the driver's step
/// interval has passed since this step began.
///
/// `run_server` is this in a loop. A caller that needs to look at the driver
/// between steps, such as a benchmark reading its counters, loops over it
/// directly.
pub fn serve_step<S, A, C>(driver: &mut ServerDriver<S>, app: &mut A, clock: &C) -> io::Result<()>
where
    S: Socket + Wait,
    A: ServerApp,
    C: Clock,
{
    let started = clock.now();
    let deadline = driver.step(started, app)?;
    pause(
        driver.socket(),
        clock,
        deadline,
        started.saturating_add(driver.step_interval()),
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
        serve_step(driver, app, clock)?;
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
        let started = clock.now();
        let deadline = driver.step(started, app)?;
        if driver.endpoint().is_empty() || (clock.now() >= give_up) {
            return Ok(());
        }
        pause(
            driver.socket(),
            clock,
            Some(deadline.map_or(give_up, |at| at.min(give_up))),
            started.saturating_add(driver.step_interval()),
        )?;
    }
}

/// Runs a client until its connection attempt fails, its connection closes,
/// or `stop` is raised. Returns the connector's state at that point.
///
/// A client steps on every arrival: it has one peer, so there is nothing to
/// batch.
pub fn run_client<S, A, C>(driver: &mut ClientDriver<S>, app: &mut A, clock: &C, stop: &StopSignal) -> io::Result<State>
where
    S: Socket + Wait,
    A: ClientApp,
    C: Clock,
{
    loop {
        let started = clock.now();
        let deadline = driver.step(started, app)?;
        let state = driver.connector().state();
        if ended(state) || stop.is_requested() {
            return Ok(state);
        }
        pause(driver.socket(), clock, deadline, started)?;
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
        let started = clock.now();
        let deadline = driver.step(started, app)?;
        let state = driver.connector().state();
        if ended(state) || (clock.now() >= give_up) {
            return Ok(state);
        }
        pause(
            driver.socket(),
            clock,
            Some(deadline.map_or(give_up, |at| at.min(give_up))),
            started,
        )?;
    }
}

#[inline]
fn ended(state: State) -> bool {
    matches!(state, State::Failed(_) | State::Closed(_))
}

/// Waits until `deadline`, or until the socket may have something to read,
/// but reads nothing before `not_before`. Returns at once for a deadline
/// already due, and waits without limit for none.
///
/// Before `not_before` only the waker and the deadline end the wait, so
/// datagrams gather in the kernel meanwhile. A wake ends it at once, since it
/// may be a stop request.
fn pause(socket: &impl Wait, clock: &impl Clock, deadline: Option<Timestamp>, not_before: Timestamp) -> io::Result<()> {
    let now = clock.now();
    if deadline.is_some_and(|at| at <= now) {
        return Ok(());
    }

    if now < not_before {
        let until = deadline.map_or(not_before, |at| at.min(not_before));
        if socket.park(until.saturating_since(now))? {
            return Ok(());
        }
    }

    let now = clock.now();
    let timeout = match deadline {
        None => None,
        Some(at) if at <= now => return Ok(()),
        Some(at) => Some(at.saturating_since(now)),
    };
    socket.wait(timeout)
}

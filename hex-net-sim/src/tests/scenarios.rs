//! Scripted disruptions: crashes, clean closes, rebinding addresses, resumed
//! sessions, a degrading path, and a server going down.

use std::time::Duration;

use hex_net_core::channel::{ChannelKind, ChannelSet};
use hex_net_core::connection::CloseReason;
use hex_net_core::connector::State;

use crate::net::{Burst, Link};
use crate::scenario::{Chatter, Echo, Pace, assert_clean};
use crate::world::World;

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

const SEND_INTERVAL: Duration = Duration::from_millis(50);

/// Long enough that the whole exchange straddles whatever happens mid-run.
const TOTAL: u32 = 100;

/// The transport gives up on silence after ten seconds; a suspended session
/// lasts another forty-five.
const PAST_IDLE_TIMEOUT: Duration = Duration::from_secs(12);
const PAST_RESUME_GRACE: Duration = Duration::from_secs(50);

fn link() -> Link {
    Link::clean(Duration::from_millis(25))
}

fn world(seed: u64, clients: usize, total: u32) -> World<Echo, Chatter> {
    let mut world = World::new(seed, 64, ORDERED, Echo::default());
    for index in 0..clients {
        world.add_client(link(), link(), Chatter::new(index, total, SEND_INTERVAL));
    }
    world
}

#[test]
fn a_crashed_client_leaves_a_suspended_session_that_later_expires() {
    let mut world = world(20, 1, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");
    let session = world.server_app().sessions[0];

    world.crash_client(0);
    world.run_for(PAST_IDLE_TIMEOUT).expect("progress");

    let endings = world.server_app().endings.clone();
    assert_eq!(endings.len(), 1, "{endings:?}");
    assert_eq!(endings[0].reason, CloseReason::TimedOut);
    assert!(endings[0].suspended, "a crash holds the player's place");
    assert_eq!(world.server().endpoint().num_connections(), 0);
    assert!(world.server_app().expired.is_empty(), "the grace period has not lapsed");

    world.run_for(PAST_RESUME_GRACE).expect("progress");
    assert_eq!(world.server_app().expired, vec![session]);
}

#[test]
fn a_clean_close_ends_the_session_at_once() {
    let mut world = world(21, 1, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");

    world.close_client(0);
    world.run_for(Duration::from_secs(2)).expect("progress");

    let endings = world.server_app().endings.clone();
    assert_eq!(endings.len(), 1, "{endings:?}");
    assert_eq!(endings[0].reason, CloseReason::Requested);
    assert!(!endings[0].suspended, "a deliberate quit keeps no place");
    assert_eq!(world.server().endpoint().num_connections(), 0);

    world.run_for(PAST_RESUME_GRACE).expect("progress");
    assert!(world.server_app().expired.is_empty(), "the session is already gone");
}

#[test]
fn a_rebound_address_keeps_the_connection_and_is_reported() {
    let mut world = world(22, 1, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");

    let new_addr = world.rebind_client(0);
    world.run_for(Duration::from_secs(20)).expect("progress");

    assert_eq!(world.server_app().migrations, vec![new_addr]);
    assert_clean(&world, TOTAL);
}

#[test]
fn a_reconnect_takes_the_session_from_the_live_connection() {
    let mut world = world(23, 1, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");
    let session = world.server_app().sessions[0];

    // Relaunching before the server noticed anything was wrong: the old
    // connection is still live and must give up the session.
    world.reconnect_client(0, session, Chatter::new(0, TOTAL, SEND_INTERVAL));
    world.run_for(Duration::from_secs(20)).expect("progress");

    assert_eq!(world.server_app().resumed, 1);
    assert_eq!(world.server_app().sessions, vec![session, session]);

    let endings = world.server_app().endings.clone();
    assert_eq!(endings.len(), 1, "{endings:?}");
    assert_eq!(endings[0].reason, CloseReason::Replaced);
    assert!(!endings[0].suspended, "the session moved rather than lapsed");

    assert_eq!(world.server().endpoint().num_connections(), 1);
    assert_eq!(world.client(0).connector().state(), State::Connected);
    assert!(world.server_app().expired.is_empty());

    // The new connection numbers its stream from zero again, so the server's
    // record ends with the whole of it, preceded by whatever the old
    // connection had already delivered.
    let expected: Vec<u32> = (0..TOTAL).collect();
    let received = world.server_app().received[&0].clone();
    assert!(received.len() >= expected.len(), "{} entries", received.len());
    assert_eq!(&received[(received.len() - expected.len())..], expected.as_slice());
    assert_eq!(world.client_app(0).echoes, expected);
}

#[test]
fn a_crashed_client_resumes_within_the_grace_period() {
    let mut world = world(24, 1, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");
    let session = world.server_app().sessions[0];

    world.crash_client(0);
    world.run_for(PAST_IDLE_TIMEOUT).expect("progress");
    assert_eq!(world.server().endpoint().num_connections(), 0);

    world.reconnect_client(0, session, Chatter::new(0, TOTAL, SEND_INTERVAL));
    world.run_for(Duration::from_secs(20)).expect("progress");

    assert_eq!(world.server_app().resumed, 1);
    assert_eq!(world.server().endpoint().num_connections(), 1);
    assert_eq!(world.client(0).connector().state(), State::Connected);
    assert_eq!(world.client_app(0).echoes, (0..TOTAL).collect::<Vec<u32>>());

    world.run_for(PAST_RESUME_GRACE).expect("progress");
    assert!(
        world.server_app().expired.is_empty(),
        "the session was reclaimed, not abandoned"
    );
}

#[test]
fn a_server_shutdown_ends_every_client() {
    let mut world = world(25, 5, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");

    world.shutdown_server();
    world.run_for(Duration::from_secs(5)).expect("progress");

    assert_eq!(world.server().endpoint().num_connections(), 0);
    let endings = world.server_app().endings.clone();
    assert_eq!(endings.len(), 5, "{endings:?}");
    for ending in endings {
        assert_eq!(ending.reason, CloseReason::ServerShutdown);
        assert!(!ending.suspended, "nothing to come back to");
    }
    for index in 0..5 {
        assert_eq!(
            world.client(index).connector().state(),
            State::Closed(CloseReason::ServerShutdown),
            "client {index}"
        );
    }
}

#[test]
fn a_path_that_degrades_mid_run_still_delivers_everything() {
    let hostile = Link {
        latency: Duration::from_millis(90),
        jitter: Duration::from_millis(60),
        loss: 0.15,
        burst: Some(Burst { enter: 0.03, leave: 0.2, loss: 0.8 }),
        duplicate: 0.02,
    };

    let mut world = world(26, 4, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");
    for index in 0..4 {
        world.set_links(index, hostile, hostile);
    }
    world.run_for(Duration::from_secs(60)).expect("progress");

    assert!(world.wire_stats().lost > 0);
    assert_clean(&world, TOTAL);
}

/// A total blackout swallows a message and the probes that follow it. Once
/// the link returns, the probe itself carries the message, so recovery costs
/// the probe timeout rather than the probe timeout plus another round trip.
#[test]
fn a_message_lost_in_a_blackout_rides_the_probe_back() {
    let clean = Link::clean(Duration::from_millis(50));
    let blackout = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        loss: 1.0,
        burst: None,
        duplicate: 0.0,
    };

    // Two messages a second and a half apart: the first settles, the second
    // is sent into the blackout.
    let pace = Pace::steady(Duration::from_millis(1500));
    let mut world = World::new(27, 8, ORDERED, Echo::default());
    world.add_client(clean, clean, Chatter::paced(0, 2, pace));

    world.run_for(Duration::from_millis(1200)).expect("progress");
    world.set_links(0, blackout, blackout);
    world.run_for(Duration::from_millis(800)).expect("progress");
    world.set_links(0, clean, clean);
    world.run_for(Duration::from_secs(5)).expect("progress");

    let round_trips = world.client_app(0).round_trips.clone();
    assert_eq!(round_trips.len(), 2, "{round_trips:?}");
    let (seq, elapsed) = round_trips[1];
    assert_eq!(seq, 1);
    // 525 ms: the probe timeout, the outage, and one trip back. Without the
    // probe carrying the message it is a round trip more.
    assert!(
        elapsed < Duration::from_millis(600),
        "recovery took {elapsed:?}, which is a probe timeout plus a wasted round trip"
    );
}

/// A ticket for one player that names another player's session is refused,
/// and the session's owner is left untouched.
#[test]
fn a_ticket_cannot_resume_another_players_session() {
    let mut world = world(28, 2, TOTAL);
    world.run_for(Duration::from_secs(2)).expect("progress");
    let session = world.server_app().sessions[0];

    // Client 1 relaunches with a ticket naming client 0's session.
    world.reconnect_client(1, session, Chatter::new(1, TOTAL, SEND_INTERVAL));
    world.run_for(Duration::from_secs(20)).expect("progress");

    assert_eq!(world.server_app().resumed, 0, "the session was not handed over");
    assert_ne!(world.client(1).connector().state(), State::Connected);

    // Client 1's own earlier connection went silent when it relaunched, so it
    // times out; nothing may happen to client 0's session.
    let endings = world.server_app().endings.clone();
    assert!(endings.iter().all(|ending| ending.session != session), "{endings:?}");

    assert_eq!(world.client(0).connector().state(), State::Connected);
    assert_eq!(world.client_app(0).echoes, (0..TOTAL).collect::<Vec<u32>>());
}

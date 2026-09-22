//! Many clients over imperfect links, driven by the deadlines each node
//! reports, with every run checked against the delivery guarantees.

use hex_net_core::{
    channel::{ChannelKind, ChannelSet},
    connector::State,
    time::Span,
};

use crate::{
    net::{Burst, Link},
    scenario::{Chatter, Echo, assert_clean, check},
    world::World,
};

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

const SEND_INTERVAL: Span = Span::from_millis(33);

/// Ordinary consumer conditions: some loss, some of it in runs, enough jitter
/// to reorder, and the occasional duplicate.
fn lossy() -> Link {
    Link {
        latency: Span::from_millis(40),
        jitter: Span::from_millis(30),
        loss: 0.03,
        burst: Some(Burst { enter: 0.01, leave: 0.3, loss: 0.6 }),
        duplicate: 0.01,
    }
}

/// A bad mobile link: long, wildly variable, and losing most of a burst.
fn hostile() -> Link {
    Link {
        latency: Span::from_millis(80),
        jitter: Span::from_millis(80),
        loss: 0.10,
        burst: Some(Burst { enter: 0.02, leave: 0.2, loss: 0.9 }),
        duplicate: 0.05,
    }
}

/// Short but erratic, as on congested wifi: reordering without much loss.
fn jittery() -> Link {
    Link {
        latency: Span::from_millis(5),
        jitter: Span::from_millis(40),
        loss: 0.01,
        burst: None,
        duplicate: 0.0,
    }
}

fn world(seed: u64, clients: usize, link: Link, total: u32) -> World<Echo, Chatter> {
    let mut world = World::new(seed, 256, ORDERED, Echo::default());
    for index in 0..clients {
        world.add_client(link, link, Chatter::new(index, total, SEND_INTERVAL));
    }
    world
}

#[test]
fn clients_on_clean_links_exchange_every_message_once_in_order() {
    let mut world = world(1, 20, Link::clean(Span::from_millis(25)), 40);
    world.run_for(Span::from_secs(10)).expect("the run made progress");

    assert_eq!(world.server_app().connected, 20);
    assert_eq!(world.wire_stats().lost, 0);
    assert_clean(&world, 40);
}

#[test]
fn clients_on_lossy_jittery_links_exchange_every_message_once_in_order() {
    let mut world = world(2, 20, lossy(), 40);
    world.run_for(Span::from_secs(60)).expect("the run made progress");

    let stats = world.wire_stats();
    assert!(stats.lost > 0, "the links lost something: {stats:?}");
    assert!(stats.duplicated > 0, "the links duplicated something: {stats:?}");
    assert_eq!(world.server_app().connected, 20);
    assert_clean(&world, 40);
}

/// The guarantees hold across many seeds, not just a lucky one. A failure
/// names the profile and the seed, which is all that is needed to replay it.
#[test]
fn the_guarantees_hold_across_seeds_and_link_profiles() {
    const CLIENTS: usize = 6;
    const TOTAL: u32 = 30;

    let profiles = [("lossy", lossy()), ("hostile", hostile()), ("jittery", jittery())];
    let mut failures = Vec::new();

    for (name, link) in profiles {
        for seed in 0..8u64 {
            let mut world = world(seed, CLIENTS, link, TOTAL);
            if let Err(stall) = world.run_for(Span::from_secs(45)) {
                failures.push(format!("{name}: {stall:?}"));
                continue;
            }
            for violation in check(&world, TOTAL) {
                failures.push(format!("{name} seed {seed}: {violation}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} failures:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn a_seed_replays_exactly() {
    let run = |seed| {
        let mut world = world(seed, 10, lossy(), 20);
        world.run_for(Span::from_secs(20)).expect("the run made progress");
        world.fingerprint()
    };
    assert_eq!(run(7), run(7), "the same seed took a different course");
    assert_ne!(run(7), run(8), "different seeds took the same course");
}

#[test]
fn many_idle_clients_stay_connected_on_keepalives() {
    let mut world = World::new(3, 256, ORDERED, Echo::default());
    for index in 0..200 {
        let latency = Span::from_millis(10 + ((index as u64) % 150));
        world.add_client(
            Link::clean(latency),
            Link::clean(latency),
            Chatter::new(index, 0, SEND_INTERVAL),
        );
    }
    world.run_for(Span::from_secs(30)).expect("the run made progress");

    assert_eq!(world.server().endpoint().num_connections(), 200);
    for index in 0..200 {
        assert_eq!(
            world.client(index).connector().state(),
            State::Connected,
            "client {index}"
        );
    }
    assert_clean(&world, 0);
}

/// Arrivals and departures in bulk are each reported once: a crowd that
/// connects in the same instant, drops together, and lets its sessions lapse
/// together produces as many events of each kind as there were players.
#[test]
fn a_crowd_arriving_and_leaving_together_is_reported_in_full() {
    const CLIENTS: usize = 200;
    let mut world = World::new(4, 256, ORDERED, Echo::default());
    for index in 0..CLIENTS {
        let link = Link::clean(Span::from_millis(20));
        world.add_client(link, link, Chatter::new(index, 0, SEND_INTERVAL));
    }
    world.run_for(Span::from_secs(5)).expect("the run made progress");
    assert_eq!(world.server().endpoint().num_connections(), CLIENTS);
    assert_eq!(world.server_app().connected, CLIENTS, "every arrival was reported");

    for index in 0..CLIENTS {
        world.crash_client(index);
    }
    world.run_for(Span::from_secs(120)).expect("the run made progress");

    let app = world.server_app();
    assert_eq!(world.server().endpoint().num_connections(), 0);
    assert_eq!(app.endings.len(), CLIENTS, "every departure was reported");
    assert!(
        app.endings.iter().all(|ending| ending.suspended),
        "a dropped player's session is held"
    );
    assert_eq!(app.expired.len(), CLIENTS, "every lapsed session was reported");
}

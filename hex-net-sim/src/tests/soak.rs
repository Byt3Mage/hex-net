//! Load: many players at once, on the mix of links a real population has.
//!
//! These runs measure rather than merely pass, and print their report, so a
//! change in throughput or latency shows up as numbers.

use hex_net_core::channel::{ChannelKind, ChannelSet};
use hex_net_core::time::Span;

use crate::net::{Burst, Link};
use crate::scenario::{Chatter, Echo, Pace, assert_clean, report};
use crate::world::World;

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

/// Bursts with quiet between them, as a game's chat, inventory, or ability
/// traffic behaves. The quiet is what makes the last message of each burst a
/// tail.
const PACE: Pace = Pace {
    interval: Span::from_millis(50),
    burst: Some(4),
    gap: Span::from_secs(1),
};

/// A third of players on each: a short clean link, ordinary consumer
/// conditions, and a bad mobile connection.
fn profile(index: usize) -> Link {
    match index % 3 {
        0 => Link::clean(Span::from_millis(20)),
        1 => Link {
            latency: Span::from_millis(40),
            jitter: Span::from_millis(30),
            loss: 0.03,
            burst: Some(Burst { enter: 0.01, leave: 0.3, loss: 0.6 }),
            duplicate: 0.01,
        },
        _ => Link {
            latency: Span::from_millis(80),
            jitter: Span::from_millis(80),
            loss: 0.08,
            burst: Some(Burst { enter: 0.02, leave: 0.2, loss: 0.8 }),
            duplicate: 0.02,
        },
    }
}

fn crowd(seed: u64, clients: usize, total: u32) -> World<Echo, Chatter> {
    let mut world = World::new(seed, 16_384, ORDERED, Echo::default());
    for index in 0..clients {
        let link = profile(index);
        world.add_client(link, link, Chatter::paced(index, total, PACE));
    }
    world
}

#[test]
fn a_crowd_of_players_is_served_without_loss() {
    const CLIENTS: usize = 250;
    const TOTAL: u32 = 20;
    let simulated = Span::from_secs(15);

    let mut world = crowd(30, CLIENTS, TOTAL);
    world.run_for(simulated).expect("the run made progress");

    let report = report(&world, simulated, TOTAL);
    println!("{report}");

    assert_clean(&world, TOTAL);
    assert!(
        report.bytes_per_connection < (report.budget as f64),
        "the server sent more than the budget allows"
    );
}

/// The full target: a thousand players at once. Slow in a debug build, so it
/// is run on request:
/// `cargo test --release -p hex-net-sim -- --ignored --nocapture`
#[test]
#[ignore = "takes about a minute unless built with --release"]
fn a_thousand_players_are_served_without_loss() {
    const CLIENTS: usize = 1000;
    const TOTAL: u32 = 40;
    let simulated = Span::from_secs(60);

    let mut world = crowd(31, CLIENTS, TOTAL);
    world.run_for(simulated).expect("the run made progress");

    let report = report(&world, simulated, TOTAL);
    println!("{report}");

    assert_clean(&world, TOTAL);
    assert!(
        report.bytes_per_connection < (report.budget as f64),
        "the server sent more than the budget allows"
    );
}

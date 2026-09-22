//! The timer heap: one deadline per slot, moved in place, served earliest
//! first.

use crate::{
    time::{Span, Timestamp},
    timer::TimerHeap,
};

fn at(ms: u64) -> Timestamp {
    Timestamp::ZERO.saturating_add(Span::from_millis(ms))
}

#[test]
fn deadlines_come_due_earliest_first_ties_by_slot() {
    let mut timers = TimerHeap::with_slots(4);
    timers.set(3, at(20));
    timers.set(1, at(10));
    timers.set(2, at(10));
    timers.set(0, at(30));

    assert_eq!(timers.pop_due(at(5)), None, "nothing is due yet");
    let order: Vec<u32> = std::iter::from_fn(|| timers.pop_due(at(100))).collect();
    assert_eq!(order, vec![1, 2, 3, 0]);
    assert!(timers.is_empty());
}

#[test]
fn a_moved_deadline_replaces_the_old_one() {
    let mut timers = TimerHeap::with_slots(2);
    timers.set(0, at(10));
    timers.set(1, at(20));

    timers.set(0, at(30));
    assert_eq!(timers.peek(), Some((at(20), 1)), "moved later, behind the other");
    timers.set(0, at(5));
    assert_eq!(timers.peek(), Some((at(5), 0)), "moved earlier, ahead of it");

    assert_eq!(timers.pop_due(at(100)), Some(0));
    assert_eq!(timers.pop_due(at(100)), Some(1));
    assert_eq!(timers.pop_due(at(100)), None, "a moved deadline leaves nothing behind");
}

#[test]
fn a_cancelled_deadline_never_comes_due() {
    let mut timers = TimerHeap::with_slots(3);
    timers.set(0, at(10));
    timers.set(1, at(20));
    timers.set(2, at(30));
    timers.cancel(1);
    timers.cancel(1);

    assert_eq!(timers.deadline(1), None);
    let order: Vec<u32> = std::iter::from_fn(|| timers.pop_due(at(100))).collect();
    assert_eq!(order, vec![0, 2]);
}

/// Random operations against the obvious model: an array of deadlines,
/// searched in full for the earliest.
#[test]
fn it_agrees_with_a_linear_scan() {
    const SLOTS: u32 = 64;
    let mut timers = TimerHeap::with_slots(SLOTS);
    let mut model: [Option<Timestamp>; SLOTS as usize] = [None; SLOTS as usize];

    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..20_000 {
        let slot = (next() % u64::from(SLOTS)) as u32;
        match next() % 4 {
            0 | 1 => {
                let deadline = at(next() % 1000);
                timers.set(slot, deadline);
                model[slot as usize] = Some(deadline);
            }
            2 => {
                timers.cancel(slot);
                model[slot as usize] = None;
            }
            _ => {
                let now = at(next() % 1000);
                let expected = model
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, deadline)| deadline.map(|deadline| (deadline, slot as u32)))
                    .filter(|&(deadline, _)| deadline <= now)
                    .min();
                let popped = timers.pop_due(now);
                assert_eq!(popped, expected.map(|(_, slot)| slot));
                if let Some(slot) = popped {
                    model[slot as usize] = None;
                }
            }
        }
        for (index, deadline) in model.iter().enumerate() {
            assert_eq!(timers.deadline(index as u32), *deadline, "slot {index}");
        }
    }
}

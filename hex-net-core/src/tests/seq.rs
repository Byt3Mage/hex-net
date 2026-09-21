//! Sequence arithmetic, the receive window, and the sequence ring.

use crate::seq::{ReceiveWindow, Sequence, SequenceBuffer, WindowError, WireSequence, reconstruct};

fn seq(n: u64) -> Sequence {
    Sequence::new(n).expect("nonzero literal")
}

#[test]
fn zero_is_not_a_sequence() {
    assert_eq!(Sequence::new(0), None);
    assert_eq!(Sequence::FIRST.checked_sub(1), None);
    assert_eq!(size_of::<Option<Sequence>>(), size_of::<u64>());
}

#[test]
fn resolution_picks_the_nearest_candidate_across_a_wrap() {
    let reference = seq(65_530);
    assert_eq!(Sequence::resolve(Some(reference), WireSequence(3)), Some(seq(65_539)));
    assert_eq!(
        Sequence::resolve(Some(reference), WireSequence(65_500)),
        Some(seq(65_500))
    );
    assert_eq!(Sequence::resolve(None, WireSequence(7)), Some(seq(7)));
    assert_eq!(Sequence::resolve(None, WireSequence(0)), None);
    assert_eq!(reconstruct(0, WireSequence(0)), Some(0));
}

#[test]
fn the_window_rejects_duplicates_and_the_too_old() {
    let mut window = ReceiveWindow::default();
    assert_eq!(window.check(seq(5)), Ok(()));
    window.insert(seq(5));
    window.insert(seq(3));

    assert_eq!(window.check(seq(5)), Err(WindowError::Duplicate));
    assert_eq!(window.check(seq(3)), Err(WindowError::Duplicate));
    assert_eq!(window.check(seq(4)), Ok(()));
    assert_eq!(window.ack_bits(), 0b10);

    window.insert(seq(100));
    assert_eq!(window.check(seq(36)), Err(WindowError::TooOld));
    assert_eq!(window.newest(), Some(seq(100)));
}

#[test]
fn an_insert_returns_what_it_displaced() {
    let mut ring: SequenceBuffer<u32, 4> = SequenceBuffer::new();
    assert!(ring.insert(seq(1), 10).is_none());
    assert_eq!(ring.insert(seq(5), 50), Some((seq(1), 10)));
    assert_eq!(ring.get(seq(1)), None);
    assert_eq!(ring.get(seq(5)), Some(&50));
    assert_eq!(ring.remove(seq(5)), Some(50));
    assert_eq!(ring.get(seq(5)), None);
}

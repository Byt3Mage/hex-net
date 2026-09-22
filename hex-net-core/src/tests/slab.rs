//! The slab: handles that track their item, and the occupancy count a
//! connection id is derived from.

use crate::slab::Slab;

#[test]
fn an_item_built_with_its_handle_is_found_by_it() {
    let mut slab: Slab<u32> = Slab::with_capacity(4);
    let mut seen = None;
    let handle = slab
        .insert_with(|handle| {
            seen = Some(handle);
            handle.index()
        })
        .expect("room");

    assert_eq!(seen, Some(handle), "the item was built with the handle it got");
    assert_eq!(slab.get(handle), Some(&handle.index()));
    assert_eq!(slab.handle_at(handle.index()), Some(handle));
}

#[test]
fn a_full_slab_builds_nothing() {
    let mut slab: Slab<u32> = Slab::with_capacity(1);
    slab.insert(1).expect("room");
    let mut built = false;
    let inserted = slab.insert_with(|_| {
        built = true;
        2
    });
    assert!(inserted.is_none());
    assert!(!built, "nothing is built for a slot that does not exist");
}

#[test]
fn a_reused_slot_counts_its_occupancies() {
    let mut slab: Slab<u32> = Slab::with_capacity(1);
    for occupancy in 0..5u32 {
        let handle = slab.insert(occupancy).expect("room");
        assert_eq!(handle.index(), 0, "the one slot is reused");
        assert_eq!(handle.generation() >> 1, occupancy);
        assert_eq!(slab.remove(handle), Some(occupancy));
        assert_eq!(slab.handle_at(0), None, "an emptied slot has no occupant");
    }
}

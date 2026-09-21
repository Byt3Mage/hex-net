//! Storage with stable handles and contiguous items.

use core::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

const NONE: u32 = u32::MAX;

/// A reference into a `Slab<T>` that keeps working as items move and stops
/// working once its item is removed.
pub struct Handle<T> {
    index: u32,
    generation: u32,
    marker: PhantomData<fn() -> T>,
}

impl<T> Handle<T> {
    #[inline]
    const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation, marker: PhantomData }
    }

    /// Slot number, for logs and metrics. Not unique over time.
    #[inline]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[inline]
    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

// Written out rather than derived: derived impls would require the same
// traits of T, and a handle to a non-Clone type must still be Copy.
impl<T> Clone for Handle<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Handle<T> {}

impl<T> PartialEq for Handle<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (self.index == other.index) && (self.generation == other.generation)
    }
}
impl<T> Eq for Handle<T> {}

impl<T> Hash for Handle<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.generation.hash(state);
    }
}

impl<T> fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({}v{})", self.index, self.generation)
    }
}

#[derive(Clone, Copy)]
struct Slot {
    /// Odd while occupied, even while free. Incremented on every transition.
    generation: u32,
    /// Occupied: position in `items`. Free: next free slot, or NONE.
    value: u32,
}

/// Fixed-capacity storage: items stay contiguous for iteration, handles stay
/// valid for reference.
pub struct Slab<T> {
    /// Indexed by a handle's index. Never moves.
    slots: Vec<Slot>,
    items: Vec<T>,
    /// `owners[d]` is the slot owning `items[d]`.
    owners: Vec<u32>,
    free_head: u32,
    capacity: u32,
}

impl<T> Slab<T> {
    pub fn with_capacity(capacity: u32) -> Self {
        assert!(capacity < NONE, "capacity must leave u32::MAX free as a sentinel");
        Self {
            slots: Vec::with_capacity(capacity as usize),
            items: Vec::with_capacity(capacity as usize),
            owners: Vec::with_capacity(capacity as usize),
            free_head: NONE,
            capacity,
        }
    }

    /// Returns the item back when full. Never reallocates.
    pub fn insert(&mut self, item: T) -> Result<Handle<T>, T> {
        let index = if self.free_head != NONE {
            let index = self.free_head;
            self.free_head = self.slots[index as usize].value;
            index
        } else if (self.slots.len() as u32) < self.capacity {
            self.slots.push(Slot { generation: 0, value: NONE });
            (self.slots.len() - 1) as u32
        } else {
            return Err(item);
        };

        let dense = self.items.len() as u32;
        self.items.push(item);
        self.owners.push(index);

        let slot = &mut self.slots[index as usize];
        slot.generation = slot.generation.wrapping_add(1);
        slot.value = dense;
        Ok(Handle::new(index, slot.generation))
    }

    pub fn remove(&mut self, handle: Handle<T>) -> Option<T> {
        let dense = self.dense_index(handle)?;
        let item = self.items.swap_remove(dense);
        self.owners.swap_remove(dense);

        // The last item filled the hole; its slot must point at the new
        // position.
        if dense < self.items.len() {
            let moved = self.owners[dense];
            self.slots[moved as usize].value = dense as u32;
        }

        let slot = &mut self.slots[handle.index as usize];
        slot.generation = slot.generation.wrapping_add(1);
        if slot.generation != 0 {
            slot.value = self.free_head;
            self.free_head = handle.index;
        }
        // A generation that wrapped to zero retires the slot permanently: a
        // handle from 2^31 lifetimes ago would otherwise match it again.
        Some(item)
    }

    #[inline]
    fn dense_index(&self, handle: Handle<T>) -> Option<usize> {
        let slot = self.slots.get(handle.index as usize)?;
        (slot.generation == handle.generation).then_some(slot.value as usize)
    }

    #[inline]
    pub fn get(&self, handle: Handle<T>) -> Option<&T> {
        self.dense_index(handle).map(|i| &self.items[i])
    }

    #[inline]
    pub fn get_mut(&mut self, handle: Handle<T>) -> Option<&mut T> {
        self.dense_index(handle).map(|i| &mut self.items[i])
    }

    #[inline]
    pub fn contains(&self, handle: Handle<T>) -> bool {
        self.dense_index(handle).is_some()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// All items, contiguous. Order changes as items are removed.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items
    }

    pub fn iter(&self) -> impl Iterator<Item = (Handle<T>, &T)> {
        let slots = &self.slots;
        self.owners
            .iter()
            .zip(self.items.iter())
            .map(move |(&index, item)| (Handle::new(index, slots[index as usize].generation), item))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Handle<T>, &mut T)> {
        let slots = &self.slots;
        self.owners
            .iter()
            .zip(self.items.iter_mut())
            .map(move |(&index, item)| (Handle::new(index, slots[index as usize].generation), item))
    }
}

//! Splitting one address across several endpoints, one per core.
//!
//! Every endpoint in a group owns a disjoint slice of the state: its
//! connections, the sessions it created, and the tickets it redeemed. A
//! datagram therefore has exactly one owner, and the owner can be read from
//! the datagram without decrypting anything:
//!
//! - A payload packet belongs to the shard in the low bits of its connection
//!   id, which that shard assigned.
//! - A challenge response belongs to the shard named in the first byte of the
//!   cookie it echoes, which the issuing shard wrote there and authenticated.
//! - A request belongs to nobody in particular. Any shard can answer it,
//!   because the cookie it issues names the shard that must finish the
//!   handshake.
//!
//! Which shard finishes a handshake is fixed by the ticket alone: the shard
//! that owns the session being resumed, or for a new player a shard chosen by
//! the ticket's identity. Every attempt to redeem one ticket therefore meets
//! the same `redeemed` table and the same session record, however the kernel
//! spreads the requests, which is what keeps a ticket single-use and a session
//! in one place.

use core::fmt;

use crate::{
    crypto::{self, Key},
    handshake::{SessionId, TicketId},
};

/// Bits of a connection or session id that name the shard owning it.
pub const SHARD_BITS: u32 = 8;

/// The most endpoints one group can hold.
pub const MAX_SHARDS: usize = 1 << SHARD_BITS;

/// One endpoint's position in its group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardId(u8);

impl ShardId {
    /// The only shard of an ungrouped endpoint.
    pub const FIRST: ShardId = ShardId(0);

    #[inline]
    pub const fn from_byte(byte: u8) -> ShardId {
        ShardId(byte)
    }

    #[inline]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// How many endpoints share an address: from one to `MAX_SHARDS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardCount(u16);

impl ShardCount {
    pub const ONE: ShardCount = ShardCount(1);

    pub const fn new(count: usize) -> Option<ShardCount> {
        if (count == 0) || (count > MAX_SHARDS) {
            return None;
        }
        Some(ShardCount(count as u16))
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0 as usize
    }

    /// Whether `shard` is a member of a group this size.
    #[inline]
    pub const fn contains(self, shard: ShardId) -> bool {
        (shard.0 as u16) < self.0
    }

    pub fn ids(self) -> impl Iterator<Item = ShardId> {
        (0..self.0).map(|index| ShardId(index as u8))
    }

    /// The shard that completes a handshake presenting this ticket.
    ///
    /// A resume goes to the shard holding the session. A new player goes to a
    /// shard picked by the ticket's identity, which is drawn at random when
    /// the ticket is sealed, so new players spread evenly. `None` for a
    /// session no shard in a group this size can hold, which can only be one
    /// named by a ticket from a differently sized group.
    pub fn home(self, session: Option<SessionId>, ticket: TicketId) -> Option<ShardId> {
        match session {
            Some(session) => {
                let shard = session.shard();
                self.contains(shard).then_some(shard)
            }
            None => {
                let [a, b, c, d, ..] = ticket.0;
                let spread = u32::from_le_bytes([a, b, c, d]) % u32::from(self.0);
                Some(ShardId(spread as u8))
            }
        }
    }
}

/// The endpoints sharing one address, and the key they share.
///
/// Cookies and resume tickets are sealed under the server key. A request can
/// land on any shard and a resume ticket can be presented to any shard, so
/// every shard of a group must hold the same one.
#[derive(Clone, Copy)]
pub struct ShardGroup {
    count: ShardCount,
    server_key: Key,
}

impl ShardGroup {
    /// A group with a fresh server key. Resume tickets it seals do not survive
    /// a restart.
    pub fn new(count: ShardCount) -> ShardGroup {
        ShardGroup::with_server_key(count, crypto::generate_key())
    }

    /// A group sealing under a key the caller keeps, so resume tickets stay
    /// valid across a restart of the whole group.
    pub fn with_server_key(count: ShardCount, server_key: Key) -> ShardGroup {
        ShardGroup { count, server_key }
    }

    #[inline]
    pub fn count(&self) -> ShardCount {
        self.count
    }

    /// The member at `id`, or `None` past the end of the group.
    pub fn shard(&self, id: ShardId) -> Option<Shard> {
        self.count
            .contains(id)
            .then_some(Shard { id, count: self.count, server_key: self.server_key })
    }

    /// Every member, in order.
    pub fn shards(&self) -> impl Iterator<Item = Shard> + '_ {
        self.count
            .ids()
            .map(|id| Shard { id, count: self.count, server_key: self.server_key })
    }
}

impl fmt::Debug for ShardGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShardGroup")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// One member of a group: which it is, how large the group is, and the key
/// the group seals with. Made only by a `ShardGroup`, so the id is always
/// inside the group.
#[derive(Clone, Copy)]
pub struct Shard {
    id: ShardId,
    count: ShardCount,
    server_key: Key,
}

impl Shard {
    /// An endpoint alone on its address, sealing under a fresh key.
    pub fn solo() -> Shard {
        Shard {
            id: ShardId::FIRST,
            count: ShardCount::ONE,
            server_key: crypto::generate_key(),
        }
    }

    #[inline]
    pub fn id(&self) -> ShardId {
        self.id
    }

    #[inline]
    pub fn count(&self) -> ShardCount {
        self.count
    }

    #[inline]
    pub(crate) fn server_key(&self) -> &Key {
        &self.server_key
    }
}

impl fmt::Debug for Shard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shard")
            .field("id", &self.id)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

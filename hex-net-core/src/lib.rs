//! Sans-IO transport: a reliable, encrypted connection over UDP.
//!
//! Nothing here touches a socket. Feed datagrams and the current time in, take
//! datagrams, events, and deadlines out.

pub mod ack;
pub mod arena;
pub mod bits;
pub mod budget;
pub mod channel;
pub mod connection;
pub mod connector;
pub mod crypto;
pub mod ctx;
pub mod endpoint;
pub mod fixed;
pub mod handshake;
pub mod packet;
pub mod seq;
pub mod shard;
pub mod slab;
pub mod stats;
pub mod time;
pub mod timer;
pub mod wire;

#[cfg(test)]
mod tests;

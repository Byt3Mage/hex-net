//! An in-memory network for driving the transport deterministically.
//!
//! Time only moves when told to, so a run of several simulated minutes
//! completes in milliseconds, and every random decision comes from one seed, so
//! a failing run replays exactly.

mod pair;

#[cfg(test)]
mod tests;

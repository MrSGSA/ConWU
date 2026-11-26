//! Port estimation and socket helpers for TCP simultaneous open.

pub mod burst;
pub mod estimator;
pub mod handover;

#[cfg(test)]
mod tests;

//! Aethel application proofs; all application-independent primitives are zkPI's.
//! Existing proof domains and wire bytes are preserved by the ownership move.

pub use qomm_zkpi::*;

pub mod receivable;
pub mod receivable_wire;

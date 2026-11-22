//! Rings: how two programs pass a stream of small fixed-size records
//! through memory they share. The rings are `silica_rt::ring` (the runtime
//! writes its log through one); this crate is that module under its own name.
#![no_std]
#![deny(unsafe_code)]

pub use silica_rt::ring::*;

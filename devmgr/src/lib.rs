//! The parts of the device manager that read what a device says, as a
//! library: the program (`main.rs`) uses them, and so do the fuzz targets
//! that play a hostile device against them (`fuzz/`).
#![no_std]

pub mod hotplug;

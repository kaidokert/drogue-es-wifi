#![no_std]

pub mod adapter;
pub mod arbiter;
mod parser;
mod chip_select;
mod ready;
mod socket;
pub mod network;
#[cfg(feature = "net-stats")]
pub mod net_stats;
#[cfg(feature = "embedded-nal")]
pub mod nal;

#[cfg(feature = "net-stats")]
pub use net_stats::NetStats;

use drogue_embedded_timer::Delay;
use embedded_hal::blocking::spi::Transfer;
use embedded_hal::digital::v2::{OutputPin, InputPin};

use crate::arbiter::Arbiter;
use crate::adapter::Adapter;
use heapless::{
    consts::*,
    spsc::Queue
};

use heapless::{
    String,
    Vec,
    spsc::{Producer, Consumer},
    consts::*,
};
use crate::socket::{Socket, State};
//use crate::network::EsWifiNetworkDriver;
use drogue_network::addr::HostSocketAddr;
use crate::arbiter::{Arbiter, SpiError};
use core::cell::RefCell;
use drogue_embedded_timer::Delay;
use embedded_hal::blocking::spi::Transfer;
use embedded_hal::digital::v2::{OutputPin, InputPin};
use crate::parser::join;

pub enum AdapterError {
    ReadError,
    NoAvailableSockets,
    SocketNotOpen,
}


#[derive(Debug)]
pub enum JoinError {
    Unknown,
    InvalidSsid,
    InvalidPassword,
    UnableToAssociate,
}

#[derive(Debug)]
pub enum JoinInfo<'a> {
    Open,
    Wep {
        ssid: &'a str,
        password: &'a str,
    },
}

#[derive(Debug)]
pub enum ConnectError {
    SpiError(SpiError),
    ConnectionFailed,
}

#[derive(Debug)]
pub enum CloseError {
    SpiError(SpiError),
    Error,
}

#[derive(Debug)]
pub enum LeaveError {
    SpiError(SpiError),
    Error,
}

#[derive(Debug)]
pub enum WriteError {
    Error,
    SpiError(SpiError)
}

#[derive(Debug)]
pub enum ReadError {
    Error,
    SpiError(SpiError),
}

impl JoinInfo<'_> {
    pub(crate) fn validate(&self) -> Result<&Self, JoinError> {
        match self {
            JoinInfo::Open => {
                Ok(self)
            }
            JoinInfo::Wep { ssid, password } => {
                if ssid.len() > 32 {
                    Err(JoinError::InvalidSsid)
                } else if password.len() > 32 {
                    Err(JoinError::InvalidPassword)
                } else {
                    Ok(self)
                }
            }
            _ => {
                Ok(self)
            }
        }
    }
}


/// eS-WiFi Adapter, over SPI
pub struct Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
    where
        Spi: Transfer<u8>,
        ChipSelectPin: OutputPin,
        ReadyPin: InputPin,
        WakeupPin: OutputPin,
        ResetPin: OutputPin,
        Clock: embedded_time::Clock + 'clock
{
    pub(crate) arbiter: RefCell<Arbiter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>>,
    pub(crate) sockets: RefCell<[Socket; 4]>,
    pub(crate) clock: &'clock Clock,
}

impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
    where
        Spi: Transfer<u8>,
        ChipSelectPin: OutputPin,
        ReadyPin: InputPin,
        WakeupPin: OutputPin,
        ResetPin: OutputPin,
        Clock: embedded_time::Clock + 'clock
{
    /// Create a new eS-WiFi Adapter.
    ///
    /// * `spi`: The SPI transfer interface (u8).
    /// * `cs`: The chip-select pin for the adapter.
    /// * `ready`: The input pin to know when the adapter is ready for a data phase.
    /// * `wakeup`: The adapter's wake-up pin.
    /// * `reset`: The adapter's reset pin.
    /// * `clock`: A clock capable of 10ms precision
    pub fn new(
        spi: Spi,
        cs: ChipSelectPin,
        ready: ReadyPin,
        wakeup: WakeupPin,
        reset: ResetPin,
        clock: &'clock Clock,
    ) -> Result<Self, ()> {
        let mut arbiter = Arbiter::new(
            spi,
            cs,
            ready,
            wakeup,
            reset,
            clock,
        );

        Ok(Self {
            arbiter: RefCell::new(arbiter),
            sockets: RefCell::new(Socket::create()),
            clock,
        })
    }

    /// Join a WiFi access point.
    pub fn join(&mut self, join_info: &JoinInfo) -> Result<(), JoinError> {
        join_info.validate()?;
        let mut arbiter = self.arbiter.borrow_mut();
        arbiter.join(join_info)
    }

    /// Join an open WiFi access point.
    pub fn join_open(&mut self) -> Result<(), JoinError> {
        self.join(&JoinInfo::Open)
    }

    /// Join a WEP-secured WiFI access point.
    pub fn join_wep(&mut self, ssid: &str, password: &str) -> Result<(), JoinError> {
        self.join(
            &JoinInfo::Wep {
                ssid,
                password,
            }
        )
    }

    /// Leave the current access point WITHOUT resetting the module: the AT interface
    /// stays up, so a following `join` re-associates with a fresh DHCP lease and DNS
    /// server. Cheaper than `recover()`, which reboots the module.
    pub fn leave(&self) -> Result<(), LeaveError> {
        let result = self.arbiter.borrow_mut().leave();
        // Disassociating drops every connection the module was holding, so the handle
        // table must not keep claiming sockets it no longer knows -- the same reason
        // `recover` resets it, and on both the success and failure paths for the same
        // reason: the association is gone either way once `CD` has been sent.
        *self.sockets.borrow_mut() = Socket::create();
        result
    }

    /// IPv4 address obtained by DHCP on the last successful join, if any.
    pub fn ip(&self) -> Option<[u8; 4]> {
        self.arbiter.borrow().ip()
    }

    /// Resolve a hostname to an IPv4 via the module's DNS (`D0`). Call after `join`.
    pub fn resolve(&self, host: &str) -> Option<[u8; 4]> {
        self.arbiter.borrow_mut().resolve(host)
    }

}

#[cfg(feature = "embedded-nal")]
impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> crate::nal::ResolveHost
    for Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
where
    Spi: Transfer<u8>,
    ChipSelectPin: OutputPin,
    ReadyPin: InputPin,
    WakeupPin: OutputPin,
    ResetPin: OutputPin,
    Clock: embedded_time::Clock + 'clock,
{
    fn resolve_host(&self, host: &str) -> Option<[u8; 4]> {
        self.resolve(host)
    }
}

#[cfg(feature = "embedded-nal")]
impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> crate::nal::DriverStatus
    for Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
where
    Spi: Transfer<u8>,
    ChipSelectPin: OutputPin,
    ReadyPin: InputPin,
    WakeupPin: OutputPin,
    ResetPin: OutputPin,
    Clock: embedded_time::Clock + 'clock,
{
    fn driver_state(&self) -> u8 {
        self.arbiter.borrow().state_code()
    }
    fn ready_timeouts(&self) -> u32 {
        self.arbiter.borrow().ready_timeouts()
    }
    fn set_degraded(&self, degraded: bool) {
        self.arbiter.borrow_mut().set_degraded(degraded);
    }
}

#[cfg(all(feature = "embedded-nal", feature = "fault-injection"))]
impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> crate::nal::FaultInject
    for Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
where
    Spi: Transfer<u8>,
    ChipSelectPin: OutputPin,
    ReadyPin: InputPin,
    WakeupPin: OutputPin,
    ResetPin: OutputPin,
    Clock: embedded_time::Clock + 'clock,
{
    fn set_ready_fault(&self, armed: bool) {
        self.arbiter.borrow_mut().set_ready_fault(armed);
    }
}

#[cfg(feature = "embedded-nal")]
impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> crate::nal::Recover
    for Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
where
    Spi: Transfer<u8>,
    ChipSelectPin: OutputPin,
    ReadyPin: InputPin,
    WakeupPin: OutputPin,
    ResetPin: OutputPin,
    Clock: embedded_time::Clock + 'clock,
{
    fn recover(&self, ssid: &str, password: &str) -> bool {
        let join = JoinInfo::Wep { ssid, password };
        if join.validate().is_err() {
            return false;
        }
        let mut arbiter = self.arbiter.borrow_mut();
        // Reset + re-init the AT interface, then re-associate. Both bounded internally.
        let joined = arbiter.recover().is_ok() && arbiter.join(&join).is_ok();
        drop(arbiter);
        // `recover` drives RESET before anything that can fail, so the module has dropped
        // every socket whether or not the re-init succeeded. Reset the handle table to
        // match on both paths, or a failed recovery leaves stale socket numbers pointing
        // at a module that no longer knows them.
        *self.sockets.borrow_mut() = Socket::create();
        joined
    }
}

#[cfg(feature = "embedded-nal")]
impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> crate::nal::Rejoin
    for Adapter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
where
    Spi: Transfer<u8>,
    ChipSelectPin: OutputPin,
    ReadyPin: InputPin,
    WakeupPin: OutputPin,
    ResetPin: OutputPin,
    Clock: embedded_time::Clock + 'clock,
{
    fn leave(&self) -> bool {
        // Named explicitly rather than `self.leave()`: the inherent method and this trait
        // method share a name, and spelling out which one is called keeps a future reader
        // from having to know that inherent resolution wins.
        Adapter::leave(self).is_ok()
    }

    fn rejoin(&self, ssid: &str, password: &str) -> bool {
        let join = JoinInfo::Wep { ssid, password };
        if join.validate().is_err() {
            return false;
        }
        let mut arbiter = self.arbiter.borrow_mut();
        // Disassociate, then take the network again. No RESET and no AT handshake, which
        // is the whole point: this rung costs one command pair, not a module reboot.
        let rejoined = arbiter.leave().is_ok() && arbiter.join(&join).is_ok();
        drop(arbiter);
        // The association is gone once `CD` has been sent, whether or not the re-join
        // succeeded, so the handle table must not keep claiming sockets the module has
        // forgotten — the same reason `recover` resets it.
        *self.sockets.borrow_mut() = Socket::create();
        rejoined
    }
}
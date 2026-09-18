use embedded_hal::blocking::spi::Transfer;
use embedded_hal::digital::v2::{OutputPin, InputPin};
use embedded_time::duration::Milliseconds;
use drogue_embedded_timer::Delay;
use heapless::{consts::*, String, spsc::{Consumer, Producer}, ArrayLength};

use core::fmt::Write;

use crate::chip_select::ChipSelect;
use crate::ready::Ready;
use nom::InputIter;
use crate::adapter::{AdapterError, JoinError, JoinInfo, ConnectError, WriteError, ReadError, CloseError, LeaveError};
use crate::parser;
use crate::parser::{JoinResponse, ConnectResponse, WriteResponse, ReadResponse, CloseResponse, LeaveResponse};
use nom::error::ErrorKind;
use drogue_network::addr::HostSocketAddr;

macro_rules! command {
    ($size:tt, $($arg:tt)*) => ({
        //let mut c = String::new();
        //c
        let mut c = String::<$size>::new();
        write!(c, $($arg)*);
        c.push_str("\r");
        c
    })
}

/// Upper bound on any single wait for the module to assert DATA_READY. Generous enough
/// not to trip on a legitimately slow op (an over-the-air DNS lookup or connect), while
/// still bounding a stuck module to a finite error instead of an unbounded spin.
const READY_TIMEOUT_MS: u32 = 5_000;

/// RESET-low hold for a mid-run recovery, longer than the 50 ms cold-boot pulse.
/// Live experiments found a running module ignores a <=120 ms pulse but a ~1 s
/// assertion reliably drops it, so `recover()` holds RESET low this long before re-booting.
const RECOVER_RESET_HOLD_MS: u32 = 1_000;

/// Lifecycle state of the module, exposed for supervision. A supervisor
/// observes it — nothing acts on the state yet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverState {
    /// Powered but the AT prompt handshake has not completed.
    Uninitialized,
    /// AT interface up (prompt handshake done), not yet associated.
    Ready,
    /// Associated to an AP with a DHCP lease.
    Joined,
    /// Reserved for a "degraded" classification — defined so a later supervisor has a
    /// state to observe; the driver itself never enters it.
    #[allow(dead_code)]
    Degraded,
}


#[derive(Debug)]
pub enum SpiError {
    ReadError,
    WriteError,
}

#[derive(Debug)]
pub enum IpProtocol {
    Tcp,
    Udp,
}


pub struct Arbiter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
    where
        Spi: Transfer<u8>,
        ChipSelectPin: OutputPin,
        ReadyPin: InputPin,
        WakeupPin: OutputPin,
        ResetPin: OutputPin,
        Clock: embedded_time::Clock + 'clock
{
    spi: Spi,
    cs: ChipSelect<'clock, ChipSelectPin, Clock>,
    ready: Ready<ReadyPin>,
    wakeup: WakeupPin,
    reset: ResetPin,
    clock: &'clock Clock,
    delay: Delay<'clock, Clock>,
    state: DriverState,
    /// IPv4 address parsed from the last successful JOIN response (DHCP lease).
    ip: Option<[u8; 4]>,
    /// Count of bounded ready-waits that hit [`READY_TIMEOUT_MS`] — the "module isn't
    /// answering SPI" signal used by classification. Lives here (not on
    /// NalTcpStack's NetStats) because the timeout fires here, where the clock is.
    ready_timeouts: u32,
    /// Fault injection: when set, every bounded ready-wait reports a timeout without
    /// consulting DATA_READY, so a supervisor's "module isn't answering SPI" path can be
    /// exercised without wedging the module. Stays armed until cleared: `recover()` runs
    /// its handshake through the same wait, so recovery keeps failing while it is set —
    /// which is what lets a bounded self-recovery loop escalate to its terminal state.
    ///
    /// Ordinary traffic leaves the module alone, but recovery does not: `recover()` drives
    /// RESET before its handshake reaches this fault, so every attempt really does reboot
    /// and de-associate the module — the same thing a real unresponsive module would get.
    /// Clearing the fault therefore restores the SPI interface but not the association;
    /// that needs a recovery attempt made while the fault is down.
    #[cfg(feature = "fault-injection")]
    ready_fault: bool,
}

/// Parse the dotted-quad IPv4 that follows the SSID in a JOIN response, e.g.
/// `\r\n[JOIN   ] WK,192.168.0.192,0,0\r\nOK\r\n>` -> [192,168,0,192].
fn parse_join_ip(resp: &[u8]) -> Option<[u8; 4]> {
    // The IP is the field between the first and second commas.
    let start = resp.iter().position(|&b| b == b',')? + 1;
    let rest = &resp[start..];
    let end = rest.iter().position(|&b| b == b',')?;
    let mut octets = [0u8; 4];
    let mut i = 0;
    for part in rest[..end].split(|&b| b == b'.') {
        if i >= 4 {
            return None;
        }
        let mut v: u16 = 0;
        for &d in part {
            if !d.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (d - b'0') as u16;
        }
        if v > 255 {
            return None;
        }
        octets[i] = v as u8;
        i += 1;
    }
    if i == 4 {
        Some(octets)
    } else {
        None
    }
}

/// Scan a response for the first bare dotted-quad IPv4 (e.g. the `D0` DNS reply,
/// which returns just the address, unlike JOIN's comma-delimited fields). Any
/// hostname echoed in the response has non-digit labels, so it is skipped.
fn parse_dotted_ip(resp: &[u8]) -> Option<[u8; 4]> {
    let mut i = 0;
    while i < resp.len() {
        if resp[i].is_ascii_digit() {
            let (mut octets, mut oi, mut v, mut seen) = ([0u8; 4], 0usize, 0u16, false);
            let mut j = i;
            while j < resp.len() {
                match resp[j] {
                    d @ b'0'..=b'9' => {
                        v = v * 10 + (d - b'0') as u16;
                        seen = true;
                        if v > 255 {
                            break;
                        }
                    }
                    b'.' if seen && oi < 3 => {
                        octets[oi] = v as u8;
                        oi += 1;
                        v = 0;
                        seen = false;
                    }
                    _ => break,
                }
                j += 1;
            }
            if oi == 3 && seen {
                octets[3] = v as u8;
                return Some(octets);
            }
            i = j;
        }
        i += 1;
    }
    None
}

impl<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock> Arbiter<'clock, Spi, ChipSelectPin, ReadyPin, WakeupPin, ResetPin, Clock>
    where
        Spi: Transfer<u8>,
        ChipSelectPin: OutputPin,
        ReadyPin: InputPin,
        WakeupPin: OutputPin,
        ResetPin: OutputPin,
        Clock: embedded_time::Clock + 'clock
{
    pub fn new(spi: Spi,
               cs: ChipSelectPin,
               ready: ReadyPin,
               wakeup: WakeupPin,
               reset: ResetPin,
               clock: &'clock Clock,
    ) -> Self {
        Self {
            spi,
            cs: ChipSelect::new(cs, Delay::new(clock)),
            ready: Ready::new(ready),
            wakeup,
            reset,
            clock,
            delay: Delay::new(clock),
            state: DriverState::Uninitialized,
            ip: None,
            ready_timeouts: 0,
            #[cfg(feature = "fault-injection")]
            ready_fault: false,
        }
    }

    /// IPv4 address from the last successful join (DHCP), if any.
    pub(crate) fn ip(&self) -> Option<[u8; 4]> {
        self.ip
    }

    /// Numeric lifecycle state for the health snapshot (0=uninit, 1=ready, 2=joined,
    /// 3=degraded). Observation only — see [`DriverState`].
    pub(crate) fn state_code(&self) -> u8 {
        match self.state {
            DriverState::Uninitialized => 0,
            DriverState::Ready => 1,
            DriverState::Joined => 2,
            DriverState::Degraded => 3,
        }
    }

    /// Bounded ready-wait timeouts so far — the "module not answering" signal.
    pub(crate) fn ready_timeouts(&self) -> u32 {
        self.ready_timeouts
    }

    /// Arm/disarm the ready-wait fault (dev only). Normal operation never touches the
    /// module, so disarming restores it; a recovery attempt made while it is armed still
    /// resets the module for real, since RESET precedes the handshake that fails.
    #[cfg(feature = "fault-injection")]
    pub(crate) fn set_ready_fault(&mut self, armed: bool) {
        self.ready_fault = armed;
    }

    /// Reflect a supervisor classification into the lifecycle state (observe-only).
    /// Toggles between Joined and Degraded — never clobbers the Uninitialized/
    /// Ready bring-up states, and does not itself trigger any recovery.
    pub(crate) fn set_degraded(&mut self, degraded: bool) {
        self.state = match (degraded, self.state) {
            (true, DriverState::Joined) => DriverState::Degraded,
            (false, DriverState::Degraded) => DriverState::Joined,
            (_, other) => other,
        };
    }

    fn initialize(&mut self) -> Result<(), ()> {
        self.wakeup();
        self.reset();
        self.handshake()
    }

    /// Mid-run module recovery: drop a wedged module with a long RESET, then re-run
    /// the AT prompt handshake back to `Ready`. Bounded by `READY_TIMEOUT_MS` (via
    /// `handshake`/`await_data_ready`), so an unresponsive module returns `Err` instead of
    /// hanging the owner. Re-association (`join`) is the caller's next step;
    /// state is left `Uninitialized` if the handshake fails so the snapshot stays honest.
    pub(crate) fn recover(&mut self) -> Result<(), ()> {
        self.state = DriverState::Uninitialized;
        self.wakeup();
        self.hard_reset();
        self.handshake()
    }

    /// Post-reset AT prompt handshake shared by `initialize` (cold boot) and `recover`
    /// (mid-run). Reads the `\r\n> ` prompt, disables verbosity, and marks the AT
    /// interface `Ready`.
    fn handshake(&mut self) -> Result<(), ()> {
        //log::info!("await ready");
        self.await_data_ready().map_err(|_| ())?;
        //log::info!("ready");

        let _cs = self.cs.select();

        let mut response = [0 as u8; 16];
        let mut pos = 0;

        loop {
            //log::info!("loop {}", pos);
            if !self.ready.is_ready() {
                break;
            }
            if pos >= response.len() {
                return Err(());
            }
            let mut chunk = [0x0A, 0x0A];
            self.spi.transfer(&mut chunk);
            //log::info!("transfer {:?}", chunk);
            // reverse order going from 16 -> 2*8 bits
            if chunk[1] != 0x15 {
                response[pos] = chunk[1];
                pos += 1;
            }
            if chunk[0] != 0x15 {
                response[pos] = chunk[0];
                pos += 1;
            }
        }

        let needle = &[b'\r', b'\n', b'>', b' '];

        drop(_cs);

        if !response[0..pos].starts_with(needle) {
            log::info!("failed to initialize {:?}", &response[0..pos]);
            Err(())
        } else {
            // disable verbosity
            self.send_string(&command!(U8, "MT=1"), &mut response);
            self.state = DriverState::Ready;
            log::info!("eS-WiFi adapter is ready");
            Ok(())
        }
    }

    fn process_backlog(&mut self) {
        if matches!(self.state, DriverState::Uninitialized) {
            self.initialize();
        }

        /*
        let mut response = [0u8; 1024];

        let response = self.send_string(
            &command!(U4, "MR"),
                &mut response
        );

        if response.is_ok() {
            let response = response.unwrap();
            log::info!( "backlog {}", core::str::from_utf8(&response).unwrap());
        }
         */
    }

    fn wakeup(&mut self) {
        // FORK PATCH: upstream drives WAKEUP low; on the B-L475E-IOT01A the module was
        // only reliable with WAKEUP held HIGH (kept out of low-power sleep).
        self.wakeup.set_high();
    }

    fn reset(&mut self) {
        // FORK PATCH: a 10 ms pulse is too short to reliably boot the module; hold
        // RESET low for a real reset and give it time to come up before the prompt
        // handshake. (Note: even this does not clear the module's stuck-TCP-stack
        // state after a warm MCU reboot — that needs a full power cycle. See README.)
        self.reset.set_low();
        self.delay.delay(Milliseconds(50u32));
        self.reset.set_high();
        self.delay.delay(Milliseconds(500u32));
    }

    fn hard_reset(&mut self) {
        // A mid-run wedged module ignores the short cold-boot pulse; hold RESET low for
        // ~1 s to reliably drop it (see RECOVER_RESET_HOLD_MS), then let it re-boot.
        self.reset.set_low();
        self.delay.delay(Milliseconds(RECOVER_RESET_HOLD_MS));
        self.reset.set_high();
        self.delay.delay(Milliseconds(500u32));
    }

    /// Wait for the module to assert DATA_READY, bounded by [`READY_TIMEOUT_MS`].
    ///
    /// Upstream spun `while !ready {}` with no timeout, so a module that stops asserting
    /// DATA_READY — after a reset/brownout, or the resolver wedge — hung the owner
    /// forever, invisibly to an external watchdog.
    /// Bounding it converts that silent hang into a countable, recoverable error.
    fn await_data_ready(&mut self) -> Result<(), SpiError> {
        // Injected fault: report the same countable timeout the real path does, but
        // without the wait, so a test does not pay READY_TIMEOUT_MS per operation.
        #[cfg(feature = "fault-injection")]
        if self.ready_fault {
            self.ready_timeouts = self.ready_timeouts.wrapping_add(1);
            return Err(SpiError::ReadError);
        }
        let timer = self
            .clock
            .new_timer(Milliseconds(READY_TIMEOUT_MS))
            .start()
            .map_err(|_| SpiError::ReadError)?;
        while !self.ready.is_ready() {
            if let Ok(true) = timer.is_expired() {
                self.ready_timeouts = self.ready_timeouts.wrapping_add(1);
                return Err(SpiError::ReadError);
            }
        }
        Ok(())
    }

    fn send_string<'a, N: ArrayLength<u8>>(&mut self, command: &String<N>, response: &'a mut [u8]) -> Result<&'a [u8], SpiError> {
        self.send(command.as_bytes(), response)
    }

    fn send<'a>(&mut self, command: &[u8], response: &'a mut [u8]) -> Result<&'a [u8], SpiError> {
        //log::info!("send {:?}", core::str::from_utf8(command).unwrap());

        self.await_data_ready()?;
        {
            let _cs = self.cs.select();

            for chunk in command.chunks(2) {
                let mut xfer: [u8; 2] = [0; 2];
                xfer[1] = chunk[0];
                if chunk.len() == 2 {
                    xfer[0] = chunk[1]
                } else {
                    xfer[0] = 0x0A
                }

                let result = self.spi.transfer(&mut xfer);
                if !result.is_ok() {
                    return Err(SpiError::WriteError);
                }
            }
        }
        self.receive(response)
    }

    fn receive<'a>(&mut self, response: &'a mut [u8]) -> Result<&'a [u8], SpiError> {
        self.await_data_ready()?;
        let mut pos = 0;

        let _cs = self.cs.select();

        // Bound the drain: upstream spun `while ready {}` with no timeout AND no `pos`
        // limit, so a module stuck asserting DATA_READY high (e.g. after a reset) would
        // both hang here forever and overrun `response`. Cap on time and on buffer space.
        let timer = self
            .clock
            .new_timer(Milliseconds(READY_TIMEOUT_MS))
            .start()
            .map_err(|_| SpiError::ReadError)?;
        while self.ready.is_ready() {
            if pos + 2 > response.len() {
                break;
            }
            if let Ok(true) = timer.is_expired() {
                self.ready_timeouts = self.ready_timeouts.wrapping_add(1);
                return Err(SpiError::ReadError);
            }
            let mut xfer: [u8; 2] = [0x0A, 0x0A];
            let result = self.spi.transfer(&mut xfer);
            if !result.is_ok() {
                return Err(SpiError::ReadError);
            }
            //log::info!( "read {} {}", xfer[1] as char, xfer[0] as char);
            response[pos] = xfer[1];
            pos += 1;
            if xfer[0] != 0x15 {
                response[pos] = xfer[0];
                pos += 1;
            }
        }
        //log::info!("response {}", core::str::from_utf8(&response[0..pos]).unwrap());
        Ok(&mut response[0..pos])
    }

    /// Binary-safe receive for socket-data reads. Unlike `receive`, it does NOT strip
    /// `0x15` bytes: for AT-command *text* responses `0x15` is only ever trailing SPI
    /// padding, but socket payloads (e.g. TLS ciphertext) are random binary and DO
    /// contain `0x15` — stripping them mid-stream corrupts the data. Trailing padding
    /// lands after the `\r\nOK\r\n>` prompt, which the read parser excludes anyway.
    /// Bounds-checked so a full 1460-byte read can't overrun the caller's buffer.
    fn receive_raw<'a>(&mut self, response: &'a mut [u8]) -> Result<&'a [u8], SpiError> {
        self.await_data_ready()?;
        let mut pos = 0;
        let _cs = self.cs.select();
        // Bounded like `receive` — a module stuck asserting DATA_READY high must not
        // spin this drain forever (the buffer cap alone bounds memory, not time).
        let timer = self
            .clock
            .new_timer(Milliseconds(READY_TIMEOUT_MS))
            .start()
            .map_err(|_| SpiError::ReadError)?;
        while self.ready.is_ready() {
            if pos + 2 > response.len() {
                break;
            }
            if let Ok(true) = timer.is_expired() {
                self.ready_timeouts = self.ready_timeouts.wrapping_add(1);
                return Err(SpiError::ReadError);
            }
            let mut xfer: [u8; 2] = [0x0A, 0x0A];
            if self.spi.transfer(&mut xfer).is_err() {
                return Err(SpiError::ReadError);
            }
            response[pos] = xfer[1];
            response[pos + 1] = xfer[0];
            pos += 2;
        }
        Ok(&response[0..pos])
    }

    // ------------------------------------------------------------------------
    // Request handling
    // ------------------------------------------------------------------------

    pub(crate) fn join(&mut self, join_info: &JoinInfo) -> Result<(), JoinError> {
        self.process_backlog();
        match join_info {
            JoinInfo::Open => {
                Ok(())
            }
            JoinInfo::Wep { ssid, password } => {
                let mut response = [0u8; 1024];

                self.send_string(
                    &command!(U36, "CB=2"),
                    &mut response).map_err(|_| JoinError::InvalidSsid)?;

                self.send_string(
                    &command!(U36, "C1={}", ssid),
                    &mut response).map_err(|_| JoinError::InvalidSsid)?;

                self.send_string(
                    &command!(U72, "C2={}", password),
                    &mut response).map_err(|_| JoinError::InvalidPassword)?;

                self.send_string(
                    &command!(U8, "C3=4"),
                    &mut response).map_err(|_| JoinError::Unknown)?;

                // FORK PATCH: enable DHCP (C4=1) — upstream omits this, so the
                // module associates but never gets an IP and every connect fails.
                self.send_string(
                    &command!(U8, "C4=1"),
                    &mut response).map_err(|_| JoinError::Unknown)?;

                let response = self.send_string(&command!(U4, "C0"), &mut response).map_err(|_| JoinError::Unknown)?;

                // Capture the DHCP IP (owned) before `response` is borrowed by the parser.
                let ip = parse_join_ip(response);
                let parse_result = parser::join_response(&response);

                log::info!("response for JOIN {:?}", parse_result);

                self.process_backlog();

                match parse_result {
                    Ok((_, response)) => {
                        match response {
                            JoinResponse::Ok => {
                                self.ip = ip;
                                self.state = DriverState::Joined;
                                Ok(())
                            }
                            JoinResponse::JoinError => {
                                Err(JoinError::UnableToAssociate)
                            }
                        }
                    }
                    Err(_) => {
                        log::info!( "{:?}", &response);
                        Err(JoinError::UnableToAssociate)
                    }
                }
            }
        }
    }

    pub(crate) fn connect(&mut self, proto: IpProtocol, socket_num: usize, remote: HostSocketAddr) -> Result<(), ConnectError> {
        self.process_backlog();
        log::info!("CONNECT {:?} {:?}", proto, remote);

        let mut response = [0u8; 1024];

        self.send_string(
            &command!( U8, "P0={}", socket_num),
            &mut response).map_err(|e| ConnectError::SpiError(e))?;

        // FORK PATCH: clear any half-open socket first — a stale P6=1 state makes the
        // next connect report "Failed to connect".
        self.send_string(
            &command!(U8, "P6=0"),
            &mut response).map_err(|e| ConnectError::SpiError(e))?;

        match proto {
            IpProtocol::Tcp => {
                self.send_string(
                    &command!(U8,"P1=0"),
                    &mut response).map_err(|e| ConnectError::SpiError(e))?;
            }
            IpProtocol::Udp => {
                self.send_string(
                    &command!(U8,"P1=1"),
                    &mut response).map_err(|e| ConnectError::SpiError(e))?;
            }
        }

        // FORK PATCH: match the ST BSP ordering — remote PORT (P4) before IP (P3).
        self.send_string(
            &command!(U32, "P4={}", remote.port()),
            &mut response).map_err(|e| ConnectError::SpiError(e))?;

        self.send_string(
            &command!(U32, "P3={}", remote.addr().ip()),
            &mut response).map_err(|e| ConnectError::SpiError(e))?;

        let response = self.send_string(&command!(U8, "P6=1"), &mut response).map_err(|e| ConnectError::SpiError(e))?;

        if let Ok((_, ConnectResponse::Ok)) = parser::connect_response(&response) {
            Ok(())
        } else {
            Err(ConnectError::ConnectionFailed)
        }
    }

    /// DNS lookup via the module's `D0=<hostname>` command. Requires an active
    /// association (call after `join`). Returns the first resolved IPv4.
    pub(crate) fn resolve(&mut self, host: &str) -> Option<[u8; 4]> {
        self.process_backlog();
        let mut response = [0u8; 128];
        // "D0=" + hostname (<= HOSTNAME_MAX) + "\r" — needs a roomy String tier.
        let resp = self.send_string(&command!(U128, "D0={}", host), &mut response).ok()?;
        parse_dotted_ip(resp)
    }

    /// Leave the current access point without touching RESET. `CD` disassociates while
    /// the AT interface stays up, so the module drops back to `Ready` and a following
    /// `join` takes a fresh DHCP lease and a fresh DNS server. This is the cheap rung
    /// beneath `recover()`, which reboots the module and costs a full handshake.
    pub(crate) fn leave(&mut self) -> Result<(), LeaveError> {
        self.process_backlog();
        let mut response = [0u8; 1024];

        let response = self
            .send_string(&command!(U4, "CD"), &mut response)
            .map_err(|e| LeaveError::SpiError(e))?;

        match parser::leave_response(&response) {
            Ok((_, LeaveResponse::Ok)) => {
                // The DHCP lease went with the association. Keeping the cached address
                // would report an IP the module no longer holds, which is exactly the
                // stale-state trap that makes association loss hard to tell apart.
                self.ip = None;
                self.state = DriverState::Ready;
                Ok(())
            }
            _ => Err(LeaveError::Error),
        }
    }

    pub(crate) fn close(&mut self, socket_num: usize) -> Result<(), CloseError> {
        self.process_backlog();
        let mut response = [0u8; 1024];

        self.send_string(
            &command!( U8, "P0={}", socket_num),
            &mut response).map_err(|e| CloseError::SpiError(e))?;

        let response = self.send_string(&command!(U8, "P6=0"), &mut response).map_err(|e| CloseError::SpiError(e))?;

        //let response = parser::close_response(&response);

        //log::info!("close resp {:?}", response);

        //Ok(())

        if let Ok((_, CloseResponse::Ok)) = parser::close_response(&response) {
            Ok(())
        } else {
            Err(CloseError::Error)
        }
    }

    pub(crate) fn write(&mut self, socket_num: usize, buf: &[u8]) -> Result<usize, WriteError> {
        self.process_backlog();

        let mut len = buf.len();
        if len > 1046 {
            len = 1046
        }

        let mut response = [0u8; 1024];

        let command = command!(U8, "P0={}", socket_num);
        self.send(command.as_bytes(), &mut response);

        self.send_string(
            &command!(U8, "P0={}", socket_num),
            &mut response,
        ).map_err(|e| WriteError::SpiError(e))?;

        self.send_string(
            &command!(U16, "S1={}", len),
            &mut response,
        ).map_err(|e| WriteError::SpiError(e))?;


        // to ensure it's an even number of bytes, abscond with 1 byte from the payload.
        let prefix = [b'S', b'0', b'\r', buf[0]];
        let remainder = &buf[1..len];

        self.await_data_ready().map_err(WriteError::SpiError)?;
        {
            let _cs = self.cs.select();

            for chunk in prefix.chunks(2) {
                let mut xfer: [u8; 2] = [0; 2];
                xfer[1] = chunk[0];
                xfer[0] = chunk[1];
                //if chunk.len() == 2 {
                //} else {
                //xfer[0] = 0x0A
                //}

                //log::info!("transfer {:?}", xfer);
                self.spi.transfer(&mut xfer);
            }

            for chunk in remainder.chunks(2) {
                let mut xfer: [u8; 2] = [0; 2];
                xfer[1] = chunk[0];
                if chunk.len() == 2 {
                    xfer[0] = chunk[1]
                } else {
                    xfer[0] = 0x0A
                }

                //log::info!("transfer {:?}", xfer);
                self.spi.transfer(&mut xfer);
            }
        }
        self.await_data_ready().map_err(WriteError::SpiError)?;
        let response = self.receive(&mut response).map_err(|e| WriteError::SpiError(e))?;

        if let Ok((_, WriteResponse::Ok(len))) = parser::write_response(response) {
            Ok(len)
        } else {
            Err(WriteError::Error)
        }
    }

    pub(crate) fn read(&mut self, socket_num: usize, buffer: &mut [u8]) -> Result<usize, ReadError> {
        self.process_backlog();
        let mut pos = 0;
        let buf_len = buffer.len();
        loop {
            let result = self.read_internal(socket_num, &mut buffer[pos..buf_len]);
            match result {
                Ok(len) => {
                    pos += len;
                    if len == 0 || pos == buffer.len() {
                        return Ok(pos);
                    }
                }
                Err(e) => {
                    if pos == 0 {
                        return Err(e);
                    } else {
                        return Ok(pos);
                    }
                }
            }
        }
    }

    fn read_internal(&mut self, socket_num: usize, buffer: &mut [u8]) -> Result<usize, ReadError> {
        self.process_backlog();

        // Must hold a full R1-capped read (1460) plus the `\r\n..\r\nOK\r\n> ` framing;
        // the original 1100 overran for large reads.
        let mut response = [0u8; 1600];

        self.send_string(
            &command!( U8, "P0={}", socket_num),
            &mut response,
        ).map_err(|e| ReadError::SpiError(e))?;

        let mut len = buffer.len();
        if len > 1460 {
            len = 1460;
        }

        self.send_string(
            &command!( U16, "R1={}", len),
            &mut response,
        ).map_err(|e| ReadError::SpiError(e))?;

        self.send_string(
            &command!(U8, "R2=15"),
            &mut response,
        ).map_err(|e| ReadError::SpiError(e))?;

        self.send_string(
            &command!(U8, "R3=1"),
            &mut response,
        ).map_err(|e| ReadError::SpiError(e))?;

        //self.send("R?\r".as_bytes(), &mut response);

        self.await_data_ready().map_err(ReadError::SpiError)?;
        {
            let _cs = self.cs.select();

            let mut xfer = [b'0', b'R'];
            self.spi.transfer(&mut xfer);

            xfer = [b'\n', b'\r'];
            self.spi.transfer(&mut xfer);
        }

        self.await_data_ready().map_err(ReadError::SpiError)?;

        // Binary-safe: socket payloads contain 0x15 bytes that must NOT be stripped.
        let response = self.receive_raw(&mut response).map_err(|e| ReadError::SpiError(e))?;

        if let Ok((_, ReadResponse::Ok(data))) = parser::read_response(&response) {
            for (i, b) in data.iter().enumerate() {
                buffer[i] = *b;
            }
            return Ok(data.len());
        }
        //result
        Err(ReadError::Error)
    }
}


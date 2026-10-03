//! `embedded_nal::TcpClientStack` adapter over the crate's `drogue_network::TcpStack`.
//!
//! The two traits are close but not drop-in compatible: drogue's `TcpStack` takes
//! `&self` (interior mutability) and *consumes* the socket handle on `connect`
//! (returning a fresh one), while `embedded_nal` wants `&mut self` and threads the
//! socket through as `&mut`. `NalTcpStack` bridges that by holding the drogue handle
//! in an `Option` so `connect` can move it out and back in, and by converting
//! `embedded_nal`'s `SocketAddr` into drogue's `HostSocketAddr` (IPv4 only — the
//! ISM43362 offload stack has no IPv6). It works for any `TcpStack`, so it lives
//! here rather than in the application.
use core::fmt::Debug;

use drogue_network::addr::{HostAddr, HostSocketAddr};
use drogue_network::tcp::{Mode, TcpStack};
use embedded_nal::{
    AddrType, Dns, IpAddr, Ipv4Addr, SocketAddr, TcpClientStack, UdpClientStack, UdpFullStack,
};

/// Hostname → IPv4 resolution, provided by the underlying offload stack (the
/// ISM43362 `D0` command). Kept separate from `TcpStack` so [`NalTcpStack`]'s
/// [`Dns`] impl stays generic over any stack that can resolve.
pub trait ResolveHost {
    fn resolve_host(&self, host: &str) -> Option<[u8; 4]>;
}

/// UDP datagrams, provided by the underlying offload stack. Kept separate from
/// `TcpStack` so [`NalTcpStack`]'s UDP impls stay generic over any stack that has them.
pub trait UdpDatagrams {
    type UdpSocket;
    type UdpError: Debug;
    /// Open a UDP endpoint whose datagrams leave from `local_port`.
    fn udp_open(&self, local_port: u16) -> Result<Self::UdpSocket, Self::UdpError>;
    /// Send one datagram to `remote`.
    fn udp_send_to(
        &self,
        socket: &mut Self::UdpSocket,
        remote: [u8; 4],
        port: u16,
        buffer: &[u8],
    ) -> Result<(), Self::UdpError>;
    /// Receive one datagram and its sender, or `WouldBlock` when none is waiting.
    fn udp_recv_from(
        &self,
        socket: &mut Self::UdpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<(usize, [u8; 4], u16), Self::UdpError>;
    fn udp_close(&self, socket: Self::UdpSocket) -> Result<(), Self::UdpError>;
}

/// Lifecycle state of the underlying offload stack, for supervision snapshots.
/// Numeric so it can ride a fixed-size record unchanged.
pub trait DriverStatus {
    /// 0 = uninitialized, 1 = ready (AT up), 2 = joined (associated + DHCP), 3 = degraded.
    fn driver_state(&self) -> u8;
    /// Count of bounded ready-wait timeouts — the "module not answering" signal.
    fn ready_timeouts(&self) -> u32;
    /// Reflect a supervisor classification into the lifecycle state (toggles
    /// Joined↔Degraded). Observe-only — sets state, triggers no recovery.
    fn set_degraded(&self, degraded: bool);
}

/// Mid-run recovery of the offload stack: reset the module and re-join the given
/// network. Returns `true` if the module came back associated. Kept separate from
/// [`DriverStatus`] so the recovery capability is opt-in per stack.
pub trait Recover {
    fn recover(&self, ssid: &str, password: &str) -> bool;
}

/// Soft re-association: drop the current access point and take it again without resetting
/// the module, so the link comes back with a fresh DHCP lease and a fresh DNS server. Kept
/// separate from [`Recover`] so a supervisor can reach for the cheap rung without also
/// taking on the one that reboots the module.
pub trait Rejoin {
    /// Leave the access point. Returns `true` if the module accepted the disassociation
    /// and the AT interface is still up. The association is gone either way.
    fn leave(&self) -> bool;

    /// Leave and re-associate in one call. Returns `true` if the module came back
    /// associated.
    ///
    /// Bundled for the same reason [`Recover`] bundles reset and join: a caller holding
    /// the stack through a wrapper has no way to issue the join half on its own, so a
    /// bare `leave` would strand the link disassociated.
    fn rejoin(&self, ssid: &str, password: &str) -> bool;
}

/// Fault injection against the module's SPI-level signalling (dev only). Kept separate
/// from [`DriverStatus`] so the capability is opt-in per stack, like [`Recover`].
#[cfg(feature = "fault-injection")]
pub trait FaultInject {
    /// Arm/disarm a ready-wait fault: every bounded wait for DATA_READY reports a
    /// timeout without touching the module, which a supervisor watching the
    /// ready-timeout counter classifies as "module unresponsive". Stays armed until
    /// disarmed, so recovery — which re-runs the handshake through the same wait —
    /// keeps failing and a bounded recovery loop reaches its terminal state.
    ///
    /// Recovery is the one path that does reach the hardware: it drives RESET before the
    /// handshake fails, so each attempt reboots and de-associates the module exactly as a
    /// real unresponsive module would. Disarming restores the SPI interface, not the
    /// association — re-joining takes a recovery attempt made with the fault down.
    fn set_ready_fault(&self, armed: bool);
}

/// Wraps any drogue `TcpStack` (e.g. `Adapter`) as an `embedded_nal` client stack.
pub struct NalTcpStack<T: TcpStack> {
    inner: T,
    /// Next local port handed to a UDP socket that is never bound.
    next_ephemeral: u16,
    /// `None` = blocking; `Some(ms)` = open sockets in `Mode::Timeout(ms)`.
    timeout_ms: Option<u16>,
    /// Driver-level counters, held here (not a global) so an isolated owner can
    /// touch them — see net_stats.rs. Read via [`NalTcpStack::net_stats`].
    #[cfg(feature = "net-stats")]
    stats: crate::net_stats::NetStats,
    /// Fault injection: when set, DNS resolution fails without querying the
    /// module (a simulated resolver wedge). Armed independently of `connect_fault` so a
    /// resolve-only fault (endpoint still reachable) can exercise a cached-IP fallback.
    #[cfg(feature = "fault-injection")]
    resolve_fault: bool,
    /// Fault injection: when set, `connect` fails without touching the module — models a
    /// dead fallback endpoint. Arm it together with `resolve_fault` to simulate a total
    /// outage; leave it off for a resolve-only fault where the endpoint is still up.
    #[cfg(feature = "fault-injection")]
    connect_fault: bool,
    /// Fault injection: when set, DNS resolution SUCCEEDS with this fixed address
    /// without querying the module — a deterministic "healthy resolve" for exercising a
    /// caller's cache-write path when the real DNS is unavailable.
    #[cfg(feature = "fault-injection")]
    resolve_ok: Option<[u8; 4]>,
}

impl<T: TcpStack> NalTcpStack<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            next_ephemeral: EPHEMERAL_FIRST,
            timeout_ms: None,
            #[cfg(feature = "net-stats")]
            stats: crate::net_stats::NetStats::default(),
            #[cfg(feature = "fault-injection")]
            resolve_fault: false,
            #[cfg(feature = "fault-injection")]
            connect_fault: false,
            #[cfg(feature = "fault-injection")]
            resolve_ok: None,
        }
    }
    /// Arm/disarm fault injection (dev only). `resolve` fails DNS lookups; `connect`
    /// fails socket connects. Both without touching the module (association stays up).
    /// `(true, false)` = DNS wedged but the endpoint is still reachable (exercises a
    /// cached-IP fallback); `(true, true)` = DNS wedged AND the fallback dead (a total
    /// outage).
    #[cfg(feature = "fault-injection")]
    pub fn set_faults(&mut self, resolve: bool, connect: bool) {
        self.resolve_fault = resolve;
        self.connect_fault = connect;
    }
    /// Force DNS resolution to SUCCEED with a fixed IP, or clear it (`None`). A
    /// deterministic healthy resolve for testing a caller's cache-write path.
    #[cfg(feature = "fault-injection")]
    pub fn set_resolve_ok(&mut self, ip: Option<[u8; 4]>) {
        self.resolve_ok = ip;
    }
    /// Arm/disarm the ready-wait fault on the underlying stack: bounded DATA_READY waits
    /// report timeouts without the module being touched. Unlike the resolve and connect
    /// faults, this one also fails `recover`, since recovery's handshake runs through the
    /// same wait — which is the point, as it lets a bounded recovery loop cap out. Note
    /// that those attempts still reset the module, so the association does not survive
    /// them; see [`FaultInject::set_ready_fault`].
    #[cfg(feature = "fault-injection")]
    pub fn set_ready_fault(&self, armed: bool)
    where
        T: FaultInject,
    {
        self.inner.set_ready_fault(armed)
    }
    /// Snapshot the driver's network counters (feature `net-stats`).
    #[cfg(feature = "net-stats")]
    pub fn net_stats(&self) -> crate::net_stats::NetStats {
        self.stats
    }
    /// Numeric lifecycle state of the underlying offload stack (see [`DriverStatus`]).
    pub fn driver_state(&self) -> u8
    where
        T: DriverStatus,
    {
        self.inner.driver_state()
    }
    /// Bounded ready-wait timeouts so far (the "module not answering" signal).
    pub fn ready_timeouts(&self) -> u32
    where
        T: DriverStatus,
    {
        self.inner.ready_timeouts()
    }
    /// Reflect a classification into the driver lifecycle state (Joined↔Degraded).
    pub fn set_degraded(&self, degraded: bool)
    where
        T: DriverStatus,
    {
        self.inner.set_degraded(degraded)
    }
    /// Reset and re-join the module mid-run. Returns `true` if it re-associated.
    /// The underlying stack drops all sockets on reset, so the caller must discard any
    /// socket handles it still holds.
    pub fn recover(&self, ssid: &str, password: &str) -> bool
    where
        T: Recover,
    {
        self.inner.recover(ssid, password)
    }
    /// Leave the access point without resetting the module. The AT interface stays up;
    /// re-associating is the caller's next step, so prefer [`Self::rejoin`] unless the
    /// link is meant to stay down.
    pub fn leave(&self) -> bool
    where
        T: Rejoin,
    {
        self.inner.leave()
    }
    /// Soft re-join: disassociate and re-associate without resetting the module, for a
    /// fresh DHCP lease and DNS server. Returns `true` if it came back associated.
    /// The association drops, so the caller must discard any socket handles it still
    /// holds — the same contract as [`Self::recover`], at a fraction of the cost.
    pub fn rejoin(&self, ssid: &str, password: &str) -> bool
    where
        T: Rejoin,
    {
        self.inner.rejoin(ssid, password)
    }
    /// Open subsequent sockets with a read timeout (`Mode::Timeout(ms)`) so reads
    /// return after a bound — needed to poll a TLS/MQTT link without blocking forever.
    pub fn with_read_timeout(mut self, ms: u16) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// An `embedded_nal` socket. `None` once the underlying drogue handle has been moved
/// into `connect` and not handed back (i.e. a failed connect, or after `close`).
pub struct NalSocket<S>(Option<S>);

#[derive(Debug)]
pub enum NalError<E> {
    /// Error surfaced by the underlying drogue stack.
    Inner(E),
    /// The socket has no live handle (never connected, or a prior connect failed).
    NotConnected,
    /// The offload stack is IPv4-only; an IPv6 address was requested.
    UnsupportedAddr,
    /// DNS lookup returned no address (NXDOMAIN, no association, or module error).
    ResolveFailed,
    /// `bind` on a UDP socket that is already open.
    AlreadyOpen,
}

fn map_nb<E>(e: nb::Error<E>) -> nb::Error<NalError<E>> {
    match e {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(e) => nb::Error::Other(NalError::Inner(e)),
    }
}

impl<T: TcpStack> TcpClientStack for NalTcpStack<T>
where
    T::Error: Debug,
{
    type TcpSocket = NalSocket<T::TcpSocket>;
    type Error = NalError<T::Error>;

    fn socket(&mut self) -> Result<Self::TcpSocket, Self::Error> {
        let mode = match self.timeout_ms {
            Some(ms) => Mode::Timeout(ms),
            None => Mode::Blocking,
        };
        let s = self.inner.open(mode).map_err(NalError::Inner)?;
        Ok(NalSocket(Some(s)))
    }

    fn connect(
        &mut self,
        socket: &mut Self::TcpSocket,
        remote: SocketAddr,
    ) -> nb::Result<(), Self::Error> {
        // Paired with the resolve shim — when armed, fail the connect too, WITHOUT
        // touching the module (leave the handle intact for a retry). Reproduces a dead
        // fallback endpoint so the caller reconnect-loops, and keeps the module idle so
        // it still answers SPI (no ready-timeouts). Feature-off builds never reach this.
        #[cfg(feature = "fault-injection")]
        if self.connect_fault {
            #[cfg(feature = "net-stats")]
            self.stats.connect_fail();
            return Err(nb::Error::Other(NalError::NotConnected));
        }
        let host = match remote {
            SocketAddr::V4(a) => {
                let o = a.ip().octets();
                HostSocketAddr::new(HostAddr::ipv4([o[0], o[1], o[2], o[3]]), a.port())
            }
            SocketAddr::V6(_) => return Err(nb::Error::Other(NalError::UnsupportedAddr)),
        };
        // drogue consumes the handle and returns it on success; move it out and back.
        let s = socket.0.take().ok_or(nb::Error::Other(NalError::NotConnected))?;
        match self.inner.connect(s, host) {
            Ok(s) => {
                socket.0 = Some(s);
                Ok(())
            }
            // On failure the handle is consumed; leave the socket empty for `close`.
            Err(e) => {
                #[cfg(feature = "net-stats")]
                self.stats.connect_fail();
                Err(nb::Error::Other(NalError::Inner(e)))
            }
        }
    }

    fn is_connected(&mut self, socket: &Self::TcpSocket) -> Result<bool, Self::Error> {
        match &socket.0 {
            Some(s) => self.inner.is_connected(s).map_err(NalError::Inner),
            None => Ok(false),
        }
    }

    fn send(
        &mut self,
        socket: &mut Self::TcpSocket,
        buffer: &[u8],
    ) -> nb::Result<usize, Self::Error> {
        let s = socket.0.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        let n = self.inner.write(s, buffer).map_err(map_nb)?;
        #[cfg(feature = "net-stats")]
        self.stats.tcp_tx(n);
        Ok(n)
    }

    fn receive(
        &mut self,
        socket: &mut Self::TcpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<usize, Self::Error> {
        let s = socket.0.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        let n = self.inner.read(s, buffer).map_err(map_nb)?;
        #[cfg(feature = "net-stats")]
        self.stats.tcp_rx(n);
        Ok(n)
    }

    fn close(&mut self, socket: Self::TcpSocket) -> Result<(), Self::Error> {
        match socket.0 {
            Some(s) => {
                let r = self.inner.close(s).map_err(NalError::Inner);
                #[cfg(feature = "net-stats")]
                if r.is_err() {
                    self.stats.close_fail();
                }
                r
            }
            None => Ok(()),
        }
    }
}

/// The IANA dynamic port range a never-bound UDP socket takes its local port from.
const EPHEMERAL_FIRST: u16 = 49152;

/// An `embedded_nal` UDP socket. The module socket opens when the local port is
/// known: at `bind`, or at the first `connect` or `send_to` of an unbound socket.
pub struct NalUdpSocket<S> {
    inner: Option<S>,
    remote: Option<([u8; 4], u16)>,
}

fn ipv4<E>(remote: SocketAddr) -> Result<([u8; 4], u16), NalError<E>> {
    match remote {
        SocketAddr::V4(a) => Ok((a.ip().octets(), a.port())),
        SocketAddr::V6(_) => Err(NalError::UnsupportedAddr),
    }
}

impl<T: TcpStack + UdpDatagrams> NalTcpStack<T>
where
    T::Error: Debug,
{
    fn ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = port.checked_add(1).unwrap_or(EPHEMERAL_FIRST);
        port
    }

    fn open_udp(
        &mut self,
        socket: &mut NalUdpSocket<T::UdpSocket>,
        local_port: u16,
    ) -> Result<(), NalError<T::UdpError>> {
        if socket.inner.is_some() {
            return Ok(());
        }
        socket.inner = Some(self.inner.udp_open(local_port).map_err(NalError::Inner)?);
        Ok(())
    }
}

impl<T: TcpStack + UdpDatagrams> UdpClientStack for NalTcpStack<T>
where
    T::Error: Debug,
{
    type UdpSocket = NalUdpSocket<T::UdpSocket>;
    type Error = NalError<T::UdpError>;

    fn socket(&mut self) -> Result<Self::UdpSocket, Self::Error> {
        Ok(NalUdpSocket {
            inner: None,
            remote: None,
        })
    }

    fn connect(&mut self, socket: &mut Self::UdpSocket, remote: SocketAddr) -> Result<(), Self::Error> {
        let remote = ipv4(remote)?;
        let port = self.ephemeral_port();
        self.open_udp(socket, port)?;
        socket.remote = Some(remote);
        Ok(())
    }

    fn send(&mut self, socket: &mut Self::UdpSocket, buffer: &[u8]) -> nb::Result<(), Self::Error> {
        let (ip, port) = socket.remote.ok_or(nb::Error::Other(NalError::NotConnected))?;
        let inner = socket.inner.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        self.inner
            .udp_send_to(inner, ip, port, buffer)
            .map_err(|e| nb::Error::Other(NalError::Inner(e)))
    }

    fn receive(
        &mut self,
        socket: &mut Self::UdpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<(usize, SocketAddr), Self::Error> {
        let inner = socket.inner.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        let (len, ip, port) = self.inner.udp_recv_from(inner, buffer).map_err(|e| match e {
            nb::Error::WouldBlock => nb::Error::WouldBlock,
            nb::Error::Other(e) => nb::Error::Other(NalError::Inner(e)),
        })?;
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port);
        Ok((len, source))
    }

    fn close(&mut self, socket: Self::UdpSocket) -> Result<(), Self::Error> {
        match socket.inner {
            Some(inner) => self.inner.udp_close(inner).map_err(NalError::Inner),
            None => Ok(()),
        }
    }
}

impl<T: TcpStack + UdpDatagrams> UdpFullStack for NalTcpStack<T>
where
    T::Error: Debug,
{
    fn bind(&mut self, socket: &mut Self::UdpSocket, local_port: u16) -> Result<(), Self::Error> {
        if socket.inner.is_some() {
            return Err(NalError::AlreadyOpen);
        }
        self.open_udp(socket, local_port)
    }

    fn send_to(
        &mut self,
        socket: &mut Self::UdpSocket,
        remote: SocketAddr,
        buffer: &[u8],
    ) -> nb::Result<(), Self::Error> {
        let (ip, port) = ipv4(remote).map_err(nb::Error::Other)?;
        let local = self.ephemeral_port();
        self.open_udp(socket, local).map_err(nb::Error::Other)?;
        let inner = socket.inner.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        self.inner
            .udp_send_to(inner, ip, port, buffer)
            .map_err(|e| nb::Error::Other(NalError::Inner(e)))
    }
}

impl<T: TcpStack + ResolveHost> Dns for NalTcpStack<T>
where
    T::Error: Debug,
{
    type Error = NalError<T::Error>;

    fn get_host_by_name(
        &mut self,
        hostname: &str,
        addr_type: AddrType,
    ) -> nb::Result<IpAddr, Self::Error> {
        // The ISM43362 offload resolver is IPv4-only (A records).
        if let AddrType::IPv6 = addr_type {
            return Err(nb::Error::Other(NalError::UnsupportedAddr));
        }
        #[cfg(feature = "net-stats")]
        self.stats.dns_query(); // count the query issue, like winc-rs
        // Fault injection: a forced-success resolve — a deterministic healthy resolve,
        // without querying the module, to exercise a caller's cache-write path.
        #[cfg(feature = "fault-injection")]
        if let Some(o) = self.resolve_ok {
            #[cfg(feature = "net-stats")]
            self.stats.dns_ok();
            return Ok(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
        }
        // Fault injection: when armed, reproduce the wedge WITHOUT querying
        // the module — count a DNS failure (drives dns_failures/consecutive → resolver-
        // wedge, exactly like a real wedge) and return `ResolveFailed`. The paired
        // `connect` shim below fails the fallback connection too (see there), so this
        // faithfully reproduces a full outage (DNS wedged AND the cold-start fallback IP
        // stale) while never touching the module — so it keeps answering SPI and only
        // name resolution and connect fail. Feature-off builds never reach this.
        #[cfg(feature = "fault-injection")]
        if self.resolve_fault {
            #[cfg(feature = "net-stats")]
            self.stats.dns_fail();
            return Err(nb::Error::Other(NalError::ResolveFailed));
        }
        match self.inner.resolve_host(hostname) {
            // `0.0.0.0` is the ISM43362's wedged-resolver sentinel: the module
            // answers but with the null address. Treat it as a failure, not a valid
            // result — a caller connecting to 0.0.0.0 would only fail later anyway.
            Some(o) if o != [0, 0, 0, 0] => {
                #[cfg(feature = "net-stats")]
                self.stats.dns_ok();
                Ok(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
            }
            _ => {
                #[cfg(feature = "net-stats")]
                self.stats.dns_fail();
                Err(nb::Error::Other(NalError::ResolveFailed))
            }
        }
    }

    // Reverse DNS isn't exposed by the module.
    fn get_host_by_address(
        &mut self,
        _addr: IpAddr,
    ) -> nb::Result<embedded_nal::heapless::String<256>, Self::Error> {
        Err(nb::Error::Other(NalError::UnsupportedAddr))
    }
}

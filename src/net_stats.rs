//! Driver-level network counters (feature `net-stats`), mirroring winc-rs's
//! collection but held per-stack rather than in process-global atomics.
//!
//! winc-rs keeps these as process-global atomics because its host is a monolith and
//! a reader can't borrow the client mid-TLS-session. Here the driver may run inside
//! an isolated (no-global) context whose data grant is only its own stack — a global in
//! shared `.bss` would fault. So the counters live as a field on `NalTcpStack` (in the
//! owner's memory); the owner reads them directly and forwards them.
//!
//! # Honest semantics (same as winc-rs)
//! - App-layer TCP/UDP payload, **not** L2 — ARP/DHCP/DNS/ICMP happen on-chip and are
//!   invisible.
//! - `*_ops` are socket send/receive *calls*, **not** wire packets (the module
//!   fragments/reassembles internally).

/// A snapshot of the driver's network counters. The first 9 fields mirror winc-rs
/// `NetStats` (throughput); the trailing fields are failure/health counters added for
/// module supervision — they let the app detect and measure
/// the DNS-resolver wedge without changing any recovery behavior yet.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    pub tcp_tx_bytes: u32,
    pub tcp_rx_bytes: u32,
    pub tcp_tx_ops: u32,
    pub tcp_rx_ops: u32,
    pub udp_tx_bytes: u32,
    pub udp_rx_bytes: u32,
    pub udp_tx_ops: u32,
    pub udp_rx_ops: u32,
    pub dns_queries: u32,
    /// DNS lookups that failed — the module returned an error, no address, or the
    /// `0.0.0.0` sentinel that signals a wedged on-chip resolver.
    pub dns_failures: u32,
    /// DNS failures since the last success. Climbs while the resolver is wedged and
    /// resets to 0 on any real resolution — the primary wedge signal for supervision.
    pub dns_consecutive_failures: u32,
    /// Socket `connect` attempts that failed (module refused, or SPI error).
    pub connect_failures: u32,
    /// Socket `close` calls that the module did not acknowledge.
    pub socket_close_failures: u32,
}

impl NetStats {
    pub(crate) fn tcp_tx(&mut self, bytes: usize) {
        self.tcp_tx_bytes = self.tcp_tx_bytes.wrapping_add(bytes as u32);
        self.tcp_tx_ops = self.tcp_tx_ops.wrapping_add(1);
    }
    pub(crate) fn tcp_rx(&mut self, bytes: usize) {
        self.tcp_rx_bytes = self.tcp_rx_bytes.wrapping_add(bytes as u32);
        self.tcp_rx_ops = self.tcp_rx_ops.wrapping_add(1);
    }
    #[allow(dead_code)]
    pub(crate) fn udp_tx(&mut self, bytes: usize) {
        self.udp_tx_bytes = self.udp_tx_bytes.wrapping_add(bytes as u32);
        self.udp_tx_ops = self.udp_tx_ops.wrapping_add(1);
    }
    #[allow(dead_code)]
    pub(crate) fn udp_rx(&mut self, bytes: usize) {
        self.udp_rx_bytes = self.udp_rx_bytes.wrapping_add(bytes as u32);
        self.udp_rx_ops = self.udp_rx_ops.wrapping_add(1);
    }
    pub(crate) fn dns_query(&mut self) {
        self.dns_queries = self.dns_queries.wrapping_add(1);
    }
    /// A DNS lookup resolved to a real address — clear the consecutive-failure run.
    pub(crate) fn dns_ok(&mut self) {
        self.dns_consecutive_failures = 0;
    }
    /// A DNS lookup failed (error, no address, or the `0.0.0.0` wedge sentinel).
    pub(crate) fn dns_fail(&mut self) {
        self.dns_failures = self.dns_failures.wrapping_add(1);
        self.dns_consecutive_failures = self.dns_consecutive_failures.wrapping_add(1);
    }
    pub(crate) fn connect_fail(&mut self) {
        self.connect_failures = self.connect_failures.wrapping_add(1);
    }
    pub(crate) fn close_fail(&mut self) {
        self.socket_close_failures = self.socket_close_failures.wrapping_add(1);
    }
}

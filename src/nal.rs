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
use embedded_nal::{SocketAddr, TcpClientStack};

/// Wraps any drogue `TcpStack` (e.g. `Adapter`) as an `embedded_nal` client stack.
pub struct NalTcpStack<T: TcpStack> {
    inner: T,
}

impl<T: TcpStack> NalTcpStack<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
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
        // Blocking mode: drogue's write/read never yield `WouldBlock`, so the nb
        // surface here only ever carries real errors.
        let s = self.inner.open(Mode::Blocking).map_err(NalError::Inner)?;
        Ok(NalSocket(Some(s)))
    }

    fn connect(
        &mut self,
        socket: &mut Self::TcpSocket,
        remote: SocketAddr,
    ) -> nb::Result<(), Self::Error> {
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
            Err(e) => Err(nb::Error::Other(NalError::Inner(e))),
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
        self.inner.write(s, buffer).map_err(map_nb)
    }

    fn receive(
        &mut self,
        socket: &mut Self::TcpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<usize, Self::Error> {
        let s = socket.0.as_mut().ok_or(nb::Error::Other(NalError::NotConnected))?;
        self.inner.read(s, buffer).map_err(map_nb)
    }

    fn close(&mut self, socket: Self::TcpSocket) -> Result<(), Self::Error> {
        match socket.0 {
            Some(s) => self.inner.close(s).map_err(NalError::Inner),
            None => Ok(()),
        }
    }
}

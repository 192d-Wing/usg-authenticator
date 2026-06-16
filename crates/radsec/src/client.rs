//! The `RadSec` connection: a mutually-authenticated TLS 1.3 channel to usg-radius
//! over TCP/2083, carrying RADIUS packets framed by [`crate::framing`].
//!
//! Connection management (one long-lived connection per NAS, reconnect on
//! failure) is the daemon's job; this type provides connect + a request/reply
//! round-trip + access to the stream for accounting and a future `CoA` reader.

use crate::error::RadSecError;
use crate::framing;
use radius_proto::Packet;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Default `RadSec` port (RFC 6614).
pub const RADSEC_PORT: u16 = 2083;

/// An established `RadSec` connection to one authentication server. Every
/// network read is bounded by `io_timeout` so a server that accepts the
/// connection but never replies cannot hang the caller (fail closed); this
/// complements the PAE `ServerTimeout` timer rather than relying on it.
#[derive(Debug)]
pub struct RadSecConnection {
    stream: TlsStream<TcpStream>,
    io_timeout: Duration,
}

impl RadSecConnection {
    /// Open a TCP connection to `addr` and complete the mutual TLS 1.3 handshake
    /// within `io_timeout`, validating the server certificate against
    /// `server_name`. The same `io_timeout` bounds subsequent reads.
    ///
    /// # Errors
    /// - [`RadSecError::BadServerName`] if `server_name` is not a valid DNS name.
    /// - [`RadSecError::Timeout`] if the connect/handshake exceeds `io_timeout`.
    /// - [`RadSecError::Io`] / [`RadSecError::Tls`] on connect/handshake failure
    ///   (including a server cert that fails verification, or a crypto policy the
    ///   peer cannot satisfy — fail closed).
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, RadSecError> {
        let name =
            ServerName::try_from(server_name.to_owned()).map_err(|_| RadSecError::BadServerName)?;
        let connector = TlsConnector::from(config);
        let stream = timeout(io_timeout, async {
            let tcp = TcpStream::connect(addr).await?;
            connector
                .connect(name, tcp)
                .await
                .map_err(RadSecError::from)
        })
        .await
        .map_err(|_| RadSecError::Timeout)??;
        Ok(Self { stream, io_timeout })
    }

    /// Send a RADIUS request and read exactly one reply, checking that the reply's
    /// Identifier matches the request (RFC 2865 §3). The caller MUST still verify
    /// the reply cryptographically (`radius_client::verify_reply`) before acting.
    ///
    /// # Errors
    /// - [`RadSecError::Timeout`] if no reply arrives within `io_timeout`.
    /// - [`RadSecError::UnexpectedReply`] if the reply Identifier mismatches (a
    ///   stale, duplicated, or server-initiated packet).
    /// - framing/codec/I-O errors from [`crate::framing`].
    pub async fn request(&mut self, request: &Packet) -> Result<Packet, RadSecError> {
        framing::write_packet(&mut self.stream, request).await?;
        let reply = self.recv().await?;
        if reply.identifier != request.identifier {
            return Err(RadSecError::UnexpectedReply {
                expected: request.identifier,
                got: reply.identifier,
            });
        }
        Ok(reply)
    }

    /// Send a packet without awaiting a reply (e.g. Accounting where the response
    /// is read separately, or to pipeline).
    ///
    /// # Errors
    /// Propagates framing/codec/I-O errors.
    pub async fn send(&mut self, packet: &Packet) -> Result<(), RadSecError> {
        framing::write_packet(&mut self.stream, packet).await
    }

    /// Read one packet from the connection, bounded by `io_timeout` (e.g. the
    /// reply paired with [`send`]).
    ///
    /// Note: `request` and a future server-initiated `CoA` reader cannot both read
    /// this connection concurrently — when `CoA` (G-2) lands, the daemon needs a
    /// single read loop dispatching by Code/Identifier.
    ///
    /// [`send`]: RadSecConnection::send
    ///
    /// # Errors
    /// - [`RadSecError::Timeout`] if no packet arrives within `io_timeout`.
    /// - framing/codec/I-O errors from [`crate::framing`].
    pub async fn recv(&mut self) -> Result<Packet, RadSecError> {
        timeout(self.io_timeout, framing::read_packet(&mut self.stream))
            .await
            .map_err(|_| RadSecError::Timeout)?
    }
}

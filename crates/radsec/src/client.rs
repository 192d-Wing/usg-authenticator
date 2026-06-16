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
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Default `RadSec` port (RFC 6614).
pub const RADSEC_PORT: u16 = 2083;

/// An established `RadSec` connection to one authentication server.
#[derive(Debug)]
pub struct RadSecConnection {
    stream: TlsStream<TcpStream>,
}

impl RadSecConnection {
    /// Open a TCP connection to `addr` and complete the mutual TLS 1.3 handshake,
    /// validating the server certificate against `server_name`.
    ///
    /// # Errors
    /// - [`RadSecError::BadServerName`] if `server_name` is not a valid DNS name.
    /// - [`RadSecError::Io`] / [`RadSecError::Tls`] on connect/handshake failure
    ///   (including a server cert that fails verification, or a crypto policy the
    ///   peer cannot satisfy — fail closed).
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self, RadSecError> {
        let name =
            ServerName::try_from(server_name.to_owned()).map_err(|_| RadSecError::BadServerName)?;
        let tcp = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(config);
        let stream = connector.connect(name, tcp).await?;
        Ok(Self { stream })
    }

    /// Send a RADIUS request and read exactly one reply (Access-Request →
    /// Access-Challenge/Accept/Reject, or Accounting-Request → -Response). The
    /// caller MUST verify the reply (`radius_client::verify_reply`) before acting.
    ///
    /// # Errors
    /// Propagates framing/codec/I-O errors from [`crate::framing`].
    pub async fn request(&mut self, request: &Packet) -> Result<Packet, RadSecError> {
        framing::write_packet(&mut self.stream, request).await?;
        framing::read_packet(&mut self.stream).await
    }

    /// Send a packet without awaiting a reply (e.g. Accounting where the response
    /// is read separately, or to pipeline).
    ///
    /// # Errors
    /// Propagates framing/codec/I-O errors.
    pub async fn send(&mut self, packet: &Packet) -> Result<(), RadSecError> {
        framing::write_packet(&mut self.stream, packet).await
    }

    /// Read one packet from the connection (e.g. the reply paired with [`send`],
    /// or a server-initiated `CoA` when that lands).
    ///
    /// [`send`]: RadSecConnection::send
    ///
    /// # Errors
    /// Propagates framing/codec/I-O errors.
    pub async fn recv(&mut self) -> Result<Packet, RadSecError> {
        framing::read_packet(&mut self.stream).await
    }
}

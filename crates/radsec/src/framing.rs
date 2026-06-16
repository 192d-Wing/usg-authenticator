//! RADIUS-over-stream framing (RFC 6614 §2.4). `RadSec` carries standard RADIUS
//! packets back-to-back over the TLS byte stream; each packet is self-delimiting
//! via the 16-bit Length field at octets 2..4 of its header.

use crate::error::RadSecError;
use radius_proto::Packet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Smallest valid RADIUS packet (header only) — sourced from `radius-proto` so
/// the framer and the codec can never disagree on bounds.
pub const MIN_RADIUS_LEN: usize = Packet::MIN_PACKET_SIZE;
/// Largest RADIUS packet we accept — sourced from `radius-proto`.
pub const MAX_RADIUS_LEN: usize = Packet::MAX_PACKET_SIZE;
/// Octets in the RADIUS header (`code | id | length(2)`).
const HEADER_LEN: usize = 4;

/// The packet length declared by a 4-octet RADIUS header.
#[must_use]
pub fn declared_length(header: &[u8; HEADER_LEN]) -> usize {
    let [_code, _id, hi, lo] = *header;
    usize::from(u16::from_be_bytes([hi, lo]))
}

/// Read one RADIUS packet from the stream: read the 4-octet header, validate the
/// declared length, read the remainder, and decode.
///
/// # Errors
/// - [`RadSecError::Io`] on a short read / closed connection.
/// - [`RadSecError::BadFrameLength`] if the declared length is outside 20..=4096.
/// - [`RadSecError::Proto`] if the bytes do not decode as RADIUS.
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Packet, RadSecError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let len = declared_length(&header);
    if !(MIN_RADIUS_LEN..=MAX_RADIUS_LEN).contains(&len) {
        return Err(RadSecError::BadFrameLength(len));
    }
    let body_len = len
        .checked_sub(HEADER_LEN)
        .ok_or(RadSecError::BadFrameLength(len))?;
    let mut buf = header.to_vec();
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    buf.extend_from_slice(&body);
    Packet::decode(&buf).map_err(RadSecError::Proto)
}

/// Encode a RADIUS packet and write it to the stream, flushing.
///
/// # Errors
/// - [`RadSecError::Proto`] if the packet cannot be encoded.
/// - [`RadSecError::Io`] on a write failure.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &Packet,
) -> Result<(), RadSecError> {
    let bytes = packet.encode().map_err(RadSecError::Proto)?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

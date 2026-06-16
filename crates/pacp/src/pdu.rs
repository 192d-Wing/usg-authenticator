//! The EAPOL PDU: `Protocol Version(1) | Packet Type(1) | Body Length(2) | Body`.
//!
//! IEEE Std 802.1X-2020 §11.3. The codec decodes the fixed header and slices the
//! body using the authoritative Body Length field; trailing octets (Ethernet
//! padding) are ignored. The body is kept opaque here — interpreting an
//! EAPOL-EAP body as an EAP packet is [`crate::eap`]'s job, and Key/MKA/
//! Announcement bodies are out of scope for the pass-through authenticator.

use super::error::PacpError;

/// Octets in an EAPOL PDU header: `version(1) | type(1) | body_length(2)`.
pub const HEADER_LEN: usize = 4;

/// EAPOL protocol version 3 (IEEE 802.1X-2010 and -2020).
pub const PROTOCOL_VERSION_2010: u8 = 3;
/// EAPOL protocol version 2 (IEEE 802.1X-2004).
pub const PROTOCOL_VERSION_2004: u8 = 2;
/// EAPOL protocol version 1 (IEEE 802.1X-2001).
pub const PROTOCOL_VERSION_2001: u8 = 1;

/// EAPOL packet type (IEEE 802.1X-2020 Table 11-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// EAPOL-EAP (0): the body is an EAP packet — the pass-through payload.
    Eap,
    /// EAPOL-Start (1).
    Start,
    /// EAPOL-Logoff (2).
    Logoff,
    /// EAPOL-Key (3).
    Key,
    /// EAPOL-Encapsulated-ASF-Alert (4).
    EncapsulatedAsfAlert,
    /// EAPOL-MKA (5): `MACsec` Key Agreement.
    Mka,
    /// EAPOL-Announcement, Generic (6).
    AnnouncementGeneric,
    /// EAPOL-Announcement, Specific (7).
    AnnouncementSpecific,
    /// EAPOL-Announcement-Req (8).
    AnnouncementReq,
    /// An unassigned/reserved packet type, preserved verbatim.
    Unknown(u8),
}

impl PacketType {
    /// The on-the-wire octet for this packet type.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Eap => 0,
            Self::Start => 1,
            Self::Logoff => 2,
            Self::Key => 3,
            Self::EncapsulatedAsfAlert => 4,
            Self::Mka => 5,
            Self::AnnouncementGeneric => 6,
            Self::AnnouncementSpecific => 7,
            Self::AnnouncementReq => 8,
            Self::Unknown(v) => v,
        }
    }

    /// Decode a packet-type octet. Unassigned values map to
    /// [`PacketType::Unknown`] rather than failing — the frame is still
    /// well-formed and the state machine decides what to do with it.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Eap,
            1 => Self::Start,
            2 => Self::Logoff,
            3 => Self::Key,
            4 => Self::EncapsulatedAsfAlert,
            5 => Self::Mka,
            6 => Self::AnnouncementGeneric,
            7 => Self::AnnouncementSpecific,
            8 => Self::AnnouncementReq,
            other => Self::Unknown(other),
        }
    }
}

/// A decoded EAPOL PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolPdu {
    /// Protocol version octet (sent verbatim; the authenticator does not
    /// downgrade-negotiate here).
    pub version: u8,
    /// The packet type.
    pub packet_type: PacketType,
    /// The body, exactly `body_length` octets (no trailing padding).
    pub body: Vec<u8>,
}

impl EapolPdu {
    /// Construct a PDU with the default protocol version (3, 802.1X-2010/2020).
    #[must_use]
    pub fn new(packet_type: PacketType, body: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION_2010,
            packet_type,
            body,
        }
    }

    /// Decode an EAPOL PDU from `buf` (the Ethernet payload).
    ///
    /// The Body Length field is authoritative: octets beyond it (Ethernet
    /// padding) are ignored, but a Body Length larger than the buffer is an
    /// error — never a silent short read.
    ///
    /// # Errors
    /// - [`PacpError::TruncatedEapolHeader`] if fewer than [`HEADER_LEN`] octets exist.
    /// - [`PacpError::TruncatedEapolBody`] if the declared body exceeds the buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, PacpError> {
        let [version, type_octet, len_hi, len_lo] = buf
            .get(..HEADER_LEN)
            .and_then(|s| <[u8; HEADER_LEN]>::try_from(s).ok())
            .ok_or(PacpError::TruncatedEapolHeader {
                available: buf.len(),
            })?;

        let declared = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        let body_end = HEADER_LEN.saturating_add(declared);
        let body = buf
            .get(HEADER_LEN..body_end)
            .ok_or(PacpError::TruncatedEapolBody {
                declared,
                available: buf.len().saturating_sub(HEADER_LEN),
            })?;

        Ok(Self {
            version,
            packet_type: PacketType::from_u8(type_octet),
            body: body.to_vec(),
        })
    }

    /// Serialize this PDU onto `out`.
    ///
    /// # Errors
    /// - [`PacpError::BodyTooLong`] if the body exceeds the 16-bit length field.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), PacpError> {
        let len = u16::try_from(self.body.len()).map_err(|_| PacpError::BodyTooLong {
            len: self.body.len(),
        })?;
        out.push(self.version);
        out.push(self.packet_type.to_u8());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(())
    }

    /// Serialize this PDU to a fresh buffer.
    ///
    /// # Errors
    /// See [`EapolPdu::encode_into`].
    pub fn encode(&self) -> Result<Vec<u8>, PacpError> {
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.body.len()));
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Serialize this PDU as a full Ethernet frame from `src` to `dst`.
    ///
    /// # Errors
    /// See [`EapolPdu::encode_into`].
    pub fn encode_frame(
        &self,
        dst: super::ethernet::MacAddr,
        src: super::ethernet::MacAddr,
    ) -> Result<Vec<u8>, PacpError> {
        let header = super::ethernet::EthernetHeader {
            dst,
            src,
            ethertype: super::ethernet::ETHERTYPE_EAPOL,
        };
        let mut out = Vec::with_capacity(super::ethernet::HEADER_LEN.saturating_add(HEADER_LEN));
        header.encode_into(&mut out);
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

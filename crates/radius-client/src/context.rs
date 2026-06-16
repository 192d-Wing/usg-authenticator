//! The per-request NAS identity attributes the authenticator includes on every
//! Access-Request and Accounting-Request (SERVER-CONTRACT.md §2).

use crate::consts::{NAS_PORT_ID, NAS_PORT_TYPE_ETHERNET};
use crate::error::RadiusClientError;
use pacp::ethernet::{MacAddr, format_mac};
use radius_proto::{Attribute, AttributeType, Packet};

/// Identity of the NAS and the access port for one supplicant.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// `NAS-IP-Address` (IPv4). Optional; an IPv6-only NAS relies on
    /// `NAS-Identifier` until usg-radius parses `NAS-IPv6-Address` (V-1).
    pub nas_ip: Option<[u8; 4]>,
    /// `NAS-Identifier` — the switch hostname.
    pub nas_identifier: String,
    /// `NAS-Port-Id` — the front-panel interface name (e.g. `Ethernet12`).
    pub nas_port_id: String,
    /// `NAS-Port` — the numeric port index, if used.
    pub nas_port: Option<u32>,
    /// `Calling-Station-Id` — the supplicant MAC.
    pub calling_station: MacAddr,
    /// `Called-Station-Id` — the switch port MAC.
    pub called_station: MacAddr,
}

impl RequestContext {
    /// Append the common NAS/port attributes to `packet`.
    ///
    /// # Errors
    /// Propagates [`RadiusClientError::Proto`] if any attribute is malformed
    /// (e.g. an over-long `NAS-Identifier`).
    pub fn append_nas_attributes(&self, packet: &mut Packet) -> Result<(), RadiusClientError> {
        if let Some(ip) = self.nas_ip {
            packet.add_attribute(Attribute::ipv4(AttributeType::NasIpAddress as u8, ip)?);
        }
        packet.add_attribute(Attribute::string(
            AttributeType::NasIdentifier as u8,
            self.nas_identifier.clone(),
        )?);
        packet.add_attribute(Attribute::string(NAS_PORT_ID, self.nas_port_id.clone())?);
        packet.add_attribute(Attribute::integer(
            AttributeType::NasPortType as u8,
            NAS_PORT_TYPE_ETHERNET,
        )?);
        if let Some(port) = self.nas_port {
            packet.add_attribute(Attribute::integer(AttributeType::NasPort as u8, port)?);
        }
        packet.add_attribute(Attribute::string(
            AttributeType::CallingStationId as u8,
            format_mac(&self.calling_station),
        )?);
        packet.add_attribute(Attribute::string(
            AttributeType::CalledStationId as u8,
            format_mac(&self.called_station),
        )?);
        Ok(())
    }
}

//! The per-port async event loop and the concrete boundary adapters binding the
//! real component crates (`eapol-io`, `radsec`, a tokio timer scheduler) to the
//! [`crate::dispatch`] orchestrator.
//!
//! Integration boundary: this wiring runs against real sockets / RadSec / SONiC
//! on the target (trio integration). The orchestration it drives ([`crate::dispatch`],
//! [`crate::session`]) is unit-tested with mocks. The enforcer is left generic so
//! the daemon can bind the SONiC backend once its DbConn is provided.

use crate::dispatch::{AuthServer, Deps, Orchestrator, Scheduler, SupplicantLink};
use crate::error::AuthdError;
use core::time::Duration;
use enforce::Enforcer;
use pacp::ethernet::MacAddr;
use pae::{Event, InboundEap, PaeConfig, PortPae, TimerKind, Timers};
use radius_client::RequestContext;
use radius_proto::Packet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Wraps an [`eapol_io::EapolSocket`] as the supplicant link: EAP packets are
/// framed in EAPOL and sent out the port toward the supplicant MAC.
#[derive(Debug)]
pub struct EapolSupplicant {
    sock: Arc<eapol_io::EapolSocket>,
    src: MacAddr,
}

impl SupplicantLink for EapolSupplicant {
    async fn send_eap(&self, mac: MacAddr, eap: Vec<u8>) -> Result<(), AuthdError> {
        let pdu = pacp::pdu::EapolPdu::new(pacp::pdu::PacketType::Eap, eap);
        let frame = pdu.encode_frame(mac, self.src).map_err(AuthdError::Frame)?;
        self.sock.send(&frame).await.map_err(AuthdError::Eapol)
    }
}

/// Wraps a [`radsec::RadSecConnection`] as the RADIUS auth server.
#[derive(Debug)]
pub struct RadSecServer {
    conn: tokio::sync::Mutex<radsec::RadSecConnection>,
}

impl AuthServer for RadSecServer {
    async fn access_request(&self, request: &Packet) -> Result<Packet, AuthdError> {
        let mut conn = self.conn.lock().await;
        conn.request(request).await.map_err(AuthdError::RadSec)
    }

    async fn accounting(&self, request: &Packet) -> Result<(), AuthdError> {
        let mut conn = self.conn.lock().await;
        // Read and discard the Accounting-Response (its identifier is checked
        // against the request by `RadSecConnection::request`).
        conn.request(request).await.map_err(AuthdError::RadSec)?;
        Ok(())
    }
}

/// A tokio-backed [`Scheduler`]: each armed timer is a spawned task that sleeps
/// then delivers `Event::Timer` over a channel back to the port loop.
#[derive(Debug)]
pub struct TokioScheduler {
    tx: mpsc::UnboundedSender<(MacAddr, Event)>,
    handles: Mutex<HashMap<(MacAddr, TimerKind), tokio::task::AbortHandle>>,
}

impl TokioScheduler {
    fn new(tx: mpsc::UnboundedSender<(MacAddr, Event)>) -> Self {
        Self {
            tx,
            handles: Mutex::new(HashMap::new()),
        }
    }
}

impl Scheduler for TokioScheduler {
    fn arm(&self, mac: MacAddr, kind: TimerKind, dur: Duration) {
        let tx = self.tx.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(dur).await;
            let _ = tx.send((mac, Event::Timer(kind)));
        });
        if let Ok(mut handles) = self.handles.lock()
            && let Some(old) = handles.insert((mac, kind), task.abort_handle())
        {
            old.abort();
        }
    }

    fn cancel(&self, mac: MacAddr, kind: TimerKind) {
        if let Ok(mut handles) = self.handles.lock()
            && let Some(h) = handles.remove(&(mac, kind))
        {
            h.abort();
        }
    }

    fn cancel_all(&self, mac: MacAddr) {
        if let Ok(mut handles) = self.handles.lock() {
            let keys: Vec<_> = handles.keys().filter(|(m, _)| *m == mac).copied().collect();
            for key in keys {
                if let Some(h) = handles.remove(&key) {
                    h.abort();
                }
            }
        }
    }
}

/// The static per-port parameters for [`run_port`].
#[derive(Debug, Clone)]
pub struct PortSetup {
    /// Front-panel interface name.
    pub port: String,
    /// The switch port's own MAC (the EAPOL source / `Called-Station-Id`).
    pub switch_mac: MacAddr,
    /// PAE policy.
    pub pae_cfg: PaeConfig,
    /// Timer durations.
    pub timers: Timers,
    /// RADIUS shared secret.
    pub secret: Vec<u8>,
    /// NAS attribute template (per-MAC `calling_station` filled in per request).
    pub ctx_template: RequestContext,
}

/// Run the 802.1X event loop for one port until the socket errors. Closes the
/// port (via the enforcer) before servicing it and decodes inbound EAPOL into
/// PAE events; timer expiries arrive over an internal channel.
///
/// # Errors
/// Propagates the first fatal boundary error (trap install, socket open, etc.).
pub async fn run_port<E>(
    setup: PortSetup,
    enforcer: &E,
    conn: radsec::RadSecConnection,
) -> Result<(), AuthdError>
where
    E: Enforcer,
    E::Error: core::fmt::Display,
{
    let PortSetup {
        port,
        switch_mac,
        pae_cfg,
        timers,
        secret,
        ctx_template,
    } = setup;

    // Fail closed: do not service a port whose EAPOL trap / closed posture the
    // dataplane cannot confirm.
    enforcer
        .ensure_eapol_trap(&port)
        .await
        .map_err(|e| AuthdError::Enforce(e.to_string()))?;

    let sock = Arc::new(eapol_io::EapolSocket::open(&port)?);
    let supplicant = EapolSupplicant {
        sock: Arc::clone(&sock),
        src: switch_mac,
    };
    let server = RadSecServer {
        conn: tokio::sync::Mutex::new(conn),
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let scheduler = TokioScheduler::new(tx);

    let mut orch = Orchestrator::new(port, ctx_template);
    let mut pae = PortPae::new(pae_cfg);
    let deps = Deps {
        supplicant: &supplicant,
        server: &server,
        enforcer,
        scheduler: &scheduler,
        timers: &timers,
        secret: &secret,
    };

    // Bring the port into service: port-wide unauthorized.
    orch.apply_effects(pae.enable(), &deps).await?;

    loop {
        tokio::select! {
            frame = sock.recv() => {
                let bytes = frame?;
                dispatch_frame(&bytes, &mut orch, &mut pae, &deps).await?;
            }
            Some((mac, event)) = rx.recv() => {
                orch.handle_event(&mut pae, mac, event, &deps).await?;
            }
        }
    }
}

/// Decode one inbound EAPOL frame into a PAE event and feed it through.
async fn dispatch_frame<S, A, E, C>(
    bytes: &[u8],
    orch: &mut Orchestrator,
    pae: &mut PortPae,
    deps: &Deps<'_, S, A, E, C>,
) -> Result<(), AuthdError>
where
    S: SupplicantLink,
    A: AuthServer,
    E: Enforcer,
    E::Error: core::fmt::Display,
    C: Scheduler,
{
    let Ok(frame) = pacp::decode_frame(bytes) else {
        return Ok(()); // not a well-formed EAPOL frame; ignore
    };
    let mac = frame.ethernet.src;
    let event = match frame.pdu.packet_type {
        pacp::pdu::PacketType::Start => Event::EapolStart,
        pacp::pdu::PacketType::Logoff => Event::EapolLogoff,
        pacp::pdu::PacketType::Eap => {
            let Ok(eap) = pacp::eap::EapPacket::decode(&frame.pdu.body) else {
                return Ok(());
            };
            Event::EapFromSupplicant(InboundEap {
                code: eap.code,
                identifier: eap.identifier,
                eap_type: eap.eap_type,
                packet: frame.pdu.body.clone(),
            })
        }
        // Key / MKA / Announcement frames are not part of the pass-through.
        _ => return Ok(()),
    };
    orch.handle_event(pae, mac, event, deps).await
}

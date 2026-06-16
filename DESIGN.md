# Design: usg-authenticator — IEEE 802.1X-2020 Authenticator (NAS) for SONiC Whiteboxes (Rust)

**Status:** DRAFT v1 for review. No implementation code yet. Stop-and-review gate.

This is the middle leg of the **802.1X Trio**:

```
usg-supplicant  ──EAPOL/L2──▶  usg-authenticator  ──EAP-over-RadSec──▶  usg-radius
 (Windows TEAP peer)            (this repo: the NAS                       (EAP/TEAP
                                 on the whitebox switch)                   auth server)
```

The authenticator is a **pure EAP pass-through** Port Access Entity (PAE). It never terminates EAP or TEAP, never sees inside the TLS tunnel, and holds no user/machine credentials. Its jobs: run the 802.1X authenticator state machines, carry EAP between EAPOL (to the supplicant) and RADIUS (to usg-radius), and enforce the resulting authorization on the SONiC dataplane.

**Locked decisions (from review):**
1. **Dataplane = SONiC (SAI/swss).** Port authorization, dynamic VLAN, and dynamic ACLs are programmed through SONiC's Redis databases; EAPOL is trapped to CPU via a SAI host-interface trap. ✅
2. **RADIUS leg = RadSec (RADIUS over TLS 1.3, RFC 6614),** FIPS via aws-lc-rs, mutually authenticated to usg-radius. **Key exchange = ML-KEM-1024 only** (FIPS 203; no classical or hybrid groups). No cleartext UDP RADIUS in v1. ✅
3. **EAP pass-through only.** No EAP method logic, no TEAP, no crypto on the EAP payload itself. ✅
4. **v1 feature set:** core PAE + controlled-port; dynamic VLAN + dACL; MAB + guest/auth-fail/critical VLAN; CoA/Disconnect (RFC 5176). ✅
5. **EAPOL transport (recommendation, see §4):** **AF_PACKET raw socket on the SONiC front-panel host netdev**, gated by an explicit SAI EAPOL trap. ✅ proposed

---

## 1. Scope & non-goals

**In scope:**
- IEEE **802.1X-2020** Authenticator PAE on wired SONiC ports: PACP (EAPOL) + the authenticator PAE/backend-auth state machines.
- **EAP pass-through** to usg-radius over **RadSec** (RFC 6614), encapsulating EAP per RFC 3579 (`EAP-Message`, `Message-Authenticator`).
- **Authorization enforcement** from `Access-Accept`: controlled-port open/close, **dynamic VLAN** (RFC 3580 `Tunnel-*`), **dynamic/downloadable ACL** (`Filter-Id` and vendor dACL).
- **MAB** (MAC Authentication Bypass) for non-802.1X endpoints; **guest VLAN**, **auth-fail VLAN**, **critical VLAN** (RADIUS-unreachable) fallbacks.
- **CoA / Disconnect** (RFC 5176): server-initiated re-auth, authorization change, and session termination — the lever usg-radius / usg-nac pull to kick or re-evaluate a port.
- **RADIUS accounting** (RFC 2866) for session start/stop/interim — needed for usg-radius session tracking and CoA targeting.
- **Per-port host modes:** single-host, multi-host, multi-auth, multi-domain (data+voice).

**Out of scope now:** wireless / 802.11; non-SONiC dataplanes (the enforcement layer is behind a trait so Linux/switchdev can be added later, but only SAI/swss ships in v1); MACsec / 802.1AE key agreement (MKA); any EAP method implementation; IPv4-only deployments are supported but IPv6 is primary (matches the fleet).

---

## 2. Workspace layout

`pacp`, `pae`, and `radius-client` are pure and fully unit-testable with no OS, no Redis, no network. SONiC/Linux coupling is isolated in `enforce-sonic` and `eapol-io`. This mirrors usg-supplicant's "pure core, thin platform shim" split.

```
usg-authenticator/
├─ Cargo.toml                  # workspace
├─ DESIGN.md
├─ crates/
│  ├─ pacp/                    # EAPOL/PACP frame codec (EAPOL-Start/Logoff/EAP/Key/
│  │                           #   Announcement), version handling. No I/O.  #![forbid(unsafe)]
│  ├─ pae/                     # 802.1X-2020 authenticator state machines + session model:
│  │   └─ src/{auth_pae.rs, backend_auth.rs, reauth.rs, port_session.rs, hostmode.rs}
│  │                           #   pure; driven by typed events, emits typed effects. No I/O.
│  ├─ radius-client/           # EAP-over-RADIUS *client*: build Access-Request, parse
│  │   └─ src/{request.rs, accept.rs, accounting.rs, coa_listen.rs, attrs.rs}
│  │                           #   reuses usg-radius `radius-proto` codec. No transport.
│  ├─ radsec/                  # RadSec transport (RFC 6614): TLS 1.3 over TCP to usg-radius,
│  │   └─ src/{client.rs, fips.rs, reconnect.rs}        #   aws-lc-rs FIPS, mutual auth.
│  ├─ enforce/                 # Enforcer trait: authorize/deauthorize port, set VLAN, apply ACL.
│  │   └─ src/{enforcer.rs, model.rs}                   #   pure trait + desired-state model.
│  ├─ enforce-sonic/           # SAI/swss backend: writes CONFIG_DB/APPL_DB, programs hostif
│  │   └─ src/{redis.rs, port_auth.rs, vlan.rs, acl.rs, trap.rs}   #   EAPOL trap. unsafe-free.
│  ├─ eapol-io/                # AF_PACKET raw-socket rx/tx of 0x888e on front-panel netdevs.
│  │   └─ src/{socket.rs, ifindex.rs}                   #   confined unsafe (libc), justified.
│  ├─ authd/                   # the daemon: wires pacp+pae+radius+enforce; config, supervisor,
│  │   └─ src/{main.rs, port_manager.rs, config.rs, telemetry.rs}
│  └─ cli/                     # diagnostics: show 802.1x, fips-check, decode EAPOL/RADIUS captures
└─ tests/                      # recorded EAPOL+RADIUS exchanges, PAE state-machine scripts, KAT
```

> The **pure core** (`pacp`/`pae`/`radius-client`) can be exercised end-to-end with scripted byte streams and event logs — no switch required. This is what makes the authenticator testable in CI without hardware.

---

## 3. SONiC / SAI enforcement strategy (locked)

The authenticator does **not** call SAI directly. It follows SONiC's contract: **write desired state to the Redis databases and let `orchagent` program the ASIC.** This keeps us ABI-stable across SONiC releases and avoids linking libsai.

| Action | Mechanism (SONiC) |
|---|---|
| Trap EAPOL (0x888e) to CPU | SAI **host-interface trap** for EAPOL via CoPP: ensure a `COPP_TRAP`/`COPP_GROUP` entry exists (trap id `eapol`), action = trap, so frames arrive on the port's host netdev. Programmed once at startup by `enforce-sonic::trap`. |
| Controlled-port = unauthorized | Default-deny: port admitted only to a **restricted context** (no data VLAN). Implemented as ACL drop of non-EAPOL ingress on that port (allow 0x888e to CPU) until authorized. |
| Controlled-port = authorized | Remove/relax the restrictive ACL; place port in its assigned VLAN. |
| Dynamic VLAN | Write `VLAN`/`VLAN_MEMBER` (and `PORT` PVID) in CONFIG_DB to move the port into the RADIUS-assigned VLAN; revert on deauth. |
| Dynamic / downloadable ACL | Program an `ACL_TABLE` + `ACL_RULE` set in CONFIG_DB bound to the port, from `Filter-Id` (named, pre-provisioned) or a vendor dACL (inline rules). |
| Multi-auth / per-MAC | Enforcement is per **{port, MAC}**: ACL rules match source MAC so multiple supplicants on one port get independent authorization (FDB-assisted). |

- **Backend boundary:** all of this sits behind the `enforce::Enforcer` trait (`enforce` crate). `enforce-sonic` is the only v1 implementation; a `enforce-linux` (nftables/bridge) backend can follow for dev boxes without changing `authd`/`pae`. This mirrors usg-nos's backend-neutral dataplane split.
- **Redis access:** plain RESP client to the SONiC Redis (CONFIG_DB id 4, APPL_DB id 0, ASIC_DB id 1 for read-back/verify). We **write CONFIG_DB / APPL_DB and read-back ASIC_DB** to confirm the ASIC actually programmed the rule (fail closed if it didn't — never report "authorized" on an unconfirmed port).
- **Reconciliation, not fire-and-forget:** `enforce-sonic` keeps a desired-state map per port and reconciles on reconnect/`orchagent` restart, so authorization survives a swss bounce.

---

## 4. EAPOL L2 transport (recommendation)

**Recommendation: AF_PACKET raw socket on the SONiC front-panel host netdev (`EthernetN`), gated by the SAI EAPOL trap from §3.**

Rationale, and why not the alternatives:
- On SONiC, front-panel ports surface as kernel netdevs (`EthernetN`) backed by the ASIC CPU port. With the EAPOL **host-interface trap** installed, 0x888e frames are punted to CPU and delivered on the matching netdev. An `AF_PACKET`/`SOCK_RAW` socket bound to ethertype `0x888e` on that netdev is the simplest correct rx/tx path, and EAPOL responses we `sendto()` are injected back out the physical port. This is the hostapd model and is well-trodden on SONiC.
- **NOS punt/inject API** (the other option offered): cleaner in theory but on SONiC there is no general userspace punt API distinct from the host netdev — the netdev *is* the punt path. So "punt API" collapses to the same AF_PACKET socket plus the trap config. We therefore take AF_PACKET explicitly and own the trap config in `enforce-sonic`.
- **Unsafe is confined** to `eapol-io` (the `libc`/`AF_PACKET` `setsockopt`/`bind` calls), justified in-comment, and wrapped behind a safe `EapolPort { recv() -> Frame, send(Frame) }` API. Everything above it is `#![forbid(unsafe_code)]`.
- We bind per controlled port (one socket per `EthernetN`) using a `PACKET_FANOUT`-free, BPF-filtered (`0x888e` only) socket; a small epoll/`tokio` reactor multiplexes them in `authd`.

**Fail-closed coupling:** if the EAPOL trap is not confirmed present in ASIC_DB, `authd` refuses to bring the port into 802.1X service (a silently-untrapped port would "authenticate" no one and quietly fail open — unacceptable).

---

## 5. PAE & backend-auth state machine (`pae`, IEEE 802.1X-2020)

Pure, I/O-free: driven by typed **events** (EAPOL frame in, RADIUS result in, timer fired, CoA request) and emits typed **effects** (send EAPOL, send RADIUS, set port-auth, start timer). `authd` is the only thing that performs effects.

### 5.1 Per-{port, session} authenticator PAE (condensed)

| State | Input | Action | Next |
|---|---|---|---|
| `Initialize` | port enabled for 802.1X | install restrictive ACL (unauthorized); arm `tx-period` | `Connecting` |
| `Connecting` | EAPOL-Start \| link-up | send EAP-Request/Identity | `Authenticating` |
| `Connecting` | no supplicant after N `tx-period` | → MAB (§6.1) or guest VLAN (§6.2) | `MabOrGuest` |
| `Authenticating` | EAP-Response/Identity | wrap in Access-Request → usg-radius | `AuthRadius` |
| `AuthRadius` | RADIUS Access-Challenge | unwrap EAP-Request → EAPOL to supplicant | `Authenticating` |
| `AuthRadius` | **Access-Accept** | apply authorization (§6.3); port authorized | `Authenticated` |
| `AuthRadius` | **Access-Reject** | → auth-fail VLAN (§6.2) or keep unauthorized | `Held` |
| `AuthRadius` | RADIUS timeout (server unreachable) | → critical VLAN (§6.2) | `Critical` |
| `Authenticated` | `reAuthWhen` timer \| CoA-Request(re-auth) | restart auth, keep port up meanwhile | `Authenticating` |
| `Authenticated` | EAPOL-Logoff \| link-down \| CoA-Disconnect | deauthorize; restrictive ACL; Acct-Stop | `Initialize` |
| any | CoA Authorization change | apply new VLAN/ACL in place (no re-auth) | (same) |
| `Held` | `quietWhile` elapsed | allow retry | `Connecting` |

- **Fail-closed default edge:** any unhandled/malformed input, enforcement failure, or FIPS/RadSec failure ⇒ port stays/returns **unauthorized**.
- **Timers** (configurable, 802.1X defaults): `tx-period`, `quiet-period`, `reAuthPeriod`, `serverTimeout`, `suppTimeout`, `held-period`.
- **Host modes** (`hostmode.rs`): `single-host` (one MAC, others dropped), `multi-host` (first auth opens port for all), `multi-auth` (each MAC authenticated independently — default for security), `multi-domain` (one data + one voice via device-traffic-class). Sessions are keyed `{port, mac}` so multi-auth is the general case and the others are restrictions of it.

### 5.2 RADIUS request construction (`radius-client`)
- `Access-Request` carries: `EAP-Message` (fragmented per RFC 3579), `Message-Authenticator` (mandatory, HMAC — see §7), `User-Name` (from EAP-Identity / MAC for MAB), `NAS-IP-Address`/`NAS-Identifier`, `NAS-Port`/`NAS-Port-Id` (the `EthernetN`), `NAS-Port-Type=Ethernet(15)`, `Calling-Station-Id` (supplicant MAC), `Called-Station-Id` (switch MAC), `Service-Type=Framed`, `Connect-Info`.
- Reuses **`radius-proto`** from usg-radius for packet/attribute/EAP/Message-Authenticator codec — we add the *client* request/response orchestration and the CoA listener only.

---

## 6. v1 feature behaviors

### 6.1 MAB (MAC Authentication Bypass)
- Triggered when no EAPOL appears within `tx-period × max-reauth-req` (or per-port "MAB-first" policy). The switch sends an `Access-Request` with `User-Name`/`Calling-Station-Id` = the source MAC and `Service-Type=Call-Check`; no EAP. usg-radius decides. Lower priority than 802.1X: a later EAPOL-Start preempts a MAB session.

### 6.2 Fallback VLANs
- **Guest VLAN:** no supplicant + MAB declined/disabled ⇒ port placed in a limited guest VLAN.
- **Auth-fail VLAN:** `Access-Reject` ⇒ optional restricted VLAN instead of hard-closed (configurable; default = stay unauthorized).
- **Critical VLAN:** **all** configured RADIUS servers unreachable ⇒ port placed in a critical-auth VLAN (fail-*open to a defined posture*, not wide open) and re-evaluated when a server returns. This is the one deliberate non-fail-closed path and is explicitly opt-in per port.

### 6.3 Authorization from `Access-Accept`
- **VLAN:** RFC 3580 `Tunnel-Type=VLAN(13)`, `Tunnel-Medium-Type=802(6)`, `Tunnel-Private-Group-ID` = VLAN id/name → program VLAN membership (§3).
- **dACL:** `Filter-Id` (name of a pre-provisioned `ACL_TABLE`) and/or vendor downloadable ACL (inline ACEs) → program `ACL_RULE`s bound to {port, MAC}.
- **Session-Timeout** + **Termination-Action=RADIUS-Request(1)** → set `reAuthWhen`. **Idle-Timeout** honored where FDB activity is observable.

### 6.4 CoA / Disconnect (RFC 5176)
- `radius-client::coa_listen` runs a CoA listener **over the same RadSec channel** (RADIUS-over-TLS carries CoA/Disconnect on the established mutually-authenticated connection — no separate open UDP/3799 port to firewall and spoof). Falls back to RFC 5176 semantics on the connection.
- **Disconnect-Request** → terminate the {port, MAC} session, Acct-Stop, port to unauthorized. Reply `Disconnect-ACK`/`NAK`.
- **CoA-Request** → either re-auth (`State`/`Service-Type` per profile) or apply changed VLAN/ACL in place. Reply `CoA-ACK`/`NAK`.
- Session identification via `Acct-Session-Id` + `Calling-Station-Id` + `NAS-Port-Id` (set at accounting start). Unknown session ⇒ NAK with `Error-Cause=Session-Context-Not-Found(503)`.

---

## 7. FIPS & crypto boundary

| Operation | Module | Notes |
|---|---|---|
| RadSec TLS 1.3 (records, KDF, exporter) | **aws-lc-rs FIPS** via rustls | TLS 1.3 only; suite allow-list `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`; **key exchange = ML-KEM-1024 only** (FIPS 203; rustls `aws_lc_rs::kx_group::MLKEM1024`, no classical/hybrid groups); mutual auth (switch presents a NAS client cert; pins usg-radius server cert/CA). |
| RADIUS `Message-Authenticator` (HMAC-MD5) | tolerated *inside* the RadSec tunnel | RFC 3579 mandates HMAC-**MD5**, which is **not** FIPS-approved. It is computed only as a RADIUS-protocol integrity field **inside** the TLS 1.3 FIPS tunnel, never as the security boundary. Documented as a protocol artifact, not a security claim — the tunnel is the boundary. |
| Switch NAS client key | local key store / TPM (deployment-defined) | Used only for the RadSec TLS client cert. |

- **Fail-closed self-check** (`cli fips-check`, at daemon init and before first RadSec connect): assert rustls `CryptoProvider.fips() == true`, the cipher-suite allow-list, and that the **only** offered/accepted key-exchange group is `ML-KEM-1024` (reject a handshake that negotiates anything else). Any failure ⇒ daemon refuses to authorize ports.
- We do **not** see or touch EAP/TEAP inner crypto — that is end-to-end between usg-supplicant and usg-radius. The authenticator's only crypto responsibility is the RadSec tunnel and the (in-tunnel) RADIUS integrity field.

---

## 8. Error handling & testing

- One `thiserror` enum per crate; **fail closed** on: malformed EAPOL/RADIUS, missing/failed `Message-Authenticator`, RadSec/FIPS failure, enforcement-not-confirmed (ASIC_DB read-back), unknown CoA session, untrapped EAPOL port. No path silently authorizes.
- **Security baseline (mirrors usg-supplicant):** `#![forbid(unsafe_code)]` in pure crates (`pacp`, `pae`, `radius-client`, `enforce`); `unsafe` confined to `eapol-io` (and justified). Deny lints: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `cast_possible_truncation/wrap/sign_loss`, `arithmetic_side_effects`, clippy `all`=deny / `pedantic`=warn. Conventional Commits + per-branch review (carry over `CONTRIBUTING.md`).
- **Pure unit tests:** EAPOL/PACP codec round-trip + KAT; RADIUS request build / accept parse round-trip + KAT (shared vectors with usg-radius); PAE state-machine via scripted event→effect sequences (single/multi-auth/MAB/guest/critical paths).
- **Recorded exchanges:** capture full EAPOL + RADIUS byte streams for a successful TEAP auth (machine then user), an Access-Reject, and a CoA-Disconnect; replay through the pure core.
- **SONiC integration:** bring up `enforce-sonic` against a SONiC VS (virtual switch) container; verify trap install, port authorize/deauthorize, dynamic VLAN move, ACL bind, and ASIC_DB read-back. End-to-end trio test: usg-supplicant ↔ usg-authenticator (SONiC-VS) ↔ usg-radius.

---

## 9. Reuse across the Trio / fleet

- **`radius-proto`** (usg-radius): reuse the RADIUS packet/attribute/EAP/`Message-Authenticator` codec directly as a workspace dependency (path or git). We add only the *client* and CoA-listener layers. Keeps wire encoding identical on both ends — fewer interop surprises and shared KAT vectors.
- **usg-nos** dataplane pattern: `enforce`'s backend-neutral trait intentionally mirrors usg-nos's Linux/switchdev/SAI split, so an `enforce-linux` or a future usg-nos integration is a drop-in.
- **usg-radius / usg-nac** are the CoA/accounting peers: accounting feeds session tracking; CoA is how policy changes reach the port. Attribute/VENDOR dictionaries should match what usg-radius emits — pin a shared dictionary doc (proposed `SERVER-CONTRACT.md`, §11 Q-A).

---

## 10. Milestones (after sign-off)

1. `pacp` EAPOL/PACP codec + KAT tests.
2. `pae` authenticator + backend-auth state machines + host modes + tests (scripted event/effect).
3. `radius-client` (Access-Request/Challenge/Accept/Reject, accounting) on top of `radius-proto` + KAT (shared vectors w/ usg-radius).
4. `radsec` TLS 1.3 FIPS transport + mutual auth + reconnect + `fips-check`.
5. `enforce` trait + `enforce-sonic` (Redis CONFIG_DB/APPL_DB writes, ASIC_DB read-back, EAPOL trap install) against SONiC-VS.
6. `eapol-io` AF_PACKET rx/tx; `authd` wiring + config + port manager + telemetry.
7. Features: dynamic VLAN + dACL; MAB; guest/auth-fail/critical VLAN; CoA/Disconnect.
8. Trio integration: supplicant ↔ authenticator(SONiC-VS) ↔ usg-radius — machine boot auth then user logon auth, plus a CoA-Disconnect.

---

## 11. Open questions

The full wire contract — what usg-radius actually emits, plus the server-side gaps it implies — is pinned in [SERVER-CONTRACT.md](SERVER-CONTRACT.md), grounded in the current usg-radius source.

- **Q-A — Shared RADIUS attribute/vendor dictionary: RESOLVED.** usg-radius emits a **fixed, config-validated set of eight** reply attributes (`policy.rs:373`); dACL is **`Filter-Id` (named ACL) only** — no VSAs, no inline ACEs, no `Termination-Action`. VLAN via the RFC 2868 tag-1 group. Full encoding in [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §3.
- **Q-C — NAS client identity for RadSec: RESOLVED.** Switch RadSec client key is **TPM-resident (non-exportable)**; cert enrolled and renewed via **usg-est-client** (RFC 7030 EST) against the USG CA; same EST `cacerts` path provides the trust anchor for usg-radius's server cert. Detail in [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §1.2.
- **Q-B — RadSec for CoA, or separate RFC 5176 UDP/3799?** Proposed: CoA over the *same* mutually-authenticated RadSec connection. **Carried forward** — usg-radius has not yet implemented CoA (roadmap v0.9.0), so its origination model is undefined; the authenticator ships a dormant listener for the RadSec path. See [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §4.2.
- **Q-D — Critical-VLAN posture.** Confirm fail-open-to-critical-VLAN is desired at all (the only non-fail-closed path), and define the exact restricted posture for critical/guest/auth-fail VLANs (which is most permissive?).
- **Q-E — SONiC target & EAPOL trap.** Confirm target SONiC release/branch (affects CONFIG_DB schema for ACL/VLAN) and that a CoPP/host-interface **EAPOL trap** is installable on the target ASIC SAI profile. **Riskiest hardware dependency.**
- **Q-F — Port-unauthorized enforcement primitive.** Default-deny via per-port ACL (allow only 0x888e to CPU) vs. SAI port admin/learning state vs. an "unauth VLAN." Proposed: ACL default-deny (most precise for multi-auth). Confirm acceptable on the target ASIC.

### Server-side gaps this design depends on (see [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §0)
The locked decisions assume usg-radius capabilities it does **not** ship today — flagged here so they aren't discovered at integration:
- **G-1 (blocks locked transport):** usg-radius is **UDP-only**; RadSec (RFC 6614, TCP/2083) must be added server-side. A `udp-insecure` dev fallback exists but is non-FIPS and not for production.
- **G-2:** server-initiated **CoA/Disconnect** is unimplemented (roadmap Q4 2026).
- **G-3:** `Termination-Action` not emitted ⇒ Session-Timeout defaults to full de-auth/re-auth.

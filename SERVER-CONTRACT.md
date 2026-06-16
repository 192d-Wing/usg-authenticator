# usg-authenticator ↔ usg-radius Contract: RADIUS Transport, Authorization Attributes, CoA

**Status:** DRAFT v1 for review. Defines the wire contract between **usg-authenticator** (the NAS / 802.1X authenticator) and **usg-radius** (the EAP/RADIUS server) for the wired 802.1X-2020 pass-through path.

Unlike the supplicant↔server contract (a private TEAP profile), this leg is **standard RADIUS** (RFC 2865 / 2866 / 2869 / 3579 / 3580 / 5080 / 6614 / 5176). This document pins exactly which standard attributes usg-radius emits today, what the authenticator does with each, and the **three places the server must change** to meet the authenticator's locked design.

All claims here are grounded in the current usg-radius source; file/line citations are given so each can be re-verified as that repo evolves.

---

## 0. Reality check — server gaps the authenticator depends on

The authenticator's locked decisions (DESIGN.md §1) assume capabilities usg-radius does **not** ship today. These are requirements on usg-radius, surfaced up front so they aren't discovered at integration time:

| # | Authenticator needs | usg-radius today | Action |
|---|---|---|---|
| **G-1** | **RadSec** (RADIUS over TLS 1.3, RFC 6614, TCP/2083), mutually authenticated, **ML-KEM-1024-only key exchange** (FIPS 203) | **UDP only**, ports 1812/1813 (`radius-server/src/server.rs:523`, `UdpSocket`). The `tls` feature configures **inner EAP-TLS/TEAP**, not the RADIUS transport (`main.rs:398-422`); mTLS exists only on the management API (`access.rs`). | usg-radius MUST add a RadSec listener that offers/accepts **only** the `MLKEM1024` group (§1.1). Until then, interop is UDP + Message-Authenticator (§1.3, transitional only). |
| **G-2** | **CoA / Disconnect** (RFC 5176) initiated by the server | **Not implemented** — roadmap v0.9.0, Q4 2026 (`docs/.../ROADMAP.md:1210-1215`). | Authenticator ships a dormant CoA listener (§4); server-initiated re-auth/kick is unavailable until usg-radius lands CoA. |
| **G-3** | **Termination-Action** to signal "re-auth on Session-Timeout" | **Not emitted** — not in `KNOWN_REPLY_ATTRIBUTES` (`policy.rs:373-383`); `reply_attribute()` has no arm for it (`policy_enforce.rs:152-191`). | Authenticator defaults Session-Timeout to **terminate** (re-auth) per RFC 3580 §3.18 absent the attribute. If silent re-auth is wanted, usg-radius must emit `Termination-Action=RADIUS-Request(1)` (§3.4). |

None of these block authenticator development — the pure core and SONiC enforcement proceed against recorded vectors and a UDP test server — but G-1 must land on usg-radius before the trio runs end-to-end on the locked (RadSec) transport.

---

## 1. RADIUS transport

### 1.1 Target: RadSec (RFC 6614) — required server addition (G-1)
- **TCP/2083**, **TLS 1.3 only**, single suite `TLS_AES_256_GCM_SHA384` (AES-256 only — AES-128 is deliberately not offered, holding a uniform 256-bit / SHA-384 posture). FIPS via aws-lc-rs on both ends.
- **Key exchange = ML-KEM-1024 only** (FIPS 203). Both ends offer/accept exactly the `MLKEM1024` named group (rustls `aws_lc_rs::kx_group::MLKEM1024`) — **no classical (P-256/P-384, X25519) and no hybrid (e.g. X25519MLKEM768) groups**. A handshake that negotiates anything else MUST fail closed on both sides. (Classical EC curves remain allowed only for **certificate signatures** — ML-KEM is a KEM, not a signature scheme — but never for key agreement.)
- **Mutual TLS:** the authenticator (NAS) presents a client certificate; usg-radius presents a server certificate. Each pins the other against a configured trust anchor (the USG CA). The NAS client cert identity (CN/SAN) is the server's authenticated notion of "which switch" — it replaces the spoofable shared-secret + source-IP trust of UDP RADIUS.
- Inside the TLS tunnel, packets are **standard RADIUS** (same codec usg-radius already uses). RadSec uses a fixed shared secret of the ASCII string `"radsec"` (RFC 6614 §2.3) for the RADIUS Authenticator/Message-Authenticator computations; the real transport security is the TLS layer.
- One long-lived TLS connection per NAS carries Access-Request/Accounting and (later, G-2) CoA in the reverse direction.

### 1.2 NAS client identity & key custody (resolves DESIGN.md Q-C)
- The switch's RadSec **client key is generated in and never leaves the TPM** (non-exportable). The cert is enrolled via **usg-est-client** (RFC 7030 EST) against the USG CA: TPM generates the key → est-client builds the CSR → CA issues → cert installed for RadSec mutual auth.
- **Renewal:** est-client re-enrolls (`simplereenroll`) before `not_after`; rotation is hitless (new connection on the new cert, drain the old).
- **Trust anchor:** the CA bundle that validates usg-radius's server cert is provisioned alongside (same EST `cacerts` path).

### 1.3 Transitional fallback: UDP + Message-Authenticator (until G-1)
Permitted **only** for development against today's UDP-only usg-radius, behind an explicit `transport = "udp-insecure"` config flag (default = `radsec`; the daemon logs a prominent warning and refuses it in any non-dev build profile):
- UDP/1812 (auth), UDP/1813 (accounting). Per-NAS shared secret.
- **Every** Access-Request carrying `EAP-Message` MUST include `Message-Authenticator` (80), and the authenticator MUST verify it on every reply (RFC 3579 §3.2, RFC 5080). This is HMAC-MD5 — **not** FIPS-approved; it is tolerated only on this transitional path and is not a security boundary. The FIPS posture requires G-1.

---

## 2. Access-Request — what the authenticator sends

EAP pass-through per RFC 3579. The authenticator copies the supplicant's EAP verbatim into `EAP-Message` (79), fragmenting across multiple `EAP-Message` attributes when > 253 bytes (RFC 3579 §3.1), and reassembling challenges the same way on the return path.

| Attribute | Type | Value | Note |
|---|---|---|---|
| `User-Name` | 1 | EAP-Response/Identity, or the MAC for MAB | usg-radius keys policy on this (`policy_enforce.rs:97`). |
| `EAP-Message` | 79 | EAP packet (fragmented) | usg-radius reads EAP type from offset 4 (`policy_enforce.rs:83-91`). |
| `Message-Authenticator` | 80 | HMAC | Mandatory whenever EAP-Message present. |
| `NAS-IP-Address` | 4 | switch mgmt IP (IPv4) | `policy_enforce.rs:114`. IPv6 NAS: also send `NAS-IPv6-Address` (95) — **verify usg-radius parses it** (§5 V-1). |
| `NAS-Identifier` | 32 | switch hostname | condition attr (`policy_enforce.rs:103`). |
| `NAS-Port-Id` | 87 | the `EthernetN` name | CoA/accounting session key. |
| `NAS-Port-Type` | 61 | `Ethernet` = **15** | usg-radius maps 15→"Ethernet" (`policy_enforce.rs:25`). |
| `Service-Type` | 6 | `Framed` (2); `Call-Check` (10) for MAB | `policy_enforce.rs:36-47`. |
| `Calling-Station-Id` | 31 | supplicant MAC, `AA-BB-CC-DD-EE-FF` | condition attr (`policy_enforce.rs:105`). |
| `Called-Station-Id` | 30 | switch port MAC `+ ":SSID"`-style not used (wired) | `policy_enforce.rs:104`. |

**MAC format:** usg-radius treats `Calling/Called-Station-Id` as opaque strings for `equals`/`contains` policy matching (`policy_enforce.rs:108-111`, lossy-UTF8, never dropped). The authenticator emits the IETF-canonical **upper-case hyphen-separated** form `AA-BB-CC-DD-EE-FF`. **Pin this format** so MAB and MAC-based policies match deterministically (§5 V-2).

---

## 3. Access-Accept — authorization the authenticator honors

usg-radius validates every authorization-profile attribute against a fixed allow-list and **rejects unknown names at config time** (`policy.rs:373-383`, "unknown names can't be silently dropped"). The complete set it can put on the wire is therefore exactly these eight (`policy_enforce.rs:152-191`):

### 3.1 Dynamic VLAN (RFC 3580 / RFC 2868) — supported
Returned as an RFC 2868 tagged group, all sharing **tag = 1** (`policy_enforce.rs:146`):

| Attribute | Type | Encoding (as usg-radius emits) |
|---|---|---|
| `Tunnel-Type` | 64 | tagged integer `[01, 00, 00, 0D]` → **VLAN (13)** (`policy_enforce.rs:172-176, 194-200`) |
| `Tunnel-Medium-Type` | 65 | tagged integer `[01, 00, 00, 06]` → **802 (6)** |
| `Tunnel-Private-Group-ID` | 81 | tagged string `[01]` + ASCII VLAN id/name, e.g. `[01]"42"` (`policy_enforce.rs:183-188`) |

Authenticator action: parse the tag-1 group, take `Tunnel-Private-Group-ID` as the target VLAN (numeric id or name resolvable in CONFIG_DB), and program `VLAN`/`VLAN_MEMBER` + port PVID (DESIGN.md §3). Reject a `Tunnel-Type ≠ 13` or `Tunnel-Medium-Type ≠ 6` as malformed (fail closed; stay unauthorized).

### 3.2 dACL — **`Filter-Id` only (named ACL), no inline ACEs**
- usg-radius emits **`Filter-Id` (11)** as a plain string (`policy_enforce.rs:154`) — the **name of an ACL the switch already has provisioned**. There is **no** Vendor-Specific attribute and **no** downloadable/inline ACE format in usg-radius today.
- Authenticator action: resolve the `Filter-Id` string to a pre-provisioned `ACL_TABLE` in CONFIG_DB and bind it to `{port, MAC}`. If the named ACL does not exist, **fail closed** (Access-Reject behavior: keep unauthorized; log) — never authorize without the policy the server asked for.
- **Implication for ops:** ACL *content* lives on the switch (or its config management), not in RADIUS. The contract is the **name**. If inline/downloadable ACLs are later wanted, that is a new usg-radius VSA + a new arm here (out of scope v1).

### 3.3 Class (25) — supported, opaque
Echoed verbatim by usg-radius from policy (`policy_enforce.rs:158`). Authenticator stores it and **echoes it in all Accounting and CoA packets** for this session (RFC 2865 §5.25) — it is the server's session correlation handle.

### 3.4 Timers — Session-Timeout & Idle-Timeout (plain u32 seconds)
- `Session-Timeout` (27) and `Idle-Timeout` (28) as plain 4-byte integers (`policy_enforce.rs:159-168`).
- **No `Termination-Action` is emitted (G-3).** Per RFC 3580 §3.18, absent `Termination-Action=RADIUS-Request(1)`, Session-Timeout means **terminate the session** (full de-auth, supplicant must re-authenticate from scratch). The authenticator defaults to that. If usg-radius later wants silent in-place re-auth, it must add `Termination-Action` to `KNOWN_REPLY_ATTRIBUTES` + a `reply_attribute()` arm; the authenticator will then re-auth without dropping the port.

### 3.5 Reply-Message (18)
Human-readable string (`policy_enforce.rs:155`). Logged/displayed only; no enforcement.

> **Attributes the authenticator must NOT expect** (because usg-radius cannot emit them): any VSA, inline dACL, `Tunnel-Assignment-Id`, `Egress-VLANID`, `Termination-Action`, `Acct-Interim-Interval`. Designing enforcement around any of these is a contract violation until the server adds them.

---

## 4. RADIUS Accounting (RFC 2866) & CoA (RFC 5176)

### 4.1 Accounting — authenticator → usg-radius
On authorization the authenticator sends `Accounting-Request` Start; periodic Interim; Stop on de-auth, carrying `Acct-Session-Id` (44), `Acct-Multi-Session-Id` (50, stable across re-auth), `Class` (25, §3.3), `Calling-Station-Id`, `NAS-Port-Id`, and on Stop `Acct-Terminate-Cause` (49). usg-radius's accounting types (`radius-proto::AcctStatusType`, `AcctTerminateCause`) define the enum values to use. **`Acct-Session-Id` + `NAS-Port-Id` + `Calling-Station-Id` are the session key CoA will target** — they MUST be set at Start and be stable.

### 4.2 CoA / Disconnect — usg-radius → authenticator (dormant until G-2)
- **Transport (proposed, pending usg-radius's model):** over the **same RadSec connection**, server→NAS direction. This avoids an inbound UDP/3799 port that would otherwise need a per-NAS secret and IP allow-listing and is spoofable. The authenticator builds the listener now; it stays dormant until usg-radius implements CoA (`ROADMAP.md:1210`).
- `Disconnect-Request` → terminate the matched `{port, MAC}` session, Acct-Stop, port→unauthorized; reply `Disconnect-ACK` / `-NAK`.
- `CoA-Request` → re-auth, or apply changed VLAN/Filter-Id in place; reply `CoA-ACK` / `-NAK`.
- Session match on `Acct-Session-Id` (+ `Calling-Station-Id`, `NAS-Port-Id`). No match → NAK with `Error-Cause = Session-Context-Not-Found (503)` (RFC 5176 §3.5).
- **Open (Q-B carried forward):** confirm usg-radius will originate CoA over the established RadSec connection vs. opening a fresh RFC 5176 UDP/3799 session to the NAS. The dormant listener supports the RadSec path; a UDP/3799 path would need a separate listener + per-NAS secret.

---

## 5. Verification checklist (to confirm against usg-radius before integration)

- **V-1 — IPv6 NAS identity.** The fleet is IPv6-first, but usg-radius only parses `NAS-IP-Address` (IPv4, `policy_enforce.rs:114-124`). Confirm it accepts `NAS-IPv6-Address` (95) — or the authenticator must also carry an IPv4 `NAS-IP-Address` for identification.
- **V-2 — Station-Id format.** Confirm operators author MAC policies in `AA-BB-CC-DD-EE-FF`; usg-radius matching is literal string compare, so format drift silently breaks MAB/MAC policy.
- **V-3 — Message-Authenticator.** Confirm usg-radius *requires and verifies* `Message-Authenticator` on EAP Access-Requests (RFC 5080 / "Blast-RADIUS" hardening). (No verification arm was found in `access.rs`; confirm location.)
- **V-4 — EAP-Message fragmentation.** Confirm reassembly of multi-`EAP-Message` requests (the TEAP TLS handshake will exceed 253 bytes); server fragments challenges (`eap_auth.rs:447-474`) — confirm the inbound reassembly mirror.
- **V-5 — Shared KAT vectors.** Commit byte-level vectors to **both** repos for: a VLAN-assigning Access-Accept (§3.1), a `Filter-Id` Accept (§3.2), and a fragmented EAP-Message Access-Request — so encode/decode stays locked on both ends.

---

## 6. Summary of what's locked vs. open

**Locked (grounded in usg-radius source):** the eight emit-able reply attributes (§3); VLAN tag-1 encoding (§3.1); `Filter-Id`-only dACL (§3.2); plain-u32 timers with terminate-on-timeout default (§3.4); UDP-today transport (§1, G-1).

**Requires usg-radius work:** RadSec listener with **ML-KEM-1024-only** key exchange (G-1, blocks locked transport); CoA (G-2, blocks server-initiated re-auth/kick); optional `Termination-Action` (G-3, for silent re-auth).

**Open questions:** Q-B CoA transport (§4.2); V-1 IPv6 NAS identity; V-3 Message-Authenticator enforcement location.

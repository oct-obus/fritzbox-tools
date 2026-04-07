# Fritz!Box 7590 Firmware Research Findings

> **Firmware:** FritzOS 8.25 (`FRITZ.Box_7590-08.25.image`)  
> **Hardware:** HW226 — MIPS32r2, Lantiq/Intel VRX518 DSL SoC  
> **OEM variants:** avm, avme (enterprise), 1und1

---

## 1. Binary Architecture

All binaries share the same toolchain:

| Property | Value |
|----------|-------|
| ISA | MIPS32 Release 2, big-endian |
| ABI | o32, soft-float |
| Libc | musl (`ld-musl-mips-sf.so.1`) |
| Compiler | GCC 8.4.0 (Buildroot) |
| Linking | Dynamic, PIE |
| Security | Stripped, stack canaries |

Key daemons: `avmnexusd` (mesh transport, 132K), `meshd` → `libmeshd.so.0` (mesh intelligence, 434K), `ctlmgr` (web UI + control plane, 86K), `telefon` (telephony + DTMF), `wland` (WLAN driver interface).

The system has **197 shared libraries** including AVM's proprietary mesh stack, OpenSSL 3, protobuf, MQTT, and IKEv2.

---

## 2. Mesh Architecture

### Centralized Design

The mesh is **fully centralized** — the gateway Fritz!Box makes all optimization decisions. Repeaters are EasyMesh agents that execute commands.

**Two-daemon architecture:**
- **`avmnexusd`** — transport layer: peer discovery via multicast, mTLS-authenticated connections (certificate fingerprint pinned, not CA chain), distributed master election
- **`meshd`** (via `libmeshd.so.0`) — control plane: implements IEEE 802.11 EasyMesh / 1905.1 Multi-AP with AVM proprietary extensions

### Master Election

On startup, all devices run a distributed election via `avmnexusd`. The winner becomes the nexus master, opens a TCP+TLS listener; losers connect as slaves. Role is persisted across reboots.

### Controllers (Master Only)

| Controller | Function |
|-----------|----------|
| `TopologyOptimisation` | Top-level coordinator |
| `BackhaulOptimisationController` | Decides which AP each repeater connects to |
| `ChannelOptimisationController` | Assigns channels across all devices |
| `TribandOptimiser` | 2.4/5/6 GHz band optimization |
| `InterferenceOptimiser` | Inter-BSS interference mitigation |
| `WLANSteeringCoordinator` | Client band/BSS steering |

### Client Steering State Machine

The master steers phones/devices between APs:

1. **SendRRMRequests** — 802.11k beacon measurement requests to client
2. **EstimateRSSI** — infer signal on target band when client doesn't support 802.11k
3. **SelectTarget** — pick best target AP from candidates
4. **SendBTMRequest** — 802.11v BSS Transition Management (polite request to roam)
5. **LegacySteer** — deauth/disassociate fallback if client ignores BTM
6. **WaitForConnect** — verify client associated with target

Policy: repeaters default to `AGENT_INITIATED_STEERING_DISALLOWED` — they must wait for master commands unless explicitly granted autonomy.

### Backhaul Steering

The master monitors RSSI (via CSI driver), latency, and data rates. When a repeater's uplink degrades:

1. Channel scan AP candidates
2. Build candidate list, filter by `BACKHAUL_STEERING_REQUEST_REJECTED_BSS_SIGNAL`
3. Send IEEE 1905.1 `BACKHAUL_STEERING_REQUEST_MESSAGE` to repeater
4. Repeater accepts or declines with reason (`DECLINE_BREAKS_BACKHAUL_LINK`, etc.)

### Metrics

`NodeMetricsManager` continuously collects: RSSI via CSI driver, latency via ping, WAN throughput counters, channel utilization, BSS load, TX/RX data rates.

---

## 3. Hidden Endpoints & Debug Features

### `dbg=1` — Debug Log Injection

Any authenticated POST to `data.lua` with `dbg=1` dumps server-side state into the JSON response:

```
POST /data.lua  sid=X&page=overview&dbg=1
```

Returns `response.data.debug` containing:
- **`queries`** — every `box.query()` call with values and timing (ms)
- **`config`** — the entire global config table (all feature flags, product ID, capabilities)
- **`get`/`post`** — all request parameters

**Limitation:** Mesh-related Lua files use a separate `dbg.*` logger that does NOT feed into the dbg=1 output. So `page=homeNet&dbg=1` reveals config queries but not steering decisions or RSSI data.

### `query.lua` — Raw Config Query API

Any authenticated session can query arbitrary internal config paths:

```
/query.lua?sid=X&role=nexus:settings/role
/query.lua?sid=X&master=nexus:settings/is_master
/query.lua?sid=X&loop=meshd:settings/loop_prevention_state
/query.lua?sid=X&wan=connections:settings/ipaddress
```

Accepts paths matching `<module>:settings/`, `<module>:status/`, or `<module>:command/`. **Read-only** — no write capability.

### `capture_notimeout` — Live Packet Capture

Streams Wireshark-compatible pcap on any interface without timeout:
- LAN, WLAN, DSL, USB, Zigbee, LTE interfaces
- Includes WLAN monitor mode traces

### `shellinaboxd` — Browser Root Shell

Full browser-based terminal infrastructure exists in `support.lua`, but the binary is NOT included in release firmware. Gated behind `gu_type == "private"/"beta"` or `CERTWAVE` (carrier firmware). On internal builds: start/stop console button, optional WAN access.

### Other Notable Pages

| Page ID | What it does |
|---------|-------------|
| `query` | Raw config query API (see above) |
| `cap` | Wireshark packet capture |
| `dsl_test` | Dr. DSL cable echo measurement |
| `dslSpectrum` | DSL spectrum analyzer (has debug fake mode) |
| `lisp` | LISP tunneling (cable OEM / internal builds only) |
| `dbg` | Debug sidebar menu (internal builds only, `gDbg == true`) |
| `rrd` | RRD time-series statistics (internal builds only) |

---

## 4. Root Shell Access

### Telnet via DECT Phone

Dial `#96*<code>` on a DECT phone connected to the Fritz!Box. The `telefon` daemon intercepts DTMF sequences and launches `/usr/sbin/telnetd` (BusyBox). Login via `/sbin/ar7login` using Fritz!Box user credentials → drops to `/bin/sh`.

Known codes: `#96*5*` (telnet on), `#96*4*` (telnet off), `#96*7*` (call monitor).

### Serial Console

`/etc/inittab` contains `ttyLTQ0::askfirst:-/bin/sh` — **no password**. Physical serial = instant root shell.

### Firmware Signing

Release firmware requires RSA signature verification (`libfwupdate.so.0`). Public keys at `/etc/avm_firmware_public_key*`. Unsigned and downgrade images are blocked.

---

## 5. OPENSESAMETF04T — ISDN Subaddress Backdoor

**Not a telnet code.** It's a hidden trigger in the `telefon` binary activated by a specially crafted ISDN call.

### Mechanism

1. Incoming call arrives on Fritz!Box **ISDN S0 interface** (network side)
2. `telefon` inspects Q.931 calling party subaddress in signaling
3. `memcmp` against 17 bytes: `\x10\xA0OPENSESAMETF04T`
   - `\x10` = length (16 bytes follow)
   - `\xA0` = User-specific subaddress type (ITU-T Q.931)
   - `OPENSESAMETF04T` = magic passphrase
4. On match: registers facility callback via `fc_funcs->callback()` with codes `\x0cSESAME` and `\x0cOPENSESAMETF04T`

### Name Breakdown

- **"OPEN SESAME"** — Ali Baba's magic word
- **"TF"** — TeleFon (German: telephone)
- **"04T"** — model/version or "Test" suffix
- **"SEASAME"** (transposed variant) — reverse call direction check

### Practical Impact

Low. Requires ISDN network-side call with Q.931 subaddress injection — consumer equipment can't produce this. The ISDN S0 port on the 7590 is a local bus port requiring physical access. The facility code `\x0c` suggests a factory/engineering diagnostic mode, same family as `\x0b` (answering machine controller) and `\x0e` (SWISSVOICE handset compatibility).

---

## 6. Repeater Uplink Control ⭐

### Discovery

The repeater's web UI **fully exposes uplink selection** through `wizard_meshset.lua`. This allows changing which AP a Fritz!Repeater connects to.

### Config Paths (on repeater, `wlan:settings/`)

| Path | Role |
|------|------|
| `STA_mac_master` | Uplink AP BSSID |
| `STA_ssid` | Uplink AP SSID |
| `STA_pskvalue` | WPA passphrase (**cleartext**) |
| `STA_configured` | Configured flag |
| `STA_encryption` | WPA mode |
| `STA_uplink_state` | Connection state (read-only; `3` = connected) |

Band suffixes: `_scnd` (5 GHz), `_thrd` (6 GHz), `_frth` (4th band).

### API Flow

**1. Trigger AP scan:**
```
POST http://<repeater-ip>/data.lua
sid=X&page=wizard_meshset&xhrId=refresh_scanlist
```

**2. Poll scan results:**
```
POST http://<repeater-ip>/data.lua
sid=X&page=wizard_meshset&xhrId=request_scanlist
```

**3. Set new uplink:**
```
POST http://<repeater-ip>/data.lua
sid=X&page=wizard_meshset&roleType=repeater&connectionType=wifi
&mac=<bssid>&ssid=<ssid>&enc=wpa2&pskvalue=<password>
```

### Network Accessibility

Repeaters operate in **Layer-2 bridge mode** (same subnet as master). A phone on the repeater's WiFi can reach both the master (`192.168.178.1`) and any repeater's web UI directly at its DHCP-assigned IP. No proxy through the master is needed.

### Script

`repeater_uplink.py` implements this flow: `list-repeaters`, `status`, `scan`, `set` commands.

---

## 7. meshd Debug CLI (aicmd)

The mesh daemon exposes a socket-based CLI via `avmluautils.aicmd("meshd", ...)`. **Only accessible from root shell** (`/bin/aicmd`) — not reachable from the web UI.

| Module | Commands |
|--------|----------|
| `topology` | `show`, `update`, `clear`, `trace` |
| `steering` | `enable`, `enabled`, `flush_steering_history`, `add_steering_task`, `config_*` |
| `backhaul` | `enabled`, `move`, `device`, `children`, `steal`, `get_history`, `set_min/max_wait` |
| `nodemetrics` | `measurelatency`, `fullmacaddressupdate`, `set*interval` |

The only web-reachable path to meshd is `meshlist.lua` on the TR-064 port (49000), which sends two **hardcoded read-only** commands (`topology update` + `topology show`).

---

## 8. TR-064 Notable Actions

| Service | Action | Risk |
|---------|--------|------|
| `deviceconfigSCPD` | `X_AVM-DE_GetConfigFile` | Exports full config including credentials |
| `deviceconfigSCPD` | `X_AVM-DE_SetConfigFile` | Imports config from caller-supplied URL |
| `deviceconfigSCPD` | `X_AVM-DE_CreateUrlSID` | Creates authenticated session tokens |
| `fboxSCPD` | `SetLogParam` | Sets syslog destination (remote log exfiltration) |
| `x_appsetupSCPD` | `RegisterApp` | Self-register for API keys without UI confirmation |
| `x_uspcontrollerSCPD` | `AddUSPController` | Full MQTT-based TR-369 remote management |
| `x_speedtestSCPD` | `GetInfo/SetConfig` | Built-in speed test service |
| `deviceconfigSCPD` | `FactoryReset` / `Reboot` | Destructive operations |

---

## 9. Firmware Tiers

| `gu_type` | Level | Features unlocked |
|-----------|-------|-------------------|
| `release` | Public | Normal firmware |
| `labor` | Public beta | Lab features |
| `private` / `beta` | Internal AVM | shellinabox, enhanced support data, debug pages |
| `inhaus` | Engineering | Highest privilege, AVM telemetry locked ON |

---

## 10. Practical Implications for the Flutter App

### Can implement now:
- **Repeater uplink control** — authenticate to repeater directly, scan APs, change uplink BSSID (`wizard_meshset.lua`)
- **`query.lua` reads** — query arbitrary config paths on master and repeaters for richer device info
- **`dbg=1` diagnostics** — expose config state and timing data for debugging
- **Repeater discovery** — get repeater IPs from master's mesh topology, authenticate to each

### Cannot implement (requires root):
- **Force backhaul steering** — meshd `backhaul move/steal` commands need `/bin/aicmd`
- **Client steering control** — meshd `steering add_steering_task` requires root
- **Topology trace streaming** — `meshd topology trace` requires root
- **Real-time RSSI data** — CSI driver interface not exposed to web UI

### Architecture notes:
- Repeaters are L2 bridged (same subnet) — app can talk to any repeater directly
- Each repeater runs its own `login_sid.lua` — same PBKDF2 auth flow as master
- Config pushed from master to repeaters automatically (SSID/PSK changes propagate)
- `meshlist.lua` on TR-064 port (49000) returns full topology JSON (read-only)

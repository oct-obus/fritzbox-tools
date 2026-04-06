# Fritz!Box Tools — Agent Context

## Project Overview

Fritz!Box router management tools: a Flutter iOS app and standalone Python CLI scripts. The app provides a WebView UI served by a local Dart proxy server for device listing, mesh topology visualization, and repeater management. Python scripts offer command-line access to the same APIs.

## Repository Structure

```
fritzbox-tools/
├── flutter_app/              # Flutter iOS app
│   ├── lib/
│   │   ├── main.dart         # App entry — WebView loading proxy URL
│   │   └── fritz_proxy.dart  # Dart HTTP proxy server (~495 lines)
│   ├── assets/
│   │   └── fritzbox_tools.html  # Entire web UI — single-file SPA (~1660 lines)
│   ├── ios/
│   │   └── Runner/
│   │       ├── Info.plist        # App config, permissions
│   │       └── Runner.entitlements  # WiFi info entitlement
│   └── pubspec.yaml           # Flutter deps and version
├── mesh_manager.py            # CLI mesh topology tool (list/topology/clients/pair/info)
├── fritzbox_auth.py           # Shared auth module (PBKDF2 v2 + MD5 v1)
├── fritzbox_api.py            # Generic API endpoint fetcher
├── mesh_pair.py               # Mesh pairing CLI
├── fritzbox_web.py            # Browser-based web UI (standalone Python)
├── .github/workflows/
│   └── build-ios.yml          # CI: build IPA, release, dispatch app-source
└── README.md
```

## App Architecture

The Flutter app uses a **Dart proxy + WebView** pattern:

1. `main.dart` starts a `FritzProxy` shelf HTTP server on port 8742 (fixed for localStorage persistence)
2. A `WebViewController` loads `http://127.0.0.1:8742/` in a WebView
3. `fritz_proxy.dart` serves the HTML UI at `/` and proxies all Fritz!Box API calls
4. `fritzbox_tools.html` is a self-contained SPA with inline CSS (~200 lines), HTML structure (~100 lines), and JavaScript (~1350 lines)

### Why a proxy?

- Avoids CORS issues with Fritz!Box APIs
- Handles PBKDF2 auth (not available in browser JS without WebCrypto complexity)
- Provides native platform access (local IP, WiFi BSSID via `network_info_plus`)
- Port 8742 is fixed so localStorage persists across app restarts

### Key proxy endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Serves the HTML UI |
| `GET /local-ip` | Returns phone's non-loopback IPv4 addresses |
| `GET /wifi-bssid` | Returns current WiFi BSSID (requires location permission) |
| `POST /proxy/<host>/login` | Handles Fritz!Box authentication |
| `GET /proxy/<host>/api/*` | Proxies landevice and other REST APIs |
| `POST /proxy/<host>/data.lua` | Proxies mesh topology data endpoint |
| `POST /proxy/<host>/wps-trigger` | Triggers WPS on a repeater via TR-064 |

### UI tabs

- **Devices** — full device list with repeater detection, filtering, "My AP" highlight
- **Tree** — hierarchical mesh topology view (master → repeaters → clients)
- **Pair** — mesh pairing interface (WPS trigger + nexus monitoring)
- **Manager** — repeater status overview with per-repeater client lists

## Fritz!Box API Integration

### Authentication

Challenge-response via `/login_sid.lua?version=2`:
- v2: PBKDF2-HMAC-SHA256 two-pass (challenge format `$iter1$salt1$iter2$salt2`)
- v1 fallback: MD5 with UTF-16LE encoding

### Device list

`GET /api/v0/generic/landevice` with `AUTHORIZATION: AVM-SID <sid>` header.

Returns all known LAN devices with IP, MAC, name, online status, link_list (network connections), mesh_UIDs, nexuspeer_UID, etc.

### Mesh topology

`POST /data.lua` with body `sid=<sid>&page=mesh`.

Returns mesh node hierarchy with node_interfaces, node_links (including UPLINK relationships), per-interface MAC addresses, and connection types.

### Repeater detection heuristics

A device is classified as a repeater if ANY of:
- `modelname` contains "repeater" (case-insensitive)
- `meshNode.meshRole === 'slave'` (from mesh topology)
- `link_list` has entries with `local_interface_name` starting with "AP:" (access point interfaces)
- `nexuspeer_UID` is non-empty (most reliable single field — 100% discriminator in test data)

All views use the same detection via `allDevices.isRepeater` computed in `parseDeviceList()`.

### Mesh status (isMeshed)

Requires `mesh_UIDs` non-empty PLUS one of:
- `meshNode.isMeshed` from mesh topology API
- `nexuspeer_UID` non-empty
- Has uplink entry in `link_list`

### AP highlight ("My AP")

Two detection methods (BSSID preferred, IP fallback):

**BSSID detection** (requires location permission):
- `/wifi-bssid` endpoint returns current WiFi BSSID via `network_info_plus`
- Matched against device MACs, mesh interface MACs (exact), then fuzzy ±4 on last byte for repeaters
- Polled every N seconds (configurable, default 5s)

**IP fallback:**
- `/local-ip` returns phone's IPv4 addresses
- Matched against device list IPs
- Uplink traced via `link_list` → `remote_dev_mesh_uid` to find connected AP

### Uplink resolution (used in Devices and Tree tabs)

Both views use the same priority:
1. Mesh topology API: `node_interfaces` → `node_links` → UPLINK type → target node
2. Fallback: landevice `link_list` → `is_uplink === '1'` → `remote_dev_mesh_uid`

### Key finding: uplink target is NOT API-controllable

Firmware research confirmed no REST API or TR-064 endpoint exists to change which Fritz!Box/repeater a repeater connects to. Only possible via the repeater's own web UI (Home Network → Mesh → Mesh Settings).

## Build & Release Pipeline

### CI workflow (`.github/workflows/build-ios.yml`)

Triggered by `v*` tags or manual `workflow_dispatch`.

1. `macos-latest` runner, Flutter 3.32.0
2. `flutter pub get` → `flutter build ios --release --no-codesign`
3. Creates unsigned IPA (`FritzTools.ipa`)
4. Uploads as artifact + creates GitHub release
5. Dispatches `update-source` event to `oct-obus/app-source` repo

Total build time: ~2.5 minutes.

### Release workflow

1. Bump `flutter_app/pubspec.yaml` version (format: `X.Y.Z+N`)
2. Commit and push to `main`
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. CI builds automatically
5. `oct-obus/app-source` auto-updates AltStore-compatible `apps.json` via `repository_dispatch`

### Secrets

- `DISPATCH_PAT`: GitHub PAT with `repo` scope, set on fritzbox-tools repo, used to trigger app-source dispatch

## Python Scripts

All scripts use `fritzbox_auth.py` as shared auth module. No external dependencies (stdlib only).

| Script | Purpose |
|---|---|
| `fritzbox_auth.py` | Auth module: challenge-response, REST helpers, TR-064 SOAP |
| `fritzbox_api.py` | Fetch data from any `/api/v0/generic/` endpoint |
| `mesh_pair.py` | Initiate mesh pairing (nexus + WPS trigger) |
| `mesh_manager.py` | Comprehensive mesh CLI: list, topology, clients, pair, info |
| `fritzbox_web.py` | Standalone browser-based web UI |

## Conventions

- **Version format**: `pubspec.yaml` uses `major.minor.patch+build` (e.g., `1.2.5+10`)
- **Git tags**: `v` prefix (e.g., `v1.2.5`) — triggers CI
- **Commit messages**: Include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` trailer
- **Single-file UI**: All web UI code lives in `fritzbox_tools.html` (inline CSS + HTML + JS)
- **No external JS deps**: The embedded UI uses no frameworks or libraries
- **GitHub org**: `oct-obus`

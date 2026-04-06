# fritzbox-tools

Fritz!Box router management tools: a Flutter iOS app and standalone Python CLI scripts.

## Flutter iOS App

The `flutter_app/` directory contains an iOS app for Fritz!Box device management. Built with Flutter, it uses a local Dart proxy server with a WebView UI.

**Features:**
- Device list with repeater detection and filtering
- Mesh topology tree view (hierarchical parent-child relationships)
- "My AP" highlight — real-time detection of which repeater your phone connects to (via BSSID polling)
- Device detail view (tap any device to see all attributes)
- Mesh Manager tab (repeater status, uplink info, per-repeater client lists)
- Mesh pairing (WPS trigger via TR-064)
- Configurable UI scale and poll interval

### Build

CI builds automatically on `v*` tags via GitHub Actions. To build locally:

```bash
cd flutter_app
flutter pub get
flutter build ios --release --no-codesign
```

### Release

```bash
# Bump version in flutter_app/pubspec.yaml, then:
git tag v1.2.5 && git push origin v1.2.5
# CI builds IPA, creates GitHub release, updates app-source
```

## Python Scripts

Standalone CLI tools for Fritz!Box APIs. No external dependencies (stdlib only).

### fritzbox_api.py

Fetch data from any `/api/v0/generic/` endpoint.

```bash
python3 fritzbox_api.py                        # fetch landevice data
python3 fritzbox_api.py -e mesh                # fetch mesh topology
python3 fritzbox_api.py -e nexus               # fetch nexus/mesh peer info
python3 fritzbox_api.py -o devices.json        # save to file
python3 fritzbox_api.py --sid ab0c7d67cc6f796c # reuse existing session
```

### mesh_manager.py

Comprehensive mesh topology CLI — list repeaters, visualize topology, show clients, trigger pairing, and inspect devices.

```bash
python3 mesh_manager.py list                   # list all repeaters with mesh status
python3 mesh_manager.py topology               # ASCII topology tree
python3 mesh_manager.py clients                # show clients per repeater
python3 mesh_manager.py pair --repeater-ip X   # initiate mesh pairing
python3 mesh_manager.py info "repeater name"   # detailed device info
```

### mesh_pair.py

Remotely initiate mesh pairing between Fritz!Box and repeaters without pressing physical WPS buttons.

```bash
python3 mesh_pair.py -p "password" --repeater-ip 192.168.178.2
python3 mesh_pair.py -p "password" --master-only
python3 mesh_pair.py -p "password" --wps-info --repeater-ip 192.168.178.2
```

### fritzbox_web.py

Browser-based web UI for device list and mesh pairing. Runs a local HTTP server.

```bash
python3 fritzbox_web.py                    # start on localhost:8080
python3 fritzbox_web.py --port 9000        # custom port
python3 fritzbox_web.py --bind 0.0.0.0     # listen on all interfaces
```

### fritzbox_auth.py

Shared auth module used by all scripts. Provides:
- PBKDF2 v2 + MD5 v1 challenge-response authentication
- REST API helpers (GET, PUT)
- TR-064 SOAP client with HTTP Digest auth

## Auth Flow

1. `GET /login_sid.lua?version=2` to get challenge
2. PBKDF2-SHA256 two-pass response generation (v2) or MD5 with UTF-16LE (v1 fallback)
3. `POST` credentials to get SID
4. Use SID for API requests via `AUTHORIZATION: AVM-SID <sid>` header


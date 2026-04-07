# Fritz!Box Tools — Desktop Server

Standalone server version of the Fritz!Box Tools app. Runs on **any OS** (macOS, Windows, Linux) — just needs [Dart SDK](https://dart.dev/get-dart) and a browser.

## Quick Start

```bash
cd desktop_server
dart pub get
dart run bin/server.dart
```

Then open **http://localhost:8742/** in your browser.

## Custom Port

```bash
dart run bin/server.dart 9000
```

## How It Works

The server serves the same web UI (`fritzbox_tools.html`) used by the iOS app, and proxies all Fritz!Box API calls through a local HTTP server. Your browser connects to `localhost` which forwards requests to your Fritz!Box on the local network.

### Features

All features from the iOS app work, except BSSID-based AP detection (requires WiFi hardware APIs not available in a browser context):

- **Device list** with repeater detection
- **Mesh topology** tree view
- **Mesh Manager** with repeater status
- **Repeater controls** (reboot, change uplink AP)
- **Debug mode** (dbg=1 diagnostics)
- **Extended device info** (query.lua config reads)
- **Mesh pairing** (WPS trigger)

## Requirements

- [Dart SDK](https://dart.dev/get-dart) ≥ 3.0
- A web browser
- Network access to your Fritz!Box

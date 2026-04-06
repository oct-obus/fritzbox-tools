# Fritz!Box Tools — Flutter iOS App

Fritz!Box router management app for iOS. Uses a local Dart HTTP proxy server with a WebView UI.

## Architecture

```
main.dart          → Starts FritzProxy, loads WebView pointing to http://127.0.0.1:8742
fritz_proxy.dart   → Shelf HTTP server: serves UI, proxies Fritz!Box APIs, provides native endpoints
fritzbox_tools.html → Self-contained SPA (inline CSS + HTML + JS, ~1660 lines)
```

### Why this pattern?

- **No CORS issues**: the Dart proxy handles all Fritz!Box communication
- **Native access**: proxy exposes `/local-ip` (network interfaces) and `/wifi-bssid` (WiFi BSSID via network_info_plus)
- **PBKDF2 auth**: handled in Dart (cleaner than browser-side WebCrypto)
- **Fixed port 8742**: ensures localStorage persists across app restarts

### Key dependencies

- `webview_flutter` — WebView widget
- `shelf` + `shelf_router` — HTTP server
- `network_info_plus` — WiFi BSSID access (requires iOS location permission)
- `crypto` — HMAC-SHA256 for PBKDF2 auth

## iOS Permissions

| Permission | File | Purpose |
|---|---|---|
| Local network access | Info.plist `NSLocalNetworkUsageDescription` | Fritz!Box communication |
| Location (when in use) | Info.plist `NSLocationWhenInUseUsageDescription` | WiFi BSSID for AP detection |
| WiFi info | Runner.entitlements `com.apple.developer.networking.wifi-info` | Access BSSID/SSID |
| Arbitrary loads | Info.plist `NSAppTransportSecurity` | HTTP connections to Fritz!Box |

## Build

```bash
flutter pub get
flutter build ios --release --no-codesign
```

The unsigned IPA is created by CI from the `.app` bundle. See `.github/workflows/build-ios.yml`.

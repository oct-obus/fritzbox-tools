#!/usr/bin/env python3
"""
Fritz!Box Web UI — browser-based interface for device list and mesh pairing.

Runs a local HTTP server with an embedded web interface. Uses fritzbox_auth.py
for authentication and API calls.

Usage:
    python fritzbox_web.py                    # start on port 8080
    python fritzbox_web.py --port 9000        # custom port
    python fritzbox_web.py --bind 0.0.0.0     # listen on all interfaces
"""

import argparse
import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from urllib.error import URLError

from fritzbox_auth import login, api_get, api_put, tr064_call

WLAN_SERVICE = "urn:dslforum-org:service:WLANConfiguration:1"
WLAN_CONTROL_URL = "/upnp/control/wlanconfig1"

# In-memory session store: {fritz_host: {sid, host, username, password}}
sessions: dict[str, dict] = {}
sessions_lock = threading.Lock()


def get_session(host: str) -> dict | None:
    with sessions_lock:
        return sessions.get(host)


def set_session(host: str, data: dict) -> None:
    with sessions_lock:
        sessions[host] = data


def clear_session(host: str) -> None:
    with sessions_lock:
        sessions.pop(host, None)


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fritz!Box Tools</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --green: #3fb950;
    --red: #f85149;
    --orange: #d29922;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .subtitle { color: var(--text-dim); font-size: 14px; margin-bottom: 24px; }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
  }
  .card h2 { font-size: 16px; margin-bottom: 12px; }
  label { display: block; font-size: 13px; color: var(--text-dim); margin-bottom: 4px; }
  input[type="text"], input[type="password"] {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 14px;
    margin-bottom: 12px;
  }
  input:focus { outline: none; border-color: var(--accent); }
  .row { display: flex; gap: 12px; }
  .row > div { flex: 1; }
  button {
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
  }
  button:hover { background: var(--border); border-color: var(--text-dim); }
  button.primary {
    background: #238636;
    border-color: rgba(240,246,252,0.1);
    color: #fff;
  }
  button.primary:hover { background: #2ea043; }
  button.danger { background: #da3633; border-color: rgba(240,246,252,0.1); color: #fff; }
  button.danger:hover { background: #f85149; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .status { font-size: 13px; margin-top: 8px; }
  .status.ok { color: var(--green); }
  .status.err { color: var(--red); }
  .status.warn { color: var(--orange); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); color: var(--text-dim); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 500;
  }
  .badge.online { background: rgba(63,185,80,0.15); color: var(--green); }
  .badge.offline { background: rgba(139,148,158,0.15); color: var(--text-dim); }
  .badge.mesh { background: rgba(88,166,255,0.15); color: var(--accent); }
  .empty { text-align: center; padding: 32px; color: var(--text-dim); }
  .mesh-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .flex-between { display: flex; justify-content: space-between; align-items: center; }
  .log { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; max-height: 200px; overflow-y: auto; white-space: pre-wrap; color: var(--text-dim); margin-top: 12px; display: none; }
  @media (max-width: 600px) { .row { flex-direction: column; } }
</style>
</head>
<body>
<div class="container">
  <h1>Fritz!Box Tools</h1>
  <p class="subtitle">Device list and mesh pairing</p>

  <!-- Login -->
  <div class="card" id="login-card">
    <h2>Connect to Fritz!Box</h2>
    <div class="row">
      <div>
        <label for="host">Host</label>
        <input type="text" id="host" value="fritz.box" placeholder="fritz.box or 192.168.178.1">
      </div>
      <div>
        <label for="username">Username</label>
        <input type="text" id="username" value="" placeholder="(optional)">
      </div>
    </div>
    <label for="password">Password</label>
    <input type="password" id="password" placeholder="Fritz!Box password">
    <button class="primary" id="btn-login" onclick="doLogin()">Connect</button>
    <button id="btn-logout" onclick="doLogout()" style="display:none; margin-left: 8px;">Disconnect</button>
    <div class="status" id="login-status"></div>
  </div>

  <!-- Devices -->
  <div class="card" id="devices-card" style="display:none;">
    <div class="flex-between">
      <h2>LAN Devices</h2>
      <button onclick="loadDevices()">Refresh</button>
    </div>
    <div id="devices-content">
      <div class="empty">Loading...</div>
    </div>
  </div>

  <!-- Mesh Pairing -->
  <div class="card" id="mesh-card" style="display:none;">
    <h2>Mesh Pairing</h2>
    <p style="font-size: 13px; color: var(--text-dim); margin-bottom: 12px;">
      Start mesh coupling on the Fritz!Box master. Optionally trigger WPS on a repeater via TR-064.
    </p>
    <div class="row">
      <div>
        <label for="repeater-ip">Repeater IP (optional)</label>
        <input type="text" id="repeater-ip" placeholder="192.168.178.2">
      </div>
      <div>
        <label for="repeater-pw">Repeater Password</label>
        <input type="password" id="repeater-pw" placeholder="(uses main password if empty)">
      </div>
    </div>
    <button class="primary" id="btn-mesh" onclick="startMeshPairing()">Start Mesh Coupling</button>
    <button id="btn-mesh-stop" onclick="stopMeshPolling()" style="display:none; margin-left: 8px;">Stop Polling</button>
    <div class="status" id="mesh-status"></div>
    <div class="log" id="mesh-log"></div>
  </div>
</div>

<script>
let polling = false;
let pollTimer = null;

async function api(path, body) {
  const opts = {method: body ? "POST" : "GET", headers: {"Content-Type": "application/json"}};
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

function setStatus(id, msg, cls) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = "status " + (cls || "");
}

function appendLog(msg) {
  const el = document.getElementById("mesh-log");
  el.style.display = "block";
  el.textContent += msg + "\n";
  el.scrollTop = el.scrollHeight;
}

async function doLogin() {
  const host = document.getElementById("host").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!host || !password) { setStatus("login-status", "Host and password required.", "err"); return; }

  document.getElementById("btn-login").disabled = true;
  setStatus("login-status", "Connecting...", "warn");

  try {
    const r = await api("/api/login", {host, username, password});
    if (r.error) { setStatus("login-status", r.error, "err"); return; }
    setStatus("login-status", "Connected. SID: " + r.sid, "ok");
    document.getElementById("btn-logout").style.display = "inline-block";
    document.getElementById("devices-card").style.display = "block";
    document.getElementById("mesh-card").style.display = "block";
    loadDevices();
  } catch (e) {
    setStatus("login-status", "Connection failed: " + e.message, "err");
  } finally {
    document.getElementById("btn-login").disabled = false;
  }
}

async function doLogout() {
  const host = document.getElementById("host").value.trim();
  await api("/api/logout", {host});
  setStatus("login-status", "Disconnected.", "");
  document.getElementById("btn-logout").style.display = "none";
  document.getElementById("devices-card").style.display = "none";
  document.getElementById("mesh-card").style.display = "none";
}

async function loadDevices() {
  const host = document.getElementById("host").value.trim();
  const el = document.getElementById("devices-content");
  el.innerHTML = '<div class="empty">Loading...</div>';

  try {
    const r = await api("/api/devices", {host});
    if (r.error) { el.innerHTML = '<div class="empty">' + r.error + '</div>'; return; }
    renderDevices(r.devices);
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load: ' + e.message + '</div>';
  }
}

function renderDevices(devices) {
  const el = document.getElementById("devices-content");
  if (!devices || devices.length === 0) {
    el.innerHTML = '<div class="empty">No devices found.</div>';
    return;
  }

  // Sort: online first, then by name
  devices.sort((a, b) => {
    if (a.online !== b.online) return a.online ? -1 : 1;
    return (a.name || "").localeCompare(b.name || "");
  });

  let html = '<table><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Status</th><th>Type</th></tr></thead><tbody>';
  for (const d of devices) {
    const status = d.online
      ? '<span class="badge online">online</span>'
      : '<span class="badge offline">offline</span>';
    const mesh = d.mesh ? ' <span class="badge mesh">mesh</span>' : '';
    html += `<tr>
      <td>${esc(d.name || "(unknown)")}</td>
      <td>${esc(d.ip || "-")}</td>
      <td style="font-family: monospace; font-size: 13px;">${esc(d.mac || "-")}</td>
      <td>${status}</td>
      <td>${esc(d.type || "-")}${mesh}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

async function startMeshPairing() {
  const host = document.getElementById("host").value.trim();
  const repeaterIp = document.getElementById("repeater-ip").value.trim();
  const repeaterPw = document.getElementById("repeater-pw").value;

  document.getElementById("btn-mesh").disabled = true;
  document.getElementById("mesh-log").textContent = "";
  document.getElementById("mesh-log").style.display = "block";
  setStatus("mesh-status", "Starting mesh coupling...", "warn");
  appendLog("[" + new Date().toLocaleTimeString() + "] Starting mesh coupling on " + host);

  try {
    const r = await api("/api/mesh/start", {host, repeater_ip: repeaterIp || null, repeater_password: repeaterPw || null});
    if (r.error) {
      setStatus("mesh-status", r.error, "err");
      appendLog("Error: " + r.error);
      document.getElementById("btn-mesh").disabled = false;
      return;
    }
    appendLog(r.message || "Mesh coupling started.");
    if (r.wps_message) appendLog(r.wps_message);

    // Start polling
    polling = true;
    document.getElementById("btn-mesh-stop").style.display = "inline-block";
    setStatus("mesh-status", "Polling for new mesh peers...", "warn");
    pollMesh();
  } catch (e) {
    setStatus("mesh-status", "Failed: " + e.message, "err");
    appendLog("Error: " + e.message);
    document.getElementById("btn-mesh").disabled = false;
  }
}

async function pollMesh() {
  if (!polling) return;
  const host = document.getElementById("host").value.trim();

  try {
    const r = await api("/api/mesh/poll", {host});
    if (r.error) {
      appendLog("Poll error: " + r.error);
    } else if (r.new_peers && r.new_peers.length > 0) {
      appendLog("[" + new Date().toLocaleTimeString() + "] New mesh peer(s): " + r.new_peers.join(", "));
      setStatus("mesh-status", "Pairing successful!", "ok");
      stopMeshPolling();
      loadDevices();
      return;
    } else {
      appendLog("[" + new Date().toLocaleTimeString() + "] Waiting... (" + (r.peer_count || 0) + " trusted peers)");
    }
  } catch (e) {
    appendLog("Poll error: " + e.message);
  }

  if (polling) {
    pollTimer = setTimeout(pollMesh, 5000);
  }
}

function stopMeshPolling() {
  polling = false;
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  document.getElementById("btn-mesh").disabled = false;
  document.getElementById("btn-mesh-stop").style.display = "none";
  if (document.getElementById("mesh-status").classList.contains("warn")) {
    setStatus("mesh-status", "Polling stopped.", "");
  }
}
</script>
</body>
</html>"""


class FritzHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quieter logging
        print(f"[{self.log_date_time_string()}] {format % args}", file=sys.stderr)

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "":
            self.send_html(HTML_PAGE)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_body()
        except Exception:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        if path == "/api/login":
            self.handle_login(body)
        elif path == "/api/logout":
            self.handle_logout(body)
        elif path == "/api/devices":
            self.handle_devices(body)
        elif path == "/api/mesh/start":
            self.handle_mesh_start(body)
        elif path == "/api/mesh/poll":
            self.handle_mesh_poll(body)
        else:
            self.send_json({"error": "Not found"}, 404)

    def handle_login(self, body: dict):
        host = body.get("host", "fritz.box")
        username = body.get("username", "")
        password = body.get("password", "")
        if not password:
            self.send_json({"error": "Password required."})
            return

        try:
            sid = login(host, username, password)
        except Exception as e:
            self.send_json({"error": f"Login failed: {e}"})
            return

        set_session(host, {"sid": sid, "host": host, "username": username, "password": password})
        self.send_json({"sid": sid})

    def handle_logout(self, body: dict):
        host = body.get("host", "fritz.box")
        clear_session(host)
        self.send_json({"ok": True})

    def handle_devices(self, body: dict):
        host = body.get("host", "fritz.box")
        session = get_session(host)
        if not session:
            self.send_json({"error": "Not connected. Please login first."})
            return

        try:
            data = api_get(host, session["sid"], "landevice")
        except URLError as e:
            # Session may have expired, try re-login
            try:
                sid = login(host, session["username"], session["password"])
                set_session(host, {**session, "sid": sid})
                data = api_get(host, sid, "landevice")
            except Exception as e2:
                self.send_json({"error": f"Failed to fetch devices: {e2}"})
                return
        except Exception as e:
            self.send_json({"error": f"Failed to fetch devices: {e}"})
            return

        devices = parse_landevices(data)
        self.send_json({"devices": devices})

    def handle_mesh_start(self, body: dict):
        host = body.get("host", "fritz.box")
        repeater_ip = body.get("repeater_ip")
        repeater_password = body.get("repeater_password")
        session = get_session(host)
        if not session:
            self.send_json({"error": "Not connected. Please login first."})
            return

        # Start mesh coupling on master
        try:
            result = api_put(host, session["sid"], "nexus", {"enhanced_trust_mode": "1"})
        except Exception as e:
            self.send_json({"error": f"Failed to start mesh coupling: {e}"})
            return

        response = {"message": "Mesh coupling started on master."}

        # Capture initial peer state for polling
        try:
            nexus = api_get(host, session["sid"], "nexus")
            initial_peers = extract_trusted_peers(nexus)
            set_session(host, {**session, "initial_peers": initial_peers})
        except Exception:
            pass

        # Trigger WPS on repeater if specified
        if repeater_ip:
            pw = repeater_password or session.get("password", "")
            try:
                tr064_call(
                    host=repeater_ip,
                    service=WLAN_SERVICE,
                    control_url=WLAN_CONTROL_URL,
                    action="X_AVM-DE_SetWPSConfig",
                    arguments={"NewX_AVM-DE_WPSMode": "pbc"},
                    username="",
                    password=pw,
                )
                response["wps_message"] = f"WPS triggered on repeater {repeater_ip}."
            except Exception as e:
                response["wps_message"] = f"Failed to trigger WPS on repeater: {e}. Press WPS button manually."

        self.send_json(response)

    def handle_mesh_poll(self, body: dict):
        host = body.get("host", "fritz.box")
        session = get_session(host)
        if not session:
            self.send_json({"error": "Not connected."})
            return

        try:
            nexus = api_get(host, session["sid"], "nexus")
        except Exception as e:
            self.send_json({"error": f"Poll failed: {e}"})
            return

        current_peers = extract_trusted_peers(nexus)
        initial_peers = session.get("initial_peers", set())
        new_peers = list(current_peers - initial_peers)

        self.send_json({
            "peer_count": len(current_peers),
            "new_peers": new_peers,
        })


def extract_trusted_peers(nexus_data: dict) -> set:
    """Extract UIDs of trusted peers from nexus API response."""
    peers = set()
    peers_data = nexus_data.get("peers", [])
    if isinstance(peers_data, list) and peers_data:
        first = peers_data[0] if peers_data else {}
        for peer in first.get("peer", []):
            uid = peer.get("UID", "")
            if peer.get("peer_trusted") == "1" and peer.get("iam_trusted") == "1" and uid:
                peers.add(uid)
    return peers


def parse_landevices(data: dict) -> list[dict]:
    """Parse the landevice API response into a flat device list."""
    devices = []
    # The landevice response structure varies; handle nested lists
    device_list = data.get("landevice", data.get("devices", []))
    if isinstance(device_list, dict):
        device_list = device_list.get("device", [])
    if isinstance(device_list, list) and device_list:
        # Sometimes it's [{device: [...]}]
        if isinstance(device_list[0], dict) and "device" in device_list[0]:
            device_list = device_list[0]["device"]

    for dev in device_list:
        if not isinstance(dev, dict):
            continue
        devices.append({
            "name": dev.get("name", dev.get("hostname", "")),
            "ip": dev.get("ip", dev.get("ipv4", "")),
            "mac": dev.get("mac", ""),
            "online": dev.get("active") == "1" or dev.get("online") == "1" or dev.get("active") is True,
            "type": dev.get("type", dev.get("devtype", "")),
            "mesh": dev.get("mesh_state") == "1" or dev.get("is_mesh") == "1",
        })

    return devices


def main():
    parser = argparse.ArgumentParser(description="Fritz!Box Web UI")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--bind", default="127.0.0.1", help="Address to bind (default: 127.0.0.1)")
    args = parser.parse_args()

    server = HTTPServer((args.bind, args.port), FritzHandler)
    print(f"Fritz!Box Web UI running at http://{args.bind}:{args.port}/", file=sys.stderr)
    print("Press Ctrl+C to stop.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.", file=sys.stderr)
        server.shutdown()


if __name__ == "__main__":
    main()

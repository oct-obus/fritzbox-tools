#!/usr/bin/env python3
"""
Fritz!Box mesh pairing tool. Initiates mesh coupling remotely without
pressing physical WPS buttons.

Flow:
  1. Login to Fritz!Box (master) via PBKDF2 auth
  2. PUT enhanced_trust_mode=1 to start mesh coupling on the master
  3. Trigger WPS on the repeater via TR-064 SOAP
  4. Poll nexus status until pairing completes or times out

Usage:
    # Start mesh coupling on Fritz!Box + trigger WPS on a repeater
    python mesh_pair.py --repeater-ip 192.168.178.2

    # Just start mesh coupling on Fritz!Box (press WPS on repeater manually)
    python mesh_pair.py --master-only

    # With explicit credentials
    python mesh_pair.py -p "password" --repeater-ip 192.168.178.2 --repeater-password "reppw"
"""

import argparse
import json
import sys
import time

from fritzbox_auth import login, api_get, api_put, tr064_call

WLAN_SERVICE = "urn:dslforum-org:service:WLANConfiguration:1"
WLAN_CONTROL_URL = "/upnp/control/wlanconfig1"


def start_mesh_coupling(host: str, sid: str) -> None:
    """Put the Fritz!Box into mesh coupling mode (enhanced trust mode)."""
    print("Starting mesh coupling on Fritz!Box...", file=sys.stderr)
    result = api_put(host, sid, "nexus", {"enhanced_trust_mode": "1"})
    print(f"  Result: {json.dumps(result)}", file=sys.stderr)


def trigger_repeater_wps(repeater_ip: str, username: str = "", password: str = "") -> None:
    """Trigger WPS push-button mode on a repeater via TR-064."""
    print(f"Triggering WPS on repeater {repeater_ip}...", file=sys.stderr)

    # WPS mode "pbc" = push-button configuration
    try:
        result = tr064_call(
            host=repeater_ip,
            service=WLAN_SERVICE,
            control_url=WLAN_CONTROL_URL,
            action="X_AVM-DE_SetWPSConfig",
            arguments={"NewX_AVM-DE_WPSMode": "pbc"},
            username=username,
            password=password,
        )
        # Extract status from response
        ns = {"s": "http://schemas.xmlsoap.org/soap/envelope/",
              "u": WLAN_SERVICE}
        status_el = result.find(f".//NewX_AVM-DE_WPSStatus")
        if status_el is None:
            # Try without namespace
            status_el = result.find(f".//{{{WLAN_SERVICE}}}NewX_AVM-DE_WPSStatus")
        status = status_el.text if status_el is not None else "unknown"
        print(f"  WPS status: {status}", file=sys.stderr)
    except Exception as e:
        print(f"  Failed to trigger WPS on repeater: {e}", file=sys.stderr)
        print("  You may need to press the WPS button on the repeater manually.", file=sys.stderr)


def get_wps_info(host: str, username: str = "", password: str = "") -> dict:
    """Get current WPS status via TR-064."""
    try:
        result = tr064_call(
            host=host,
            service=WLAN_SERVICE,
            control_url=WLAN_CONTROL_URL,
            action="X_AVM-DE_GetWPSInfo",
            username=username,
            password=password,
        )
        info = {}
        for tag in ["NewX_AVM-DE_WPSMode", "NewX_AVM-DE_WPSStatus"]:
            el = result.find(f".//{tag}")
            if el is None:
                el = result.find(f".//{{{WLAN_SERVICE}}}{tag}")
            info[tag] = el.text if el is not None else "unknown"
        return info
    except Exception as e:
        return {"error": str(e)}


def poll_mesh_status(host: str, sid: str, timeout: int = 120, interval: int = 5) -> bool:
    """Poll nexus data until a new peer appears as trusted, or timeout."""
    print(f"Polling mesh status (timeout: {timeout}s)...", file=sys.stderr)

    # Get initial peer state
    initial = api_get(host, sid, "nexus")
    initial_peers = set()
    peers_data = initial.get("peers", [])
    if isinstance(peers_data, list) and peers_data:
        first = peers_data[0] if peers_data else {}
        for peer in first.get("peer", []):
            uid = peer.get("UID", "")
            trusted = peer.get("peer_trusted") == "1" and peer.get("iam_trusted") == "1"
            if trusted and uid:
                initial_peers.add(uid)

    start = time.time()
    while time.time() - start < timeout:
        time.sleep(interval)
        elapsed = int(time.time() - start)

        try:
            current = api_get(host, sid, "nexus")
        except Exception as e:
            print(f"  [{elapsed}s] Error polling: {e}", file=sys.stderr)
            continue

        current_peers = set()
        peers_data = current.get("peers", [])
        if isinstance(peers_data, list) and peers_data:
            first = peers_data[0] if peers_data else {}
            for peer in first.get("peer", []):
                uid = peer.get("UID", "")
                trusted = peer.get("peer_trusted") == "1" and peer.get("iam_trusted") == "1"
                if trusted and uid:
                    current_peers.add(uid)

        new_peers = current_peers - initial_peers
        if new_peers:
            print(f"  [{elapsed}s] New mesh peer(s) joined: {new_peers}", file=sys.stderr)
            return True

        print(f"  [{elapsed}s] Waiting... ({len(current_peers)} trusted peers)", file=sys.stderr)

    print(f"  Timed out after {timeout}s.", file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description="Fritz!Box mesh pairing tool")
    parser.add_argument("--host", default="fritz.box", help="Fritz!Box master hostname/IP")
    parser.add_argument("--user", "-u", default="", help="Fritz!Box username")
    parser.add_argument("--password", "-p", default=None, help="Fritz!Box password (prompted if omitted)")
    parser.add_argument("--repeater-ip", default=None, help="Repeater IP for remote WPS trigger")
    parser.add_argument("--repeater-user", default="", help="Repeater TR-064 username (usually empty)")
    parser.add_argument("--repeater-password", default=None, help="Repeater password (uses main password if omitted)")
    parser.add_argument("--master-only", action="store_true", help="Only start coupling on master, skip repeater")
    parser.add_argument("--timeout", type=int, default=120, help="Pairing timeout in seconds (default: 120)")
    parser.add_argument("--no-poll", action="store_true", help="Don't poll for completion")
    parser.add_argument("--wps-info", action="store_true", help="Just show WPS status and exit")
    parser.add_argument("--sid", default=None, help="Reuse existing SID")
    args = parser.parse_args()

    # Login to Fritz!Box
    if args.sid:
        sid = args.sid
    else:
        sid = login(args.host, args.user, args.password or "")
        print(f"SID: {sid}", file=sys.stderr)

    repeater_pw = args.repeater_password or args.password or ""

    # WPS info mode
    if args.wps_info:
        if args.repeater_ip:
            info = get_wps_info(args.repeater_ip, args.repeater_user, repeater_pw)
            print(f"Repeater WPS: {json.dumps(info, indent=2)}")
        info = get_wps_info(args.host, args.user, args.password or "")
        print(f"Master WPS: {json.dumps(info, indent=2)}")
        return

    # Start mesh coupling on master
    start_mesh_coupling(args.host, sid)

    # Trigger WPS on repeater
    if not args.master_only:
        if args.repeater_ip:
            trigger_repeater_wps(args.repeater_ip, args.repeater_user, repeater_pw)
        else:
            print("\nNo --repeater-ip given. Press the WPS/Connect button on the repeater now.", file=sys.stderr)
            print("Or re-run with --repeater-ip <ip> to trigger it remotely.\n", file=sys.stderr)

    # Poll for completion
    if not args.no_poll:
        success = poll_mesh_status(args.host, sid, timeout=args.timeout)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

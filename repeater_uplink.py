#!/usr/bin/env python3
"""
Repeater uplink control — change which AP a Fritz!Repeater connects to.

Authenticates directly to a repeater's web UI and uses the wizard_meshset
page to scan for available APs and set a new uplink BSSID.

Usage:
    python3 repeater_uplink.py scan -r 192.168.178.46
    python3 repeater_uplink.py scan -r 192.168.178.46 -p "password"
    python3 repeater_uplink.py set  -r 192.168.178.46 --bssid AA:BB:CC:DD:EE:FF
    python3 repeater_uplink.py status -r 192.168.178.46
    python3 repeater_uplink.py list-repeaters -m 192.168.178.1 -p "password"

Requires: fritzbox_auth.py (in the same directory)
"""

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import fritzbox_auth


def data_lua_post(host: str, sid: str, params: dict, timeout: int = 15) -> dict:
    """POST to data.lua and return parsed JSON response."""
    params["sid"] = sid
    body = urlencode(params).encode()
    url = f"http://{host}/data.lua"
    req = Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def query_lua(host: str, sid: str, queries: dict, timeout: int = 10) -> dict:
    """GET query.lua with multiple variable queries. Returns {name: value}."""
    params = {"sid": sid}
    params.update(queries)
    qs = urlencode(params)
    url = f"http://{host}/query.lua?{qs}"
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def get_uplink_status(host: str, sid: str) -> dict:
    """Read current uplink config from a repeater via query.lua."""
    queries = {
        "mac_master": "wlan:settings/STA_mac_master",
        "mac_master_5g": "wlan:settings/STA_mac_master_scnd",
        "ssid": "wlan:settings/STA_ssid",
        "ssid_5g": "wlan:settings/STA_ssid_scnd",
        "configured": "wlan:settings/STA_configured",
        "configured_5g": "wlan:settings/STA_configured_scnd",
        "uplink_state": "wlan:settings/STA_uplink_state",
        "uplink_state_5g": "wlan:settings/STA_uplink_state_scnd",
        "encryption": "wlan:settings/STA_encryption",
        "bridge_mode": "wlan:settings/bridge_mode",
        "role": "nexus:settings/role",
    }
    return query_lua(host, sid, queries)


def trigger_scan(host: str, sid: str) -> dict:
    """Trigger an AP environment scan on the repeater."""
    return data_lua_post(host, sid, {
        "page": "wizard_meshset",
        "xhrId": "refresh_scanlist",
    })


def poll_scanlist(host: str, sid: str) -> dict:
    """Poll AP scan results from the repeater."""
    return data_lua_post(host, sid, {
        "page": "wizard_meshset",
        "xhrId": "request_scanlist",
    })


def set_uplink(host: str, sid: str, bssid: str, ssid: str,
               psk: str, encryption: str = "wpa2",
               band: str = "auto") -> dict:
    """Set the repeater's uplink to a specific AP."""
    params = {
        "page": "wizard_meshset",
        "roleType": "repeater",
        "connectionType": "wifi",
        "mac": bssid,
        "ssid": ssid,
        "enc": encryption,
        "pskvalue": psk,
    }
    if band == "5g":
        params["mac_scnd"] = bssid
        params["ssid_scnd"] = ssid
    return data_lua_post(host, sid, params, timeout=30)


def list_repeaters_from_master(host: str, sid: str) -> list:
    """Get repeater list from master's landevice API."""
    devices = fritzbox_auth.api_get(host, sid, "landevice")
    repeaters = []
    for dev in devices.get("landevice", devices if isinstance(devices, list) else []):
        if not isinstance(dev, dict):
            continue
        model = dev.get("modelname", "").lower()
        nexus = dev.get("nexuspeer_UID", "")
        is_rep = "repeater" in model or (nexus and dev.get("mesh_UIDs", ""))
        if is_rep:
            repeaters.append({
                "name": dev.get("name", "?"),
                "model": dev.get("modelname", "?"),
                "ip": dev.get("ip", ""),
                "mac": dev.get("mac", ""),
                "online": dev.get("online") == "1" or dev.get("online") == 1,
                "nexuspeer_UID": nexus,
            })
    return repeaters


def cmd_status(args):
    """Show current uplink status of a repeater."""
    sid = fritzbox_auth.login(args.repeater, args.username, args.password)
    print(f"✓ Authenticated to {args.repeater} (SID: {sid[:8]}...)")

    status = get_uplink_status(args.repeater, sid)
    print(f"\nRepeater role: {status.get('role', '?')}")
    print(f"Bridge mode:   {status.get('bridge_mode', '?')}")
    print(f"\n2.4 GHz uplink:")
    print(f"  BSSID:     {status.get('mac_master', '?')}")
    print(f"  SSID:      {status.get('ssid', '?')}")
    print(f"  Configured: {status.get('configured', '?')}")
    state = status.get("uplink_state", "?")
    state_str = {"0": "disconnected", "1": "connecting", "2": "authenticating", "3": "connected"}.get(str(state), state)
    print(f"  State:     {state_str}")
    print(f"\n5 GHz uplink:")
    print(f"  BSSID:     {status.get('mac_master_5g', '?')}")
    print(f"  SSID:      {status.get('ssid_5g', '?')}")
    print(f"  Configured: {status.get('configured_5g', '?')}")
    state5 = status.get("uplink_state_5g", "?")
    state5_str = {"0": "disconnected", "1": "connecting", "2": "authenticating", "3": "connected"}.get(str(state5), state5)
    print(f"  State:     {state5_str}")


def cmd_scan(args):
    """Scan for available APs from the repeater's perspective."""
    sid = fritzbox_auth.login(args.repeater, args.username, args.password)
    print(f"✓ Authenticated to {args.repeater}")

    print("Triggering AP scan...")
    trigger_scan(args.repeater, sid)

    # Poll until scan results are ready
    for attempt in range(args.poll_attempts):
        time.sleep(args.poll_interval)
        print(f"  Polling scan results ({attempt + 1}/{args.poll_attempts})...")
        result = poll_scanlist(args.repeater, sid)

        scanlist = result.get("data", {}).get("scanlist", [])
        if scanlist:
            print(f"\n{'BSSID':<20} {'RSSI':>5} {'Ch':>4} {'Enc':<8} {'SSID'}")
            print("-" * 70)
            for ap in sorted(scanlist, key=lambda x: -int(x.get("rssi", 0))):
                bssid = ap.get("mac", ap.get("bssid", "?"))
                rssi = ap.get("rssi", "?")
                channel = ap.get("channel", "?")
                enc = ap.get("enc", ap.get("encryption", "?"))
                ssid = ap.get("ssid", "?")
                suitable = " ✓" if ap.get("suitable") else ""
                print(f"{bssid:<20} {rssi:>5} {channel:>4} {enc:<8} {ssid}{suitable}")
            print(f"\nTotal: {len(scanlist)} APs found")
            if args.json:
                print(json.dumps(scanlist, indent=2))
            return

    print("No scan results after polling. The repeater may need more time.")


def cmd_set(args):
    """Set the repeater's uplink to a specific AP."""
    if not args.bssid:
        print("Error: --bssid is required", file=sys.stderr)
        sys.exit(1)
    if not args.ssid:
        print("Error: --ssid is required (the WiFi network name)", file=sys.stderr)
        sys.exit(1)
    if not args.psk:
        print("Error: --psk is required (the WiFi password)", file=sys.stderr)
        sys.exit(1)

    sid = fritzbox_auth.login(args.repeater, args.username, args.password)
    print(f"✓ Authenticated to {args.repeater}")

    print(f"Setting uplink to BSSID={args.bssid}, SSID={args.ssid}...")
    result = set_uplink(
        args.repeater, sid,
        bssid=args.bssid,
        ssid=args.ssid,
        psk=args.psk,
        encryption=args.encryption,
        band=args.band,
    )
    print(f"Response: {json.dumps(result, indent=2)}")
    print("\n⚠️  The repeater will disconnect and reconnect to the new AP.")
    print("   This may take 30-60 seconds. Check status afterwards with:")
    print(f"   python3 repeater_uplink.py status -r {args.repeater}")


def cmd_list_repeaters(args):
    """List all repeaters from the master Fritz!Box."""
    host = args.master
    sid = fritzbox_auth.login(host, args.username, args.password)
    print(f"✓ Authenticated to master at {host}")

    repeaters = list_repeaters_from_master(host, sid)
    if not repeaters:
        print("No repeaters found.")
        return

    print(f"\n{'Name':<30} {'Model':<25} {'IP':<17} {'MAC':<19} {'Status'}")
    print("-" * 100)
    for r in sorted(repeaters, key=lambda x: x["name"]):
        status = "🟢 online" if r["online"] else "🔴 offline"
        print(f"{r['name']:<30} {r['model']:<25} {r['ip']:<17} {r['mac']:<19} {status}")
    print(f"\nTotal: {len(repeaters)} repeaters")


def main():
    parser = argparse.ArgumentParser(
        description="Fritz!Repeater uplink control — change which AP a repeater connects to.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list-repeaters -m 192.168.178.1 -p "password"
  %(prog)s status -r 192.168.178.46 -p "password"
  %(prog)s scan -r 192.168.178.46 -p "password"
  %(prog)s set -r 192.168.178.46 --bssid AA:BB:CC:DD:EE:FF --ssid MyWiFi --psk "wifipass"
""")

    parser.add_argument("-u", "--username", default="", help="Fritz!Box username (default: empty)")
    parser.add_argument("-p", "--password", default="", help="Fritz!Box password")

    sub = parser.add_subparsers(dest="command", required=True)

    # list-repeaters
    p_list = sub.add_parser("list-repeaters", help="List repeaters from master Fritz!Box")
    p_list.add_argument("-m", "--master", default="192.168.178.1", help="Master Fritz!Box IP")

    # status
    p_status = sub.add_parser("status", help="Show current uplink status of a repeater")
    p_status.add_argument("-r", "--repeater", required=True, help="Repeater IP address")

    # scan
    p_scan = sub.add_parser("scan", help="Scan for available APs from repeater")
    p_scan.add_argument("-r", "--repeater", required=True, help="Repeater IP address")
    p_scan.add_argument("--poll-attempts", type=int, default=10, help="Max poll attempts (default: 10)")
    p_scan.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between polls (default: 2)")
    p_scan.add_argument("--json", action="store_true", help="Output raw JSON scan results")

    # set
    p_set = sub.add_parser("set", help="Change repeater uplink to a specific AP")
    p_set.add_argument("-r", "--repeater", required=True, help="Repeater IP address")
    p_set.add_argument("--bssid", required=True, help="Target AP BSSID (MAC address)")
    p_set.add_argument("--ssid", required=True, help="Target AP SSID")
    p_set.add_argument("--psk", required=True, help="WiFi password")
    p_set.add_argument("--encryption", default="wpa2", help="Encryption type (default: wpa2)")
    p_set.add_argument("--band", default="auto", choices=["auto", "5g"], help="Band to set (default: auto)")

    args = parser.parse_args()

    try:
        {"list-repeaters": cmd_list_repeaters, "status": cmd_status,
         "scan": cmd_scan, "set": cmd_set}[args.command](args)
    except (HTTPError, URLError) as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Fritz!Box mesh topology manager.

View your mesh network, list repeaters and their connections, identify
which repeater each device connects through, and initiate mesh pairing.

Commands:
  list      List all repeaters with their mesh status and uplink info
  topology  Show full mesh topology tree (router -> repeaters -> clients)
  clients   Show which devices connect through each repeater
  pair      Initiate mesh pairing (WPS-based, always through the master)
  info      Show detailed raw info for a device by name or IP

Usage:
  python mesh_manager.py list -p "password"
  python mesh_manager.py topology -p "password"
  python mesh_manager.py clients -p "password"
  python mesh_manager.py pair --repeater-ip 192.168.178.2 -p "password"
  python mesh_manager.py info "repeater1200Tesla" -p "password"

Note on re-pairing through a specific repeater:
  Fritz!Box firmware does not expose an API for changing a repeater's
  uplink target. Mesh trust is always established with the master via
  WPS. The actual WiFi uplink path is auto-selected by signal strength,
  or can be manually changed via the repeater's own web UI:
    Repeater Web UI -> Home Network -> Mesh -> Mesh Settings
"""

import argparse
import json
import sys
from fritzbox_auth import login, api_get, api_put, tr064_call


WLAN_SERVICE = "urn:dslforum-org:service:WLANConfiguration:1"
WLAN_CONTROL_URL = "/upnp/control/wlanconfig1"


def is_meshed(d):
    """Determine if a device is actively meshed."""
    mesh_uid = d.get("mesh_UIDs", "")
    if not mesh_uid:
        return False
    if d.get("nexuspeer_UID"):
        return True
    link_list = d.get("link_list", [])
    if isinstance(link_list, list) and link_list:
        entries = link_list[0].get("entry", []) if isinstance(link_list[0], dict) else []
        if any(e.get("is_uplink") == "1" for e in entries):
            return True
    return False


def fetch_devices(host, sid):
    """Fetch the full landevice list."""
    data = api_get(host, sid, "landevice")
    devices = data.get("landevice") or data.get("devices") or data
    if isinstance(devices, dict):
        devices = devices.get("device", [])
    if isinstance(devices, list) and devices and isinstance(devices[0], dict) and "device" in devices[0]:
        devices = devices[0]["device"]
    return devices if isinstance(devices, list) else []


def fetch_mesh(host, sid):
    """Fetch mesh topology via data.lua."""
    from urllib.request import Request, urlopen
    url = f"http://{host}/data.lua"
    body = f"sid={sid}&page=mesh".encode()
    req = Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"Warning: Could not fetch mesh topology: {e}", file=sys.stderr)
        return None


def is_repeater(d, mesh_nodes=None):
    """Determine if a device is a repeater using multiple heuristics."""
    modelname = (d.get("modelname") or "").lower()
    if "repeater" in modelname:
        return True
    if d.get("nexuspeer_UID"):
        return True
    mesh_uid = d.get("mesh_UIDs", "")
    if mesh_uid and mesh_nodes and mesh_uid in mesh_nodes:
        if mesh_nodes[mesh_uid].get("mesh_type") == "slave":
            return True
    link_list = d.get("link_list", [])
    if isinstance(link_list, list) and link_list:
        entries = link_list[0].get("entry", []) if isinstance(link_list[0], dict) else []
        for e in entries:
            if e.get("is_uplink") == "0" and (e.get("local_interface_name") or "").startswith("AP:"):
                return True
    return False


def parse_mesh_nodes(mesh_data):
    """Parse mesh topology into a uid -> node dict."""
    if not mesh_data or "data" not in mesh_data:
        return {}
    nodes = {}
    for node in mesh_data.get("data", {}).get("nodes", []):
        nodes[str(node.get("uid", ""))] = node
    return nodes


def get_uplink_info(d, devices_by_mesh_uid):
    """Get uplink info from a device's link_list."""
    link_list = d.get("link_list", [])
    if not isinstance(link_list, list) or not link_list:
        return None
    entries = link_list[0].get("entry", []) if isinstance(link_list[0], dict) else []
    for e in entries:
        if e.get("is_uplink") == "1":
            remote_uid = e.get("remote_dev_mesh_uid", "")
            remote_dev = devices_by_mesh_uid.get(remote_uid)
            name = (remote_dev.get("friendly_name") or remote_dev.get("name", "?")) if remote_dev else (
                "Fritz!Box" if remote_uid == "1" else f"Node {remote_uid}"
            )
            return {
                "name": name,
                "media": e.get("media_type", ""),
                "speed": e.get("speed", ""),
                "local_iface": e.get("local_interface_name", ""),
                "remote_iface": e.get("remote_interface_name", ""),
            }
    return None


def get_connected_clients(d, devices_by_mesh_uid, repeater_uids):
    """Get clients connected to this device (from its AP link_list entries)."""
    link_list = d.get("link_list", [])
    if not isinstance(link_list, list) or not link_list:
        return []
    entries = link_list[0].get("entry", []) if isinstance(link_list[0], dict) else []
    clients = []
    for e in entries:
        if e.get("is_uplink") == "0" and e.get("remote_dev_mesh_uid"):
            client_dev = devices_by_mesh_uid.get(e["remote_dev_mesh_uid"])
            if client_dev and client_dev.get("UID") != d.get("UID"):
                clients.append({
                    "name": client_dev.get("friendly_name") or client_dev.get("name", "?"),
                    "ip": client_dev.get("ip", ""),
                    "online": client_dev.get("active") == "1",
                    "is_repeater": client_dev.get("UID") in repeater_uids,
                    "media": e.get("media_type", ""),
                    "speed": e.get("speed", "0"),
                    "interface": e.get("local_interface_name", ""),
                })
    return clients


def cmd_list(args):
    """List all repeaters with mesh status and uplink info."""
    sid = args.sid or login(args.host, args.user, args.password or "")
    devices = fetch_devices(args.host, sid)
    mesh = fetch_mesh(args.host, sid)
    mesh_nodes = parse_mesh_nodes(mesh)
    devices_by_mesh_uid = {d["mesh_UIDs"]: d for d in devices if d.get("mesh_UIDs")}

    repeaters = [d for d in devices if is_repeater(d, mesh_nodes)]

    if not repeaters:
        print("No repeaters found.")
        return

    print(f"Found {len(repeaters)} repeater(s):\n")
    for d in repeaters:
        name = d.get("friendly_name") or d.get("name") or "(unknown)"
        model = d.get("modelname") or ""
        ip = d.get("ip") or "-"
        online = d.get("active") == "1"
        meshed = is_meshed(d)
        uplink = get_uplink_info(d, devices_by_mesh_uid)
        status = "ONLINE" if online else "offline"
        mesh_status = "meshed" if meshed else "not meshed"

        print(f"  {name}")
        if model:
            print(f"    Model:   {model}")
        print(f"    IP:      {ip}")
        print(f"    Status:  {status}, {mesh_status}")
        print(f"    UID:     {d.get('UID', '-')}")
        print(f"    MAC:     {d.get('mac', '-')}")
        if uplink:
            speed = f" {uplink['speed']} Mbit/s" if uplink["speed"] and uplink["speed"] != "0" else ""
            print(f"    Uplink:  {uplink['name']} via {uplink['media']}{speed} ({uplink['local_iface']})")
        elif not meshed:
            print(f"    Uplink:  not paired")

        clients = get_connected_clients(d, devices_by_mesh_uid,
                                         {r.get("UID") for r in repeaters})
        non_rep_clients = [c for c in clients if not c["is_repeater"]]
        if non_rep_clients:
            print(f"    Clients: {len(non_rep_clients)} connected")
        print()


def cmd_topology(args):
    """Show full mesh topology tree."""
    sid = args.sid or login(args.host, args.user, args.password or "")
    devices = fetch_devices(args.host, sid)
    mesh = fetch_mesh(args.host, sid)
    mesh_nodes = parse_mesh_nodes(mesh)
    devices_by_mesh_uid = {d["mesh_UIDs"]: d for d in devices if d.get("mesh_UIDs")}
    devices_by_uid = {d["UID"]: d for d in devices if d.get("UID")}

    master = None
    for d in devices:
        if "ownentry" in (d.get("flags") or ""):
            master = d
            break
    if not master:
        master = devices_by_mesh_uid.get("1")

    repeaters = [d for d in devices if is_repeater(d, mesh_nodes)]
    repeater_uids = {d.get("UID") for d in repeaters}

    # Group repeaters by their uplink target
    repeaters_by_parent = {}
    for r in repeaters:
        uplink = get_uplink_info(r, devices_by_mesh_uid)
        if uplink:
            link_list = r.get("link_list", [])
            entries = link_list[0].get("entry", []) if link_list and isinstance(link_list[0], dict) else []
            parent_mesh_uid = next((e["remote_dev_mesh_uid"] for e in entries if e.get("is_uplink") == "1"), None)
            parent_dev = devices_by_mesh_uid.get(parent_mesh_uid) if parent_mesh_uid else None
            parent_key = parent_dev.get("UID") if parent_dev else "master"
        else:
            parent_key = "master"
        repeaters_by_parent.setdefault(parent_key, []).append(r)

    # Print tree
    master_name = (master.get("friendly_name") or master.get("name") or "Fritz!Box") if master else "Fritz!Box"
    master_ip = master.get("ip", "") if master else ""
    print(f"[*] {master_name}  (master)" + (f"  {master_ip}" if master_ip else ""))

    # Master's direct clients
    if master:
        clients = get_connected_clients(master, devices_by_mesh_uid, repeater_uids)
        non_rep = [c for c in clients if not c["is_repeater"]]
        if non_rep:
            print(f"    | {len(non_rep)} direct client(s)")

    def print_repeater(r, indent=1):
        prefix = "    " * indent
        name = r.get("friendly_name") or r.get("name") or "?"
        model = r.get("modelname") or ""
        online = r.get("active") == "1"
        meshed = is_meshed(r)
        uplink = get_uplink_info(r, devices_by_mesh_uid)

        status_char = "+" if online else "-"
        status_text = "online" if online else "offline"
        model_text = f"  ({model})" if model else ""

        uplink_text = ""
        if uplink:
            speed = f" {uplink['speed']}Mbps" if uplink["speed"] and uplink["speed"] != "0" else ""
            uplink_text = f" via {uplink['media']}{speed}"

        mesh_tag = " [meshed]" if meshed else " [NOT meshed]"
        print(f"{prefix}|-- [{status_char}] {name}{model_text}{mesh_tag}{uplink_text}")

        # Clients
        clients = get_connected_clients(r, devices_by_mesh_uid, repeater_uids)
        non_rep = [c for c in clients if not c["is_repeater"]]
        if non_rep:
            print(f"{prefix}    | {len(non_rep)} client(s)")

        # Child repeaters
        child_reps = repeaters_by_parent.get(r.get("UID"), [])
        for cr in child_reps:
            print_repeater(cr, indent + 1)

    # Top-level repeaters (connected to master)
    assigned = set()
    for reps in repeaters_by_parent.values():
        for r in reps:
            assigned.add(r.get("UID"))

    master_uid = master.get("UID") if master else None
    top_level = (repeaters_by_parent.get("master", []) +
                 (repeaters_by_parent.get(master_uid, []) if master_uid else []))
    unassigned = [r for r in repeaters if r.get("UID") not in assigned]
    for r in top_level + unassigned:
        print_repeater(r)

    # Count unaccounted devices
    accounted = set()
    if master:
        accounted.add(master.get("UID"))
    for r in repeaters:
        accounted.add(r.get("UID"))
        for c in get_connected_clients(r, devices_by_mesh_uid, repeater_uids):
            # Can't easily get UID from client; skip
            pass
    total = len(devices)
    print(f"\nTotal devices: {total}, Repeaters: {len(repeaters)}")


def cmd_clients(args):
    """Show which devices connect through each repeater."""
    sid = args.sid or login(args.host, args.user, args.password or "")
    devices = fetch_devices(args.host, sid)
    mesh = fetch_mesh(args.host, sid)
    mesh_nodes = parse_mesh_nodes(mesh)
    devices_by_mesh_uid = {d["mesh_UIDs"]: d for d in devices if d.get("mesh_UIDs")}

    repeaters = [d for d in devices if is_repeater(d, mesh_nodes)]
    repeater_uids = {d.get("UID") for d in repeaters}

    # Also show master's clients
    master = None
    for d in devices:
        if "ownentry" in (d.get("flags") or ""):
            master = d
            break

    nodes = [master] + repeaters if master else repeaters
    for node in nodes:
        if not node:
            continue
        name = node.get("friendly_name") or node.get("name") or "?"
        is_master = "ownentry" in (node.get("flags") or "")
        label = f"{name} (master)" if is_master else name

        clients = get_connected_clients(node, devices_by_mesh_uid, repeater_uids)
        non_rep = [c for c in clients if not c["is_repeater"]]
        rep_clients = [c for c in clients if c["is_repeater"]]

        if not non_rep and not rep_clients:
            continue

        print(f"\n{label}:")
        if rep_clients:
            for c in rep_clients:
                print(f"  [repeater] {c['name']}")
        for c in sorted(non_rep, key=lambda x: (not x["online"], x["name"])):
            status = "+" if c["online"] else "-"
            speed = f" {c['speed']}Mbps" if c.get("speed") and c["speed"] != "0" else ""
            print(f"  [{status}] {c['name']:<40} {c['ip']:<16} {c['media']}{speed}  ({c['interface']})")


def cmd_pair(args):
    """Initiate mesh pairing (WPS-based)."""
    sid = args.sid or login(args.host, args.user, args.password or "")
    print(f"SID: {sid}", file=sys.stderr)

    repeater_pw = args.repeater_password or args.password or ""

    # Start mesh coupling on master
    print("Starting mesh coupling on Fritz!Box...", file=sys.stderr)
    result = api_put(args.host, sid, "nexus", {"enhanced_trust_mode": "1"})
    print(f"  Result: {json.dumps(result)}", file=sys.stderr)

    # Trigger WPS on repeater
    if not args.master_only:
        if args.repeater_ip:
            print(f"Triggering WPS on repeater {args.repeater_ip}...", file=sys.stderr)
            try:
                result = tr064_call(
                    host=args.repeater_ip,
                    service=WLAN_SERVICE,
                    control_url=WLAN_CONTROL_URL,
                    action="X_AVM-DE_SetWPSConfig",
                    arguments={"NewX_AVM-DE_WPSMode": "pbc"},
                    username="",
                    password=repeater_pw,
                )
                print("  WPS triggered.", file=sys.stderr)
            except Exception as e:
                print(f"  Failed: {e}", file=sys.stderr)
                print("  Press the WPS button on the repeater manually.", file=sys.stderr)
        else:
            print("\nNo --repeater-ip given. Press the WPS/Connect button on the repeater.", file=sys.stderr)

    # Poll for completion
    if not args.no_poll:
        print(f"Polling for new peer (timeout: {args.timeout}s)...", file=sys.stderr)
        import time
        initial = api_get(args.host, sid, "nexus")
        initial_peers = set()
        peers_data = initial.get("peers", [])
        if isinstance(peers_data, list) and peers_data:
            for peer in peers_data[0].get("peer", []):
                if peer.get("peer_trusted") == "1" and peer.get("iam_trusted") == "1":
                    initial_peers.add(peer.get("UID", ""))

        start = time.time()
        while time.time() - start < args.timeout:
            time.sleep(5)
            elapsed = int(time.time() - start)
            try:
                current = api_get(args.host, sid, "nexus")
                current_peers = set()
                peers_data = current.get("peers", [])
                if isinstance(peers_data, list) and peers_data:
                    for peer in peers_data[0].get("peer", []):
                        if peer.get("peer_trusted") == "1" and peer.get("iam_trusted") == "1":
                            current_peers.add(peer.get("UID", ""))
                new = current_peers - initial_peers
                if new:
                    print(f"  [{elapsed}s] New peer(s): {new}", file=sys.stderr)
                    print("Pairing successful!", file=sys.stderr)
                    sys.exit(0)
                print(f"  [{elapsed}s] Waiting... ({len(current_peers)} peers)", file=sys.stderr)
            except Exception as e:
                print(f"  [{elapsed}s] Error: {e}", file=sys.stderr)

        print(f"Timed out after {args.timeout}s.", file=sys.stderr)
        sys.exit(1)


def cmd_info(args):
    """Show detailed raw info for a device."""
    sid = args.sid or login(args.host, args.user, args.password or "")
    devices = fetch_devices(args.host, sid)
    mesh = fetch_mesh(args.host, sid)
    mesh_nodes = parse_mesh_nodes(mesh)
    devices_by_mesh_uid = {d["mesh_UIDs"]: d for d in devices if d.get("mesh_UIDs")}

    query = args.device.lower()
    match = None
    for d in devices:
        name = (d.get("friendly_name") or d.get("name") or "").lower()
        ip = (d.get("ip") or "").lower()
        uid = (d.get("UID") or "").lower()
        mac = (d.get("mac") or "").lower()
        if query in (name, ip, uid, mac) or query in name:
            match = d
            break

    if not match:
        print(f"No device found matching '{args.device}'")
        sys.exit(1)

    name = match.get("friendly_name") or match.get("name") or "(unknown)"
    print(f"Device: {name}\n")

    # Basic info
    fields = [
        ("UID", "UID"), ("IP", "ip"), ("MAC", "mac"),
        ("Model", "modelname"), ("Hostname", "hostname"),
        ("Active", "active"), ("Online Since", "online_since"),
        ("Flags", "flags"), ("Type", "type"),
        ("Device Class", "device_class"), ("Manufacturer", "manu_name"),
    ]
    for label, key in fields:
        val = match.get(key, "")
        if val:
            if key == "manu_name":
                val = "AVM (Fritz!)" if val == "1" else ("Third-party" if val == "0" else val)
            if key == "online_since" and val != "0":
                from datetime import datetime
                try:
                    val = datetime.fromtimestamp(int(val)).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OSError):
                    pass
            print(f"  {label:<16} {val}")

    # Mesh info
    mesh_fields = [
        ("Mesh UIDs", "mesh_UIDs"), ("Nexuspeer UID", "nexuspeer_UID"),
        ("Parent UID", "parentuid"), ("WLAN UIDs", "wlan_UIDs"),
    ]
    has_mesh = any(match.get(k) for _, k in mesh_fields)
    if has_mesh:
        print(f"\nMesh:")
        for label, key in mesh_fields:
            val = match.get(key, "")
            if val:
                if key == "parentuid":
                    parent = next((d for d in devices if d.get("UID") == val), None)
                    if parent:
                        val = f"{val} ({parent.get('friendly_name') or parent.get('name', '?')})"
                print(f"  {label:<16} {val}")

    # Is repeater?
    rep = is_repeater(match, mesh_nodes)
    meshed = is_meshed(match)
    if rep:
        print(f"\n  ** This device is a REPEATER **")
        print(f"  Mesh status: {'meshed' if meshed else 'NOT meshed'}")

    # Uplink
    uplink = get_uplink_info(match, devices_by_mesh_uid)
    if uplink:
        speed = f" {uplink['speed']} Mbit/s" if uplink["speed"] and uplink["speed"] != "0" else ""
        print(f"\nUplink:")
        print(f"  Target:    {uplink['name']}")
        print(f"  Media:     {uplink['media']}{speed}")
        print(f"  Local:     {uplink['local_iface']}")
        print(f"  Remote:    {uplink['remote_iface']}")

    # Link list summary
    link_list = match.get("link_list", [])
    if isinstance(link_list, list) and link_list:
        entries = link_list[0].get("entry", []) if isinstance(link_list[0], dict) else []
        if entries:
            print(f"\nLink List ({len(entries)} entries):")
            for e in entries:
                direction = "UPLINK" if e.get("is_uplink") == "1" else "client"
                iface = e.get("local_interface_name", "?")
                media = e.get("media_type", "?")
                speed = e.get("speed", "0")
                remote_uid = e.get("remote_dev_mesh_uid", "?")
                remote_dev = devices_by_mesh_uid.get(remote_uid)
                remote_name = (remote_dev.get("friendly_name") or remote_dev.get("name", "?")) if remote_dev else f"mesh:{remote_uid}"
                speed_text = f" {speed}Mbps" if speed and speed != "0" else ""
                print(f"  [{direction:<6}] {iface:<14} {media:<10}{speed_text:<12} -> {remote_name}")

    # Mesh topology info
    mesh_uid = match.get("mesh_UIDs", "")
    if mesh_uid and mesh_uid in mesh_nodes:
        node = mesh_nodes[mesh_uid]
        print(f"\nMesh Topology Node:")
        print(f"  Name:      {node.get('name', '?')}")
        print(f"  Role:      {node.get('mesh_type', '?')}")
        print(f"  Model:     {node.get('model', '?')}")
        print(f"  Is Meshed: {node.get('is_meshed', '?')}")


def main():
    parser = argparse.ArgumentParser(
        description="Fritz!Box mesh topology manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Note: Re-pairing a repeater through a specific other repeater is not
possible via API. Mesh trust is always established with the master.
The WiFi uplink path is auto-selected or changed via the repeater's
own web UI (Home Network > Mesh > Mesh Settings).
""")
    parser.add_argument("--host", default="fritz.box", help="Fritz!Box hostname/IP")
    parser.add_argument("-u", "--user", default="", help="Username")
    parser.add_argument("-p", "--password", default=None, help="Password (prompted if omitted)")
    parser.add_argument("--sid", default=None, help="Reuse existing SID")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("list", help="List all repeaters")
    sub.add_parser("topology", help="Show mesh topology tree")
    sub.add_parser("clients", help="Show clients per repeater")

    pair_p = sub.add_parser("pair", help="Initiate mesh pairing")
    pair_p.add_argument("--repeater-ip", help="Repeater IP for remote WPS trigger")
    pair_p.add_argument("--repeater-password", help="Repeater password")
    pair_p.add_argument("--master-only", action="store_true", help="Only start coupling on master")
    pair_p.add_argument("--no-poll", action="store_true", help="Don't poll for completion")
    pair_p.add_argument("--timeout", type=int, default=120, help="Poll timeout (default: 120s)")

    info_p = sub.add_parser("info", help="Show device details")
    info_p.add_argument("device", help="Device name, IP, UID, or MAC")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "list": cmd_list,
        "topology": cmd_topology,
        "clients": cmd_clients,
        "pair": cmd_pair,
        "info": cmd_info,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()

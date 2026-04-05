#!/usr/bin/env python3
"""
Fritz!Box API client with PBKDF2 challenge-response authentication.

Usage:
    python fritzbox_api.py                          # fetch landevice data
    python fritzbox_api.py --endpoint landevice     # same
    python fritzbox_api.py --endpoint mesh          # fetch mesh data
    python fritzbox_api.py --host 192.168.178.1     # custom host
    python fritzbox_api.py --user admin --password X # explicit credentials
"""

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from getpass import getpass
from urllib.request import Request, urlopen
from urllib.parse import urlencode


def get_session_info(host: str) -> dict:
    """Get challenge and current SID from the Fritz!Box."""
    url = f"http://{host}/login_sid.lua?version=2"
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    si = data["sessionInfo"]
    return {
        "sid": si["sid"],
        "challenge": si["challenge"],
        "block_time": si.get("blockTime", 0),
        "users": [u["user"] for u in si.get("users", [])],
    }


def solve_challenge_v2(challenge: str, password: str) -> str:
    """Solve a PBKDF2 v2 challenge. Returns the response string."""
    parts = challenge.split("$")
    if parts[0] != "2":
        raise ValueError(f"Unsupported challenge version: {parts[0]}")

    iterations1 = int(parts[1])
    salt1 = bytes.fromhex(parts[2])
    iterations2 = int(parts[3])
    salt2 = bytes.fromhex(parts[4])

    # First PBKDF2 pass
    key1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt1, iterations1, dklen=32)
    # Second PBKDF2 pass
    key2 = hashlib.pbkdf2_hmac("sha256", key1, salt2, iterations2, dklen=32)

    return f"{salt2.hex()}${key2.hex()}"


def solve_challenge_v1(challenge: str, password: str) -> str:
    """Solve a legacy MD5 challenge (fallback for older firmware)."""
    response_str = f"{challenge}-{password}"
    # Fritz!Box uses UTF-16LE for MD5 challenge
    md5_hash = hashlib.md5(response_str.encode("utf-16-le")).hexdigest()
    return f"{challenge}-{md5_hash}"


def login(host: str, username: str, password: str) -> str:
    """Authenticate and return a valid SID."""
    info = get_session_info(host)

    if info["sid"] != "0000000000000000":
        return info["sid"]

    if info["block_time"] > 0:
        print(f"Login blocked for {info['block_time']} seconds. Wait and retry.", file=sys.stderr)
        sys.exit(1)

    challenge = info["challenge"]

    if "$" in challenge:
        response = solve_challenge_v2(challenge, password)
    else:
        response = solve_challenge_v1(challenge, password)

    # Submit login
    login_data = urlencode({
        "username": username,
        "response": response,
    }).encode()

    url = f"http://{host}/login_sid.lua?version=2"
    req = Request(url, data=login_data, headers={"Accept": "application/json"})
    with urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())

    sid = data["sessionInfo"]["sid"]
    if sid == "0000000000000000":
        block = data["sessionInfo"].get("blockTime", 0)
        print(f"Login failed. Block time: {block}s", file=sys.stderr)
        sys.exit(1)

    return sid


def api_get(host: str, sid: str, endpoint: str) -> dict:
    """GET from /api/v0/generic/<endpoint> with the given SID."""
    url = f"http://{host}/api/v0/generic/{endpoint}"
    req = Request(url, headers={
        "AUTHORIZATION": f"AVM-SID {sid}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description="Fritz!Box API client")
    parser.add_argument("--host", default="fritz.box", help="Fritz!Box hostname/IP (default: fritz.box)")
    parser.add_argument("--user", "-u", default="", help="Username (empty for default/single user)")
    parser.add_argument("--password", "-p", default=None, help="Password (prompted if not given)")
    parser.add_argument("--endpoint", "-e", default="landevice", help="API endpoint under /api/v0/generic/ (default: landevice)")
    parser.add_argument("--output", "-o", default=None, help="Output file (default: stdout)")
    parser.add_argument("--sid", default=None, help="Use existing SID instead of logging in")
    args = parser.parse_args()

    if args.sid:
        sid = args.sid
    else:
        password = args.password
        if password is None:
            password = getpass(f"Password for {args.host}: ")
        sid = login(args.host, args.user, password)
        print(f"SID: {sid}", file=sys.stderr)

    data = api_get(args.host, sid, args.endpoint)

    output = json.dumps(data, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()

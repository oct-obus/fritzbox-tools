"""
Fritz!Box authentication and HTTP helpers.

Supports PBKDF2 v2 challenge-response (FRITZ!OS 7.24+) and legacy MD5.
"""

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
    """Solve a PBKDF2 v2 challenge."""
    parts = challenge.split("$")
    if parts[0] != "2":
        raise ValueError(f"Unsupported challenge version: {parts[0]}")

    iterations1 = int(parts[1])
    salt1 = bytes.fromhex(parts[2])
    iterations2 = int(parts[3])
    salt2 = bytes.fromhex(parts[4])

    key1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt1, iterations1, dklen=32)
    key2 = hashlib.pbkdf2_hmac("sha256", key1, salt2, iterations2, dklen=32)
    return f"{salt2.hex()}${key2.hex()}"


def solve_challenge_v1(challenge: str, password: str) -> str:
    """Solve a legacy MD5 challenge (older firmware)."""
    response_str = f"{challenge}-{password}"
    md5_hash = hashlib.md5(response_str.encode("utf-16-le")).hexdigest()
    return f"{challenge}-{md5_hash}"


def login(host: str, username: str = "", password: str = "") -> str:
    """Authenticate and return a valid SID."""
    info = get_session_info(host)

    if info["sid"] != "0000000000000000":
        return info["sid"]

    if info["block_time"] > 0:
        print(f"Login blocked for {info['block_time']} seconds.", file=sys.stderr)
        sys.exit(1)

    if not password:
        password = getpass(f"Password for {host}: ")

    challenge = info["challenge"]
    response = (solve_challenge_v2 if "$" in challenge else solve_challenge_v1)(challenge, password)

    login_data = urlencode({"username": username, "response": response}).encode()
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
    """GET /api/v0/generic/<endpoint>."""
    url = f"http://{host}/api/v0/generic/{endpoint}"
    req = Request(url, headers={
        "AUTHORIZATION": f"AVM-SID {sid}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def api_put(host: str, sid: str, endpoint: str, data: dict) -> dict:
    """PUT /api/v0/generic/<endpoint>."""
    url = f"http://{host}/api/v0/generic/{endpoint}"
    body = json.dumps(data).encode()
    req = Request(url, data=body, method="PUT", headers={
        "AUTHORIZATION": f"AVM-SID {sid}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def tr064_call(host: str, service: str, control_url: str, action: str,
               arguments: dict | None = None, username: str = "", password: str = "",
               port: int = 49000) -> ET.Element:
    """Make a TR-064 SOAP call. Returns the parsed XML response body."""
    url = f"http://{host}:{port}{control_url}"

    args_xml = ""
    if arguments:
        args_xml = "".join(f"<{k}>{v}</{k}>" for k, v in arguments.items())

    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{service}">
      {args_xml}
    </u:{action}>
  </s:Body>
</s:Envelope>"""

    req = Request(url, data=soap_body.encode("utf-8"), method="POST", headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f'"{service}#{action}"',
    })

    # TR-064 uses HTTP Digest auth
    if username or password:
        import urllib.request
        auth_handler = urllib.request.HTTPDigestAuthHandler()
        auth_handler.add_password("HTTPS Access", url, username, password)
        opener = urllib.request.build_opener(auth_handler)
        with opener.open(req, timeout=10) as resp:
            return ET.fromstring(resp.read())
    else:
        with urlopen(req, timeout=10) as resp:
            return ET.fromstring(resp.read())

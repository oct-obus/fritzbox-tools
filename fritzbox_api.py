#!/usr/bin/env python3
"""
Fritz!Box API client. Fetches data from /api/v0/generic/ endpoints.

Usage:
    python fritzbox_api.py                          # fetch landevice data
    python fritzbox_api.py -e mesh                  # fetch mesh data
    python fritzbox_api.py --host 192.168.178.1     # custom host
    python fritzbox_api.py -u admin -p secret       # explicit credentials
    python fritzbox_api.py --sid abc123              # reuse existing SID
"""

import argparse
import json
import sys

from fritzbox_auth import login, api_get


def main():
    parser = argparse.ArgumentParser(description="Fritz!Box API client")
    parser.add_argument("--host", default="fritz.box", help="Fritz!Box hostname/IP")
    parser.add_argument("--user", "-u", default="", help="Username (empty for single-user setups)")
    parser.add_argument("--password", "-p", default=None, help="Password (prompted if omitted)")
    parser.add_argument("--endpoint", "-e", default="landevice", help="API endpoint under /api/v0/generic/")
    parser.add_argument("--output", "-o", default=None, help="Output file (default: stdout)")
    parser.add_argument("--sid", default=None, help="Reuse existing SID")
    args = parser.parse_args()

    if args.sid:
        sid = args.sid
    else:
        sid = login(args.host, args.user, args.password or "")
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

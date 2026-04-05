# fritzbox-tools

Standalone Python tools for interacting with the Fritz!Box router API.

## fritzbox_api.py

API client with PBKDF2 challenge-response authentication. No external dependencies.

### Usage

```bash
# Fetch LAN device list (prompted for password)
python3 fritzbox_api.py

# Explicit credentials
python3 fritzbox_api.py -u admin -p "password"

# Different endpoint
python3 fritzbox_api.py -e mesh

# Save to file
python3 fritzbox_api.py -o landevice.json

# Reuse existing SID
python3 fritzbox_api.py --sid ab0c7d67cc6f796c
```

### Auth flow

1. GET `/login_sid.lua?version=2` to get challenge
2. PBKDF2-SHA256 two-pass response generation
3. POST credentials to get SID
4. Use SID for API requests

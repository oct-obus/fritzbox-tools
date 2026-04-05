# fritzbox-tools

Standalone Python tools for interacting with the Fritz!Box router API. No external dependencies.

## Scripts

### fritzbox_api.py

Fetch data from any `/api/v0/generic/` endpoint.

```bash
python3 fritzbox_api.py                        # fetch landevice data
python3 fritzbox_api.py -e mesh                # fetch mesh topology
python3 fritzbox_api.py -e nexus               # fetch nexus/mesh peer info
python3 fritzbox_api.py -o devices.json        # save to file
python3 fritzbox_api.py --sid ab0c7d67cc6f796c # reuse existing session
```

### mesh_pair.py

Remotely initiate mesh pairing between Fritz!Box and repeaters without pressing physical WPS buttons.

```bash
# Start mesh coupling + trigger WPS on repeater
python3 mesh_pair.py -p "password" --repeater-ip 192.168.178.2

# Start coupling on Fritz!Box only (press WPS on repeater manually)
python3 mesh_pair.py -p "password" --master-only

# Check WPS status
python3 mesh_pair.py -p "password" --wps-info --repeater-ip 192.168.178.2
```

### fritzbox_auth.py

Shared auth module used by the other scripts. Provides:
- PBKDF2 v2 + MD5 v1 challenge-response authentication
- REST API helpers (GET, PUT)
- TR-064 SOAP client with HTTP Digest auth

## Auth flow

1. `GET /login_sid.lua?version=2` to get challenge
2. PBKDF2-SHA256 two-pass response generation
3. `POST` credentials to get SID
4. Use SID for API requests via `AUTHORIZATION: AVM-SID <sid>` header


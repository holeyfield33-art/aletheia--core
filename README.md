# aletheia-core

**TMRP — Trusted Machine-Readable Provenance**

Agent X-ray Watcher (Snapshot Engine) for monitoring code changes, running an AST-based Causal Filter, generating ECDSA-signed Sovereign Receipts, **quarantining malicious files** (Active Interlock), and **broadcasting node health** over UDP (Heartbeat).

## Quick Start

```bash
pip install watchdog ecdsa
python agent_xray_watcher.py .
```

Edit any `.py` file in the repo — the watcher prints the diff, trust mark, and a signed receipt in real time. Press **Ctrl+C** to stop.

## How It Works

1. **File monitoring** — `watchdog` watches the repo recursively (skipping `.git`).
2. **Diff computation** — On each modification a unified diff is generated against the cached version.
3. **AST Causal Filter** — For `.py` files the code is parsed and scanned for lateral-movement signatures:
   - Dangerous module imports (`socket`, `subprocess`, `shutil`, `ctypes`, `pickle`, …)
   - Dangerous function calls (`os.system`, `eval`, `exec`, `subprocess.Popen`, …)
   - Each violation includes **line number**, **issue description**, **severity** (`high` / `critical`), and **category**.
4. **Trust Mark** — `Green` (all clear) or `Red` (violations detected).
5. **Active Interlock** — When the filter returns Red, the file is immediately renamed to `<file>.locked` (quarantined) and a **QuarantineReceipt** is generated with violation details and timestamp.
6. **Sovereign Receipt** — A JSON-LD credential containing the diff hash, filter result, and structured `violation_log`, signed with ECDSA (SECP256k1).
7. **Heartbeat Broadcast** — A UDP server (default port `12345`, configurable via `ALETHEIA_BROADCAST_PORT` env var) responds to `ping` messages with a signed **HeartbeatReceipt** reporting node ID, security status, quarantine count, and uptime.

## Receipt Format

Receipts follow the [W3C Verifiable Credentials v2](https://www.w3.org/TR/vc-data-model-2.0/) `@context`. Key fields:

| Field | Description |
|---|---|
| `credentialSubject.diffHash` | SHA-256 of the unified diff |
| `credentialSubject.filterResult.pass` | `true` (Green) / `false` (Red) |
| `credentialSubject.filterResult.reason` | Human-readable summary |
| `credentialSubject.violation_log` | Structured array of violations (see below) |
| `Causal_Filter_Signature` | Hex-encoded ECDSA signature over `credentialSubject` |

### `violation_log` Entry Schema

```json
{
    "line": 8,
    "issue": "call to dangerous function 'os.system'",
    "severity": "critical",
    "category": "dangerous_call"
}
```

- **severity**: `high` (dangerous imports) or `critical` (dangerous function calls / builtins).
- **category**: `dangerous_import`, `dangerous_call`, `dangerous_builtin`, or `parse_error`.

See [sample_red_receipt.json](sample_red_receipt.json) for a complete Red receipt example.

### Quarantine Receipt

When the interlock activates, a `QuarantineReceipt` is generated with extra fields:

| Field | Description |
|---|---|
| `credentialSubject.quarantinedPath` | Path the file was renamed to (`.locked`) |
| `credentialSubject.quarantine.timestamp` | ISO 8601 UTC timestamp of quarantine |
| `credentialSubject.quarantine.action` | Always `"file_locked"` |
| `type` | `["SovereignReceipt", "QuarantineReceipt"]` |

### Heartbeat Receipt

Send a UDP `ping` to receive a signed heartbeat:

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'ping', ('127.0.0.1', 12345))
data, _ = s.recvfrom(4096)
print(json.dumps(json.loads(data), indent=2))
"
```

Fields: `nodeId`, `status`, `lastScan`, `health.quarantineCount`, `health.uptimeSeconds`.

## Verifying Signatures

The watcher prints its session public key on startup. Use `verify_receipt(data_dict, signature_hex)` to check any receipt:

```python
from agent_xray_watcher import verify_receipt
import json

with open("sample_red_receipt.json") as f:
    receipt = json.load(f)

ok = verify_receipt(receipt["credentialSubject"], receipt["Causal_Filter_Signature"])
print("Valid" if ok else "Invalid")
```

## Project Structure

```
agent_xray_watcher.py    # Watcher + Causal Filter + Signer
sample_red_receipt.json   # Example Red receipt for demos / audit trail
README.md
```

## License

See repository for license details.
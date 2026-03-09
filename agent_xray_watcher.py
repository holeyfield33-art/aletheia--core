#!/usr/bin/env python3
"""
Agent X-ray Watcher (Snapshot Engine)
--------------------------------------
Monitors aletheia-core repo for file changes, computes diffs,
runs an AST-based Causal Filter on Python files, and generates
Sovereign Receipts in JSON-LD format signed with ECDSA (SECP256k1).
"""

import os
import sys
import ast
import time
import hashlib
import hmac
import difflib
import json
import socket
import sqlite3
import threading
import uuid
from typing import cast
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Self-exclusion: the watcher script is excluded from Active Interlock
# quarantine because it legitimately uses socket/threading for heartbeat.
WATCHER_SCRIPT = os.path.basename(__file__)  # 'agent_xray_watcher.py'

# ---------------------------------------------------------------------------
# AST Causal Filter  (DeepSeek integration)
# ---------------------------------------------------------------------------
# Severity classification for violation types
_SEVERITY_MAP = {
    'import': 'high',
    'import_from': 'high',
    'dangerous_call': 'critical',
    'dangerous_builtin': 'critical',
}


def check_causal_filter(code_str):
    """
    Scan Python code for lateral movement indicators.

    Returns
    -------
    (passed, summary, violation_log)
        passed : bool
            True if no violations found, False otherwise.
        summary : str
            Human-readable summary ("OK" or description of violations).
        violation_log : list[dict]
            Structured list of violations, each with keys:
            ``line``, ``issue``, ``severity``, ``category``.
            Empty list when the code is clean.
    """
    # Define dangerous modules (imports)
    DANGEROUS_MODULES = {
        'socket', 'subprocess', 'shutil', 'ctypes', 'paramiko',
        'telnetlib', 'ftplib', 'smtplib', 'http.client', 'xmlrpc',
        'multiprocessing', 'threading',  # can be used for persistence
        'pickle', 'shelve',  # deserialization risks
        'pty', 'pexpect',  # pseudo-terminals
        'win32api', 'win32file',  # Windows API (if on Windows)
    }

    # Dangerous function calls (including attribute access like os.system)
    DANGEROUS_FUNCTIONS = {
        # Built-in
        'eval', 'exec', 'compile', '__import__',
        # os module
        'os.system', 'os.popen', 'os.execl', 'os.execle',
        'os.execlp', 'os.execv', 'os.execve', 'os.execvp', 'os.execvpe',
        'os.kill', 'os.killpg', 'os.chmod', 'os.chown', 'os.rename', 'os.remove',
        'os.unlink', 'os.rmdir', 'os.removedirs', 'os.mkdir', 'os.makedirs',
        # subprocess (already covered by import, but direct calls)
        'subprocess.Popen', 'subprocess.call', 'subprocess.run',
        # other modules
        'socket.socket', 'socket.create_connection',
        'shutil.copy', 'shutil.copy2', 'shutil.copytree', 'shutil.move',
        'shutil.rmtree',
        'ctypes.CDLL', 'ctypes.windll', 'ctypes.util.find_library',
    }

    violation_log = []  # structured output

    try:
        tree = ast.parse(code_str)
    except SyntaxError as e:
        return False, f"Syntax error: {e}", [{
            "line": 0, "issue": f"Syntax error: {e}",
            "severity": "critical", "category": "parse_error",
        }]

    for node in ast.walk(tree):
        # --- Dangerous imports ---
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name.split('.')[0]
                if mod_name in DANGEROUS_MODULES:
                    violation_log.append({
                        "line": node.lineno,
                        "issue": f"import of dangerous module '{mod_name}'",
                        "severity": _SEVERITY_MAP['import'],
                        "category": "dangerous_import",
                    })
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mod_name = node.module.split('.')[0]
                if mod_name in DANGEROUS_MODULES:
                    violation_log.append({
                        "line": node.lineno,
                        "issue": f"import from dangerous module '{mod_name}'",
                        "severity": _SEVERITY_MAP['import_from'],
                        "category": "dangerous_import",
                    })

        # --- Dangerous function calls ---
        if isinstance(node, ast.Call):
            func = node.func
            call_str = None
            if isinstance(func, ast.Name):
                call_str = func.id
            elif isinstance(func, ast.Attribute):
                parts = []
                curr = func
                while isinstance(curr, ast.Attribute):
                    parts.append(curr.attr)
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    parts.append(curr.id)
                else:
                    parts = []
                if parts:
                    call_str = '.'.join(reversed(parts))

            if call_str and call_str in DANGEROUS_FUNCTIONS:
                is_builtin = call_str in ('eval', 'exec', 'compile', '__import__')
                violation_log.append({
                    "line": node.lineno,
                    "issue": f"call to dangerous function '{call_str}'",
                    "severity": _SEVERITY_MAP[
                        'dangerous_builtin' if is_builtin else 'dangerous_call'
                    ],
                    "category": "dangerous_builtin" if is_builtin else "dangerous_call",
                })

    # Sort by line number for deterministic output
    violation_log.sort(key=lambda v: v["line"])

    if violation_log:
        details = "; ".join(
            f"line {v['line']}: {v['issue']}" for v in violation_log
        )
        return False, f"Violations found: {details}", violation_log
    return True, "OK", []


# ---------------------------------------------------------------------------
# Hardware-Bound Key Derivation
# ---------------------------------------------------------------------------
def get_hardware_id():
    """
    Retrieve a stable hardware identifier from the system.
    Tries multiple platform-specific sources.  Returns bytes or None.
    """
    # 1. Linux DMI product UUID
    if sys.platform.startswith("linux"):
        try:
            with open("/sys/class/dmi/id/product_uuid", "rb") as f:
                return f.read().strip()
        except (PermissionError, FileNotFoundError, OSError):
            pass

    # 2. MAC address via uuid.getnode (cross-platform)
    try:
        mac = uuid.getnode()  # 48-bit integer
        return mac.to_bytes(6, "big")
    except Exception:
        pass

    # 3. Windows WMI CSProduct UUID
    if sys.platform == "win32":
        try:
            import subprocess as _sp
            output = _sp.check_output(
                ["wmic", "csproduct", "get", "uuid"], text=True, timeout=5
            )
            lines = output.strip().split("\n")
            if len(lines) >= 2 and lines[1].strip():
                return lines[1].strip().encode("utf-8")
        except Exception:
            pass

    # 4. macOS IOPlatformUUID
    if sys.platform == "darwin":
        try:
            import subprocess as _sp
            output = _sp.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True, timeout=5,
            )
            for line in output.split("\n"):
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2].encode("utf-8")
        except Exception:
            pass

    # 5. FreeBSD /etc/hostid
    try:
        with open("/etc/hostid", "rb") as f:
            return f.read(16)
    except (FileNotFoundError, OSError):
        pass

    return None


def get_hardware_bound_signing_key():
    """
    Derive a persistent SECP256k1 signing key from a hardware fingerprint
    using HKDF (RFC 5869).  Falls back to an ephemeral random key if no
    hardware ID is available.
    """
    hardware_id = get_hardware_id()
    if hardware_id is None:
        print("[WARN] No hardware identifier found. Using ephemeral random key.")
        return SigningKey.generate(curve=SECP256k1)

    hash_algo = hashlib.sha256
    salt = b"Aletheia-HW-Salt-2026"
    info = b"TMRP signing key"

    # HKDF-Extract
    prk = hmac.new(salt, hardware_id, hash_algo).digest()

    # HKDF-Expand (need 32 bytes for SECP256k1)
    length = 32
    block_size = hash_algo().digest_size
    t = b""
    okm = b""
    for i in range(1, (length + block_size - 1) // block_size + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_algo).digest()
        okm += t
    derived_key = okm[:length]

    return SigningKey.from_string(derived_key, curve=SECP256k1)


# ---------------------------------------------------------------------------
# ECDSA Receipt Signer  (hardware-bound)
# ---------------------------------------------------------------------------
_signing_key: SigningKey = get_hardware_bound_signing_key()
_verifying_key = cast(VerifyingKey, _signing_key.get_verifying_key())
print(f"[Agent X-ray] Hardware-bound ECDSA public key: "
      f"{_verifying_key.to_string().hex()}")


def sign_receipt(data_dict):
    """
    Sign a dictionary (credentialSubject) with the session's SECP256k1 key.
    Returns hex signature.
    """
    data_json = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
    data_bytes = data_json.encode('utf-8')
    signature = _signing_key.sign(data_bytes)
    return signature.hex()


def verify_receipt(data_dict, signature_hex):
    """
    Optional verification function.
    Returns True if signature matches the data and session public key.
    """
    data_json = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
    data_bytes = data_json.encode('utf-8')
    sig_bytes = bytes.fromhex(signature_hex)
    try:
        return _verifying_key.verify(sig_bytes, data_bytes)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SQLite Audit Database
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.sqlite")


def init_db():
    """Create the receipts table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_path TEXT,
            status TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            violation_log JSON
        )
    """)
    conn.commit()
    conn.close()


def insert_receipt(file_path, status, receipt_data, violations=None):
    """
    Insert a receipt into the audit database with hash chaining.
    Each row's hash_chain is SHA-256(prev_hash + receipt_json), forming
    a tamper-evident chain.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = receipt_data.get(
        'validFrom',
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    receipt_json = json.dumps(receipt_data, ensure_ascii=False)
    violation_json = json.dumps(violations) if violations else None

    # Get the last hash_chain value
    c.execute("SELECT hash_chain FROM receipts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else ""

    # Compute new chain hash
    chain_hash = hashlib.sha256(
        (prev_hash + receipt_json).encode('utf-8')
    ).hexdigest()

    c.execute(
        "INSERT INTO receipts "
        "(timestamp, file_path, status, receipt_json, violation_log, hash_chain) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, file_path, status, receipt_json, violation_json, chain_hash),
    )
    conn.commit()
    conn.close()
    return chain_hash


def upgrade_db_add_hash_chain():
    """Add hash_chain column if missing, using a transaction and integrity checks."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("BEGIN")

        # Check if column exists
        c.execute("PRAGMA table_info(receipts)")
        columns = [col[1] for col in c.fetchall()]
        if 'hash_chain' not in columns:
            c.execute("ALTER TABLE receipts ADD COLUMN hash_chain TEXT")
            print("Added hash_chain column to receipts table.")

        # Get current max id and check for gaps/duplicates
        c.execute("SELECT COUNT(*), MAX(id) FROM receipts")
        count, max_id = c.fetchone()
        if max_id is not None:
            if count != max_id:
                print(
                    f"WARNING: Receipt table may have gaps or deletions "
                    f"(count={count}, max_id={max_id}). "
                    f"Chain continuity cannot be guaranteed for backfill."
                )
        else:
            # Empty table, nothing to backfill
            conn.commit()
            return

        # Backfill existing rows with a computed chain (only if hash_chain is NULL)
        c.execute(
            "SELECT id, receipt_json FROM receipts "
            "WHERE hash_chain IS NULL ORDER BY id ASC"
        )
        rows = c.fetchall()
        if rows:
            # Get previous hash from the last row that already has a chain
            c.execute(
                "SELECT hash_chain FROM receipts "
                "WHERE hash_chain IS NOT NULL ORDER BY id DESC LIMIT 1"
            )
            prev_row = c.fetchone()
            prev_hash = prev_row[0] if prev_row else ""

            for row_id, receipt_json in rows:
                chain_hash = hashlib.sha256(
                    (prev_hash + receipt_json).encode('utf-8')
                ).hexdigest()
                c.execute(
                    "UPDATE receipts SET hash_chain = ? WHERE id = ?",
                    (chain_hash, row_id),
                )
                prev_hash = chain_hash

            print(f"Backfilled {len(rows)} receipts with hash chain.")
        conn.commit()
        print("Hash chain upgrade completed successfully.")
    except Exception as e:
        conn.rollback()
        print(f"Error during upgrade: {e}")
        raise
    finally:
        conn.close()


def get_chain_tip() -> str:
    """Return the latest hash_chain value from the ledger, or 'genesis'."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hash_chain FROM receipts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else "genesis"


# ---------------------------------------------------------------------------
# Active Interlock (Kill-Switch)
# ---------------------------------------------------------------------------
# Running tally of quarantine events for heartbeat reporting
_quarantine_count = 0
_last_scan_time = time.time()


def quarantine_file(file_path, diff_hash, violation_log):
    """
    Quarantine a file flagged by the Causal Filter.

    Renames ``file_path`` to ``<file_path>.locked`` and generates a
    QuarantineReceipt extending the standard Sovereign Receipt schema.
    """
    global _quarantine_count
    locked_path = f"{file_path}.locked"
    try:
        os.rename(file_path, locked_path)
        print(f"\nINTERLOCK ACTIVATED: Quarantined {file_path} -> {locked_path}")
    except OSError as e:
        print(f"Interlock failed: {e}")
        return None

    _quarantine_count += 1

    credential_subject = {
        "filePath": file_path,
        "quarantinedPath": locked_path,
        "diffHash": diff_hash,
        "filterResult": {
            "pass": False,
            "reason": "; ".join(v["issue"] for v in violation_log),
        },
        "violation_log": violation_log,
        "quarantine": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": "file_locked",
        },
    }
    receipt_data = {
        "@context": "https://www.w3.org/ns/credentials/v2",
        "type": ["SovereignReceipt", "QuarantineReceipt"],
        "issuer": "Aletheia Sovereign Node",
        "credentialSubject": credential_subject,
        "TEE_Measurement_Hash": get_tee_measurement(),
        "Sandbox_Public_Key_Registry_Link": "https://example.com/registry",
        "Causal_Filter_Signature": "",
    }
    signature = sign_receipt(credential_subject)
    receipt_data["Causal_Filter_Signature"] = signature

    # Persist to audit DB and get the chain hash for forensic linking
    chain_hash = insert_receipt(file_path, "Red", receipt_data, violation_log)

    # Link the quarantined file to its ledger entry
    credential_subject["quarantine"]["hashChainId"] = chain_hash
    # Re-sign with the forensic link included
    signature = sign_receipt(credential_subject)
    receipt_data["Causal_Filter_Signature"] = signature

    print(f"\nQuarantine Notification: Linked to Ledger Entry {chain_hash}")
    print("\nGenerated Quarantine Receipt (JSON-LD):")
    print(json.dumps(receipt_data, indent=4))

    ok = verify_receipt(credential_subject, signature)
    print(f"Signature self-check: {'VALID' if ok else 'INVALID'}")

    return receipt_data


# ---------------------------------------------------------------------------
# TEE Measurement (placeholder for DeepSeek hardware hash)
# ---------------------------------------------------------------------------
def get_tee_measurement() -> str:
    """Return a SHA-256 hash of the hardware identifier for TEE measurement."""
    hw_id = get_hardware_id()
    seed = hw_id if hw_id is not None else uuid.uuid4().bytes
    return hashlib.sha256(seed).hexdigest()


# ---------------------------------------------------------------------------
# Signed Report Hash
# ---------------------------------------------------------------------------
def get_report_hash(report_path: str = 'signed_report.json') -> str:
    """Return the SHA-256 hash of the latest signed_report.json, or a fallback."""
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            report_data = f.read()
        return hashlib.sha256(report_data.encode()).hexdigest()
    return "no_report_generated"


# ---------------------------------------------------------------------------
# Receipt Broadcast (UDP Heartbeat)
# ---------------------------------------------------------------------------
# Persistent node ID for the lifetime of this process
_NODE_ID = str(uuid.uuid4())
_BROADCAST_PORT = int(os.environ.get("ALETHEIA_BROADCAST_PORT", "12345"))
_start_time = time.time()


def broadcast_heartbeat():
    """
    UDP server that responds to ``ping`` messages with a signed Heartbeat
    Receipt.  Runs as a daemon thread so other TMRP tools on the LAN can
    verify this node's security status.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", _BROADCAST_PORT))
    except OSError as e:
        print(f"[Heartbeat] Could not bind port {_BROADCAST_PORT}: {e}")
        return

    print(f"[Heartbeat] Ping listener on UDP :{_BROADCAST_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except OSError:
            break
        if data.decode(errors="replace").strip().lower() == "ping":
            chain_tip = get_chain_tip()
            report_hash = get_report_hash()
            credential_subject = {
                "nodeId": _NODE_ID,
                "status": "Secure",
                "lastScan": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "teeMeasurement": get_tee_measurement(),
                "chainTip": chain_tip,
                "reportHash": report_hash,
                "health": {
                    "quarantineCount": _quarantine_count,
                    "uptimeSeconds": round(time.time() - _start_time, 1),
                },
            }
            heartbeat = {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "type": ["HeartbeatReceipt"],
                "issuer": "Aletheia Sovereign Node",
                "credentialSubject": credential_subject,
                "Causal_Filter_Signature": sign_receipt(credential_subject),
            }
            sock.sendto(json.dumps(heartbeat).encode(), addr)
            print(f"[Heartbeat] Ping reply -> {addr[0]}:{addr[1]} "
                  f"(Chain Tip: {chain_tip[:10]}..., Report Hash: {report_hash[:10]}...)")


def send_heartbeat(broadcast_addr: tuple[str, int] = ('255.255.255.255', 12345)):
    """
    Actively broadcast a signed HeartbeatReceipt via UDP every 60 seconds.
    Runs as a daemon thread so other TMRP nodes on the LAN can passively
    monitor this node's health without sending pings.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tee_hash = get_tee_measurement()
        chain_tip = get_chain_tip()
        report_hash = get_report_hash()
        credential_subject = {
            "nodeId": _NODE_ID,
            "timestamp": timestamp,
            "teeMeasurement": tee_hash,
            "chainTip": chain_tip,
            "reportHash": report_hash,
            "status": "Secure",
            "health": {
                "quarantineCount": _quarantine_count,
                "uptimeSeconds": round(time.time() - _start_time, 1),
            },
        }
        signature = sign_receipt(credential_subject)
        heartbeat_data = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["HeartbeatReceipt"],
            "issuer": "Aletheia Sovereign Node",
            "credentialSubject": credential_subject,
            "Causal_Filter_Signature": signature,
        }
        try:
            sock.sendto(json.dumps(heartbeat_data).encode(), broadcast_addr)
            print(f"[Heartbeat] Broadcast: {timestamp} "
                  f"(TEE: {tee_hash[:10]}..., Chain Tip: {chain_tip[:10]}..., "
                  f"Report Hash: {report_hash[:10]}...)")
        except OSError as e:
            print(f"[Heartbeat] Broadcast failed: {e}")
        time.sleep(60)


# ---------------------------------------------------------------------------
# File-change cache
# ---------------------------------------------------------------------------
file_cache: dict[str, list[str]] = {}


def _safe_read_lines(path: str) -> list[str] | None:
    """Read file lines, returning None on binary / unreadable files."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            return fh.readlines()
    except (UnicodeDecodeError, PermissionError, OSError):
        return None


# ---------------------------------------------------------------------------
# Watchdog handler
# ---------------------------------------------------------------------------
class AgentXrayHandler(FileSystemEventHandler):
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        # Seed the cache with current file contents
        for root, _dirs, files in os.walk(self.repo_path):
            # Skip hidden dirs (e.g. .git)
            if os.path.basename(root).startswith("."):
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                lines = _safe_read_lines(fpath)
                if lines is not None:
                    file_cache[fpath] = lines

    # ---------- Events -------------------------------------------------------
    def on_modified(self, event):
        if event.is_directory:
            return
        file_path: str = str(event.src_path)

        # Ignore hidden paths (.git, etc.)
        if any(part.startswith(".") for part in file_path.split(os.sep)):
            return

        if not os.path.exists(file_path):
            return

        new_lines = _safe_read_lines(file_path)
        if new_lines is None:
            return  # Binary or unreadable

        old_lines = file_cache.get(file_path, [])
        diff = list(
            difflib.unified_diff(old_lines, new_lines, fromfile="before", tofile="after")
        )

        if not diff:
            return  # No effective change

        print("\n" + "=" * 60)
        print("--- File Modified ---")
        print(f"Path: {file_path}")
        print("Diff:")
        for line in diff:
            print(line.rstrip())

        if file_path.endswith(".py"):
            global _last_scan_time
            _last_scan_time = time.time()

            new_content = "".join(new_lines)
            filter_pass, reason, violation_log = check_causal_filter(new_content)
            status = "Green" if filter_pass else "Red"
            print(f"\nTMRP Trust Mark: {status}")
            print(f"Reason: {reason}")
            if violation_log:
                print(f"Violations ({len(violation_log)}):")
                for v in violation_log:
                    print(f"  [{v['severity'].upper()}] line {v['line']}: {v['issue']}")

            diff_str = "".join(diff)
            diff_hash = hashlib.sha256(diff_str.encode()).hexdigest()

            if not filter_pass:
                # Self-exclusion: skip quarantine for the watcher's own script
                if os.path.basename(file_path) == WATCHER_SCRIPT:
                    print(f"\nSelf-exclusion: Ignoring modifications to {file_path}")
                    file_cache[file_path] = new_lines
                else:
                    # --- Active Interlock: quarantine the file ---
                    quarantine_file(file_path, diff_hash, violation_log)
                    # Remove quarantined path from cache; the .locked file
                    # won't be monitored as a .py file.
                    file_cache.pop(file_path, None)
            else:
                # --- Standard Sovereign Receipt for clean code ---
                credential_subject = {
                    "filePath": file_path,
                    "diffHash": diff_hash,
                    "filterResult": {"pass": filter_pass, "reason": reason},
                    "violation_log": violation_log,
                }
                receipt_data = {
                    "@context": "https://www.w3.org/ns/credentials/v2",
                    "type": ["SovereignReceipt"],
                    "issuer": "Aletheia-Core Watcher",
                    "credentialSubject": credential_subject,
                    "TEE_Measurement_Hash": get_tee_measurement(),
                    "Sandbox_Public_Key_Registry_Link": "https://example.com/registry",
                    "Causal_Filter_Signature": "",
                }
                signature = sign_receipt(credential_subject)
                receipt_data["Causal_Filter_Signature"] = signature

                print("\nGenerated Sovereign Receipt (JSON-LD):")
                print(json.dumps(receipt_data, indent=4))

                ok = verify_receipt(credential_subject, signature)
                print(f"Signature self-check: {'VALID' if ok else 'INVALID'}")

                # Persist to audit DB
                insert_receipt(file_path, "Green", receipt_data)

                # Update the cache only for clean files
                file_cache[file_path] = new_lines
        else:
            print("\nNon-Python file: Skipping Causal Filter.")
            file_cache[file_path] = new_lines

        print("=" * 60)

    def on_created(self, event):
        if event.is_directory:
            return
        file_path: str = str(event.src_path)
        lines = _safe_read_lines(file_path)
        if lines is not None:
            file_cache[file_path] = lines
            print(f"\n[+] New file cached: {file_path}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        file_path: str = str(event.src_path)
        file_cache.pop(file_path, None)
        print(f"\n[-] File removed from cache: {file_path}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_watcher(repo_path: str = "."):
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        print(f"Error: '{repo_path}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    init_db()
    upgrade_db_add_hash_chain()
    print(f"[Audit] Database at {DB_PATH}")

    event_handler = AgentXrayHandler(repo_path)
    observer = Observer()
    observer.schedule(event_handler, repo_path, recursive=True)
    observer.start()

    # Start the UDP heartbeat ping listener in a daemon thread
    threading.Thread(target=broadcast_heartbeat, daemon=True).start()
    # Start the active heartbeat broadcast (every 60s) in a daemon thread
    threading.Thread(target=send_heartbeat, daemon=True).start()

    print(f"Agent X-ray Watcher active — monitoring {repo_path}")
    print(f"Node ID: {_NODE_ID}")
    print(f"Public key (hex): {_verifying_key.to_string().hex()}")
    print("Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nWatcher stopped.")
    observer.join()


if __name__ == "__main__":
    # Default: monitor current directory (the aletheia-core repo root)
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    run_watcher(target)

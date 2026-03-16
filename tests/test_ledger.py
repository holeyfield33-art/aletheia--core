"""Tests for SQLite hash chain integrity."""

import json
import hashlib
import sqlite3

from agent_xray_watcher import sign_receipt


def _make_receipt(file_path, passed):
    """Build a minimal W3C-style receipt and sign it."""
    credential_subject = {
        "filePath": file_path,
        "diffHash": hashlib.sha256(file_path.encode()).hexdigest(),
        "filterResult": {"pass": passed, "reason": "OK" if passed else "fail"},
    }
    signature = sign_receipt(credential_subject)
    return {
        "@context": "https://www.w3.org/ns/credentials/v2",
        "type": ["SovereignReceipt"],
        "issuer": "Aletheia-Core Watcher",
        "credentialSubject": credential_subject,
        "Causal_Filter_Signature": signature,
    }


def _init_db(db_path):
    """Create the receipts table in a temp database."""
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


def _insert_receipt(db_path, file_path, status, receipt_data):
    """Insert a receipt with hash chaining into the given database."""
    import time

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    receipt_json = json.dumps(receipt_data, ensure_ascii=False)

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
        (timestamp, file_path, status, receipt_json, None, chain_hash),
    )
    conn.commit()
    conn.close()
    return chain_hash


def _verify_chain(db_path):
    """Walk the chain and return (ok, rows_checked)."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "SELECT id, receipt_json, hash_chain FROM receipts ORDER BY id ASC"
    )
    rows = c.fetchall()
    conn.close()

    prev_hash = ""
    for rid, receipt_json, stored_hash in rows:
        computed = hashlib.sha256(
            (prev_hash + receipt_json).encode("utf-8")
        ).hexdigest()
        if computed != stored_hash:
            return False, rid
        prev_hash = stored_hash
    return True, len(rows)


class TestHashChain:
    """Hash chain must link receipts correctly."""

    def test_two_receipts_chain_links(self, tmp_path):
        db = str(tmp_path / "test_audit.sqlite")
        _init_db(db)

        r1 = _make_receipt("/test/a.py", True)
        r2 = _make_receipt("/test/b.py", True)

        h1 = _insert_receipt(db, "/test/a.py", "Green", r1)
        h2 = _insert_receipt(db, "/test/b.py", "Green", r2)

        # Second hash must depend on the first
        assert h1 != h2

        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 2

    def test_tampered_receipt_breaks_chain(self, tmp_path):
        db = str(tmp_path / "test_audit.sqlite")
        _init_db(db)

        r1 = _make_receipt("/test/a.py", True)
        r2 = _make_receipt("/test/b.py", True)
        _insert_receipt(db, "/test/a.py", "Green", r1)
        _insert_receipt(db, "/test/b.py", "Green", r2)

        # Tamper with the first receipt's JSON in place
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute(
            "UPDATE receipts SET receipt_json = ? WHERE id = 1",
            ('{"tampered": true}',),
        )
        conn.commit()
        conn.close()

        ok, failed_at = _verify_chain(db)
        assert ok is False
        assert failed_at == 1  # chain breaks at the tampered row

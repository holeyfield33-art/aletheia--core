"""Edge-case tests for the SQLite hash chain and DB operations."""

import json
import hashlib
import sqlite3
import time

from agent_xray_watcher import sign_receipt


def _make_receipt(file_path, passed, extra_fields=None):
    """Build a minimal W3C-style receipt and sign it."""
    credential_subject = {
        "filePath": file_path,
        "diffHash": hashlib.sha256(file_path.encode()).hexdigest(),
        "filterResult": {"pass": passed, "reason": "OK" if passed else "fail"},
    }
    if extra_fields:
        credential_subject.update(extra_fields)
    signature = sign_receipt(credential_subject)
    return {
        "@context": "https://www.w3.org/ns/credentials/v2",
        "type": ["SovereignReceipt"],
        "issuer": "Aletheia-Core Watcher",
        "credentialSubject": credential_subject,
        "Causal_Filter_Signature": signature,
    }


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


def _insert_receipt(db_path, file_path, status, receipt_data):
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


class TestHashChainEdgeCases:
    """Edge cases for hash chain integrity."""

    def test_single_receipt_chain(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        r = _make_receipt("/test/single.py", True)
        h = _insert_receipt(db, "/test/single.py", "Green", r)
        assert len(h) == 64  # SHA-256 hex
        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 1

    def test_many_receipts_chain(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        for i in range(20):
            r = _make_receipt(f"/test/file_{i}.py", i % 2 == 0)
            _insert_receipt(db, f"/test/file_{i}.py", "Green" if i % 2 == 0 else "Red", r)
        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 20

    def test_tamper_middle_receipt_breaks_chain(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        for i in range(5):
            r = _make_receipt(f"/test/{i}.py", True)
            _insert_receipt(db, f"/test/{i}.py", "Green", r)

        # Tamper with receipt #3 (middle)
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("UPDATE receipts SET receipt_json = '{\"tampered\": true}' WHERE id = 3")
        conn.commit()
        conn.close()

        ok, failed_at = _verify_chain(db)
        assert ok is False
        assert failed_at == 3

    def test_tamper_last_receipt_breaks_chain(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        for i in range(3):
            r = _make_receipt(f"/test/{i}.py", True)
            _insert_receipt(db, f"/test/{i}.py", "Green", r)

        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("UPDATE receipts SET receipt_json = '{\"tampered\": true}' WHERE id = 3")
        conn.commit()
        conn.close()

        ok, failed_at = _verify_chain(db)
        assert ok is False
        assert failed_at == 3

    def test_empty_db_verifies_ok(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 0

    def test_chain_hashes_are_unique(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        hashes = []
        for i in range(10):
            r = _make_receipt(f"/test/unique_{i}.py", True)
            h = _insert_receipt(db, f"/test/unique_{i}.py", "Green", r)
            hashes.append(h)
        # All chain hashes must be distinct
        assert len(set(hashes)) == len(hashes)

    def test_mixed_status_receipts_chain(self, tmp_path):
        """Green and Red receipts both chain correctly."""
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        r1 = _make_receipt("/test/clean.py", True)
        r2 = _make_receipt("/test/evil.py", False)
        r3 = _make_receipt("/test/clean2.py", True)
        _insert_receipt(db, "/test/clean.py", "Green", r1)
        _insert_receipt(db, "/test/evil.py", "Red", r2)
        _insert_receipt(db, "/test/clean2.py", "Green", r3)
        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 3

    def test_receipt_with_unicode_chains_correctly(self, tmp_path):
        db = str(tmp_path / "test.sqlite")
        _init_db(db)
        r = _make_receipt("/test/日本語.py", True, extra_fields={"msg": "éàü"})
        h = _insert_receipt(db, "/test/日本語.py", "Green", r)
        assert len(h) == 64
        ok, checked = _verify_chain(db)
        assert ok is True
        assert checked == 1

#!/usr/bin/env python3
"""
Verify the integrity of the TMRP audit ledger.
Checks:
1. Hash chain continuity.
2. ECDSA signature of each receipt (using the hardware-bound public key).
"""

import sqlite3
import json
import hashlib
import sys
from agent_xray_watcher import verify_receipt, DB_PATH


def extract_signature_and_data(receipt: dict) -> tuple[dict | None, str | None]:
    """
    Extract the signed credentialSubject and the signature hex from a receipt.

    Our receipt format stores the signature at the top level in
    ``Causal_Filter_Signature`` and signs the ``credentialSubject`` dict.

    Returns (credentialSubject_dict, signature_hex) or (None, None).
    """
    cs = receipt.get("credentialSubject")
    sig = receipt.get("Causal_Filter_Signature")
    if cs and sig:
        return cs, sig

    return None, None


def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, timestamp, file_path, status, receipt_json, hash_chain "
        "FROM receipts ORDER BY id ASC"
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("No receipts found in database.")
        return

    print(f"Verifying {len(rows)} receipts...\n")
    prev_hash = ""
    prev_id = 0
    all_good = True

    for rid, ts, fpath, status, receipt_json, stored_hash in rows:
        # --- Detect missing rows (ID gaps) ---
        if rid != prev_id + 1:
            print(f"  GAP DETECTED: expected ID {prev_id + 1}, got ID {rid} "
                  f"(receipts {prev_id + 1}–{rid - 1} missing)")
            all_good = False
        prev_id = rid

        receipt = json.loads(receipt_json)

        # --- Verify hash chain ---
        computed_hash = hashlib.sha256(
            (prev_hash + receipt_json).encode("utf-8")
        ).hexdigest()
        if computed_hash != stored_hash:
            print(f"  Hash MISMATCH at ID {rid}: "
                  f"stored {stored_hash}, computed {computed_hash}")
            all_good = False
        else:
            print(f"  Hash OK at ID {rid}")

        # --- Verify signature ---
        data, sig = extract_signature_and_data(receipt)
        if data is None or sig is None:
            print(f"    Could not extract signature from receipt {rid}")
            all_good = False
        else:
            if verify_receipt(data, sig):
                print(f"    Signature valid")
            else:
                print(f"    Signature INVALID at ID {rid}")
                all_good = False

        prev_hash = stored_hash if stored_hash else computed_hash

    print(f"\nChain Tip (last hash): {prev_hash}")
    print(f"Total receipts: {len(rows)}")
    if all_good:
        print("\nLedger integrity verified.")
    else:
        print("\nLedger integrity compromised.")
    sys.exit(0 if all_good else 1)


if __name__ == "__main__":
    main()

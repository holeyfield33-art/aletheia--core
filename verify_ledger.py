#!/usr/bin/env python3
"""
Verify the integrity of the TMRP audit ledger and generate a NIST-ready manifest.
"""

import sqlite3
import json
import hashlib
import sys
import time
from agent_xray_watcher import verify_receipt, _verifying_key, sign_receipt

DB_PATH = 'audit.sqlite'
MANIFEST_FILE = 'signed_report.json'


def extract_signature_and_data(receipt: dict) -> tuple[dict | None, str | None]:
    """Extract credentialSubject and signature from various receipt formats."""
    # Format 1: causalFilter wrapper
    if 'causalFilter' in receipt and 'signature' in receipt['causalFilter']:
        sig = receipt['causalFilter']['signature']
        data = receipt.get('credentialSubject', {})
        return data, sig

    # Format 2: signature inside credentialSubject
    cs = receipt.get('credentialSubject', {})
    if 'Causal_Filter_Signature' in cs:
        sig = cs['Causal_Filter_Signature']
        data = {k: v for k, v in cs.items() if k != 'Causal_Filter_Signature'}
        return data, sig
    if 'signature' in cs:
        sig = cs['signature']
        data = {k: v for k, v in cs.items() if k != 'signature'}
        return data, sig

    # Format 3: top-level Causal_Filter_Signature (our standard format)
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
        sys.exit(1)

    print(f"Verifying {len(rows)} receipts...\n")
    prev_hash = ""
    all_good = True
    verified_count = 0

    for row in rows:
        rid, ts, fpath, status, receipt_json, stored_hash = row
        receipt = json.loads(receipt_json)

        # Verify hash chain
        computed_hash = hashlib.sha256(
            (prev_hash + receipt_json).encode('utf-8')
        ).hexdigest()
        if computed_hash != stored_hash:
            print(f"  Hash mismatch at ID {rid}: "
                  f"stored {stored_hash}, computed {computed_hash}")
            all_good = False
        else:
            print(f"  Hash OK at ID {rid}")

        # Verify signature
        data, sig = extract_signature_and_data(receipt)
        if data is None or sig is None:
            print(f"    Could not extract signature from receipt {rid}")
            all_good = False
        else:
            if verify_receipt(data, sig):
                print(f"    Signature valid")
                verified_count += 1
            else:
                print(f"    Signature INVALID at ID {rid}")
                all_good = False

        prev_hash = stored_hash

    print("\n" + "=" * 50)
    if all_good:
        print(f"Ledger integrity verified. {verified_count} receipts checked.")
        # Generate NIST-ready manifest
        from typing import cast
        from ecdsa import VerifyingKey
        vk = cast(VerifyingKey, _verifying_key)
        manifest = {
            "chain_tip": prev_hash,
            "public_key": vk.to_string().hex(),
            "status": "Verified",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "entries_verified": verified_count,
        }
        signature = sign_receipt(manifest)
        manifest["signature"] = signature

        with open(MANIFEST_FILE, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"Signed manifest written to {MANIFEST_FILE}")
        sys.exit(0)
    else:
        print("Ledger integrity compromised. No manifest generated.")
        sys.exit(1)


if __name__ == "__main__":
    main()

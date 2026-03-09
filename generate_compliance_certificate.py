#!/usr/bin/env python3
"""
generate_compliance_certificate.py

Creates a tamper-evident compliance certificate package for NIST submission.
Steps:
1. Run verify_ledger.py to validate the audit ledger and generate signed_report.json.
2. Package signed_report.json with a verification README.
3. (Optional) Convert to PDF if pandoc is available.
"""

import subprocess
import sys
import os
import json
import time
import hashlib
import shutil

VERIFY_SCRIPT = "verify_ledger.py"
REPORT_FILE = "signed_report.json"
CERT_DIR_PREFIX = "compliance_certificate"


def run_verifier():
    """Execute verify_ledger.py and return success (bool) and output."""
    if not os.path.exists(VERIFY_SCRIPT):
        print(f"Error: {VERIFY_SCRIPT} not found in current directory.")
        return False, ""
    try:
        result = subprocess.run(
            [sys.executable, VERIFY_SCRIPT],
            capture_output=True, text=True, check=False,
        )
        print(result.stdout)
        if result.stderr:
            print("stderr:", result.stderr)
        return result.returncode == 0, result.stdout
    except Exception as e:
        print(f"Exception running verifier: {e}")
        return False, ""


def create_readme(cert_dir, public_key_hex, chain_tip, report_hash, timestamp):
    """Write verification instructions."""
    readme_content = f"""# Aletheia Sovereign Node -- Compliance Certificate

**Generated:** {timestamp}

This package contains the signed audit manifest (`signed_report.json`) from an
Aletheia-Core TMRP node. The manifest proves the integrity of the node's audit
ledger up to the point of generation.

## Package Contents

- `signed_report.json` -- Signed by the node's hardware-bound key.
- `README_VERIFICATION.md` -- This file.

## Verification Instructions (for Auditors)

### 1. Verify the Manifest Signature

The manifest is a JSON object with the following fields:

- `chain_tip` -- SHA-256 hash of the last receipt in the ledger.
- `public_key` -- Hexadecimal public key of the node.
- `status` -- Must be `"Verified"`.
- `timestamp` -- ISO 8601 timestamp.
- `entries_verified` -- Number of receipts checked.
- `signature` -- ECDSA signature (SECP256k1) over the preceding fields (sorted keys).

To verify the signature:

**Using Python + ecdsa:**

```python
import json, hashlib
from ecdsa import VerifyingKey, SECP256k1

with open('signed_report.json') as f:
    manifest = json.load(f)
sig = bytes.fromhex(manifest.pop('signature'))
# Reconstruct signed data (sorted keys, no whitespace)
data = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
vk = VerifyingKey.from_string(
    bytes.fromhex(manifest['public_key']), curve=SECP256k1
)
assert vk.verify(sig, data.encode()), "Signature invalid"
print("Signature OK")
```

**Using openssl (if key converted):**

Note: The public key is in raw uncompressed format (65 bytes, starting with 04).

### 2. Verify the Ledger Chain Tip

The `chain_tip` in the manifest should match the last entry in the node's audit
database. If you have access to the node, run:

```bash
sqlite3 audit.sqlite "SELECT hash_chain FROM receipts ORDER BY id DESC LIMIT 1;"
```

The output must equal the manifest's `chain_tip`.

### 3. Verify the Report Hash (Optional)

The node's heartbeat broadcasts include a `reportHash` field. If you captured a
heartbeat near the manifest time, confirm it matches the SHA-256 of this
`signed_report.json` file:

```bash
sha256sum signed_report.json
```

Expected hash: `{report_hash}`

## Audit Trail

The node's full audit database (`audit.sqlite`) contains every receipt since
inception, each linked by a cryptographic hash chain. This manifest attests that
at {timestamp}, the ledger was consistent and all signatures verified.

**Public Key:** `{public_key_hex}`

**Chain Tip:** `{chain_tip}`

For questions, contact Aletheia Sovereign Systems.
"""
    readme_path = os.path.join(cert_dir, "README_VERIFICATION.md")
    with open(readme_path, "w") as f:
        f.write(readme_content)
    print(f"Verification README written to {readme_path}")


def maybe_generate_pdf(cert_dir):
    """If pandoc is installed, convert README to PDF."""
    if shutil.which("pandoc") is None:
        print("pandoc not found -- skipping PDF generation. "
              "Install pandoc to generate PDF.")
        return
    readme_md = os.path.join(cert_dir, "README_VERIFICATION.md")
    pdf_path = os.path.join(cert_dir, "VERIFICATION_INSTRUCTIONS.pdf")
    try:
        subprocess.run(["pandoc", readme_md, "-o", pdf_path], check=True)
        print(f"PDF generated at {pdf_path}")
    except Exception as e:
        print(f"PDF generation failed: {e}")


def main():
    print("=== Aletheia Compliance Certificate Generator ===\n")
    success, output = run_verifier()
    if not success:
        print("\nLedger verification failed. Certificate cannot be generated.")
        sys.exit(1)

    # Check that signed_report.json exists
    if not os.path.exists(REPORT_FILE):
        print(f"Error: {REPORT_FILE} not found after verification.")
        sys.exit(1)

    # Load manifest to extract info
    with open(REPORT_FILE) as f:
        manifest = json.load(f)
    public_key = manifest.get("public_key", "unknown")
    chain_tip = manifest.get("chain_tip", "unknown")
    timestamp = manifest.get(
        "timestamp",
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    # Compute report hash
    with open(REPORT_FILE, "rb") as f:
        report_hash = hashlib.sha256(f.read()).hexdigest()

    # Create timestamped certificate directory
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    cert_dir = f"{CERT_DIR_PREFIX}_{timestamp_str}"
    os.makedirs(cert_dir, exist_ok=True)

    # Copy signed_report.json into directory
    dest_report = os.path.join(cert_dir, "signed_report.json")
    shutil.copy2(REPORT_FILE, dest_report)
    print(f"Copied {REPORT_FILE} to {dest_report}")

    # Generate README
    create_readme(cert_dir, public_key, chain_tip, report_hash, timestamp)

    # Try PDF conversion
    maybe_generate_pdf(cert_dir)

    print("\nCompliance certificate package created successfully.")
    print(f"Package location: {os.path.abspath(cert_dir)}")
    print("\nSubmit the entire directory to NIST auditors. "
          "The signed manifest is self-verifying.")


if __name__ == "__main__":
    main()

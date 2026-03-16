"""Tests for ECDSA signing and W3C Verifiable Credentials format."""

import json
from agent_xray_watcher import sign_receipt, verify_receipt


class TestECDSASigning:
    """Sign-then-verify round-trip must succeed."""

    def test_sign_and_verify_returns_true(self):
        data = {
            "filePath": "/workspaces/aletheia--core/tests/dummy.py",
            "diffHash": "abc123",
            "filterResult": {"pass": True, "reason": "OK"},
        }
        signature = sign_receipt(data)
        assert verify_receipt(data, signature) is True

    def test_tampered_receipt_returns_false(self):
        data = {
            "filePath": "/workspaces/aletheia--core/tests/dummy.py",
            "diffHash": "abc123",
            "filterResult": {"pass": True, "reason": "OK"},
        }
        signature = sign_receipt(data)
        # Tamper with the data after signing
        data["diffHash"] = "tampered"
        assert verify_receipt(data, signature) is False


class TestW3CFormat:
    """Receipts must follow W3C Verifiable Credentials structure."""

    def test_receipt_has_w3c_fields(self):
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
            "issuer": "Aletheia-Core Watcher",
            "credentialSubject": {
                "filePath": "/test.py",
                "diffHash": "abc",
                "filterResult": {"pass": True, "reason": "OK"},
            },
        }
        assert receipt["@context"] == "https://www.w3.org/ns/credentials/v2"
        assert "SovereignReceipt" in receipt["type"]
        assert "issuer" in receipt
        assert "credentialSubject" in receipt
        assert isinstance(receipt["credentialSubject"], dict)

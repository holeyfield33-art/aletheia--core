"""Edge-case tests for ECDSA signing, verification, and receipt format."""

import json
from agent_xray_watcher import sign_receipt, verify_receipt


class TestECDSASigningEdgeCases:
    """Edge cases for ECDSA sign/verify round-trip."""

    def test_empty_data_dict(self):
        data = {}
        sig = sign_receipt(data)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert verify_receipt(data, sig) is True

    def test_signing_deterministic(self):
        """Same data signed twice should verify both times (may differ due to k-randomness)."""
        data = {"a": 1, "b": 2}
        sig1 = sign_receipt(data)
        sig2 = sign_receipt(data)
        assert verify_receipt(data, sig1) is True
        assert verify_receipt(data, sig2) is True

    def test_different_data_different_signatures(self):
        d1 = {"key": "value1"}
        d2 = {"key": "value2"}
        s1 = sign_receipt(d1)
        s2 = sign_receipt(d2)
        # Different data → signatures should not both verify against other data
        assert verify_receipt(d1, s2) is False
        assert verify_receipt(d2, s1) is False

    def test_unicode_data_in_receipt(self):
        data = {"filePath": "/tmp/日本語.py", "msg": "éàü"}
        sig = sign_receipt(data)
        assert verify_receipt(data, sig) is True

    def test_nested_data_dict(self):
        data = {
            "outer": {"inner": {"deep": [1, 2, 3]}},
            "filterResult": {"pass": True, "reason": "OK"},
        }
        sig = sign_receipt(data)
        assert verify_receipt(data, sig) is True

    def test_large_data_dict(self):
        data = {f"key_{i}": f"value_{i}" for i in range(200)}
        sig = sign_receipt(data)
        assert verify_receipt(data, sig) is True

    def test_invalid_signature_hex_returns_false(self):
        data = {"filePath": "/test.py"}
        assert verify_receipt(data, "deadbeef") is False

    def test_empty_signature_returns_false(self):
        data = {"filePath": "/test.py"}
        assert verify_receipt(data, "") is False

    def test_non_hex_signature_returns_false(self):
        data = {"filePath": "/test.py"}
        assert verify_receipt(data, "not-a-hex-string!!") is False

    def test_signature_is_hex_string(self):
        data = {"test": True}
        sig = sign_receipt(data)
        # Must be valid hex
        int(sig, 16)
        assert len(sig) > 0

    def test_key_order_does_not_matter(self):
        """sign_receipt uses sort_keys=True, so order shouldn't matter."""
        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        sig = sign_receipt(d1)
        assert verify_receipt(d2, sig) is True


class TestW3CFormatEdgeCases:
    """W3C Verifiable Credentials structure validation edge cases."""

    def test_sovereign_receipt_type_list(self):
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
        }
        assert isinstance(receipt["type"], list)
        assert "SovereignReceipt" in receipt["type"]

    def test_quarantine_receipt_has_both_types(self):
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt", "QuarantineReceipt"],
        }
        assert "SovereignReceipt" in receipt["type"]
        assert "QuarantineReceipt" in receipt["type"]

    def test_heartbeat_receipt_type(self):
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["HeartbeatReceipt"],
        }
        assert "HeartbeatReceipt" in receipt["type"]

    def test_credential_subject_must_be_dict(self):
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
            "credentialSubject": {"filePath": "/x.py"},
        }
        assert isinstance(receipt["credentialSubject"], dict)

    def test_signed_receipt_round_trip(self):
        """Build a full receipt, sign it, and verify."""
        cs = {
            "filePath": "/test/round_trip.py",
            "diffHash": "abc",
            "filterResult": {"pass": True, "reason": "OK"},
            "violation_log": [],
        }
        sig = sign_receipt(cs)
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
            "issuer": "Aletheia-Core Watcher",
            "credentialSubject": cs,
            "Causal_Filter_Signature": sig,
        }
        assert verify_receipt(receipt["credentialSubject"], receipt["Causal_Filter_Signature"]) is True

    def test_receipt_json_serializable(self):
        cs = {"filePath": "/test.py", "diffHash": "x", "filterResult": {"pass": True, "reason": "OK"}}
        sig = sign_receipt(cs)
        receipt = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["SovereignReceipt"],
            "issuer": "Aletheia-Core Watcher",
            "credentialSubject": cs,
            "Causal_Filter_Signature": sig,
        }
        serialized = json.dumps(receipt)
        deserialized = json.loads(serialized)
        assert deserialized == receipt

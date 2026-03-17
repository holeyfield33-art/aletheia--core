"""Tests for the AST causal filter in agent_xray_watcher."""

from agent_xray_watcher import check_causal_filter


class TestCausalFilterCleanCode:
    """Clean Python code should pass the filter."""

    def test_clean_code_passes(self):
        code = (
            "def add(a, b):\n"
            "    return a + b\n"
            "\n"
            "result = add(2, 3)\n"
            "print(result)\n"
        )
        passed, summary, violations = check_causal_filter(code)
        assert passed is True
        assert summary == "OK"
        assert violations == []


class TestCausalFilterDangerousCalls:
    """Dangerous function calls must be flagged."""

    def test_os_system_fails_critical(self):
        code = "import os\nos.system('rm -rf /')\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        os_system_violations = [
            v for v in violations if "os.system" in v["issue"]
        ]
        assert len(os_system_violations) == 1
        assert os_system_violations[0]["severity"] == "critical"
        assert os_system_violations[0]["category"] == "dangerous_call"

    def test_eval_fails_critical(self):
        code = "x = eval('1+1')\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        eval_violations = [v for v in violations if "eval" in v["issue"]]
        assert len(eval_violations) == 1
        assert eval_violations[0]["severity"] == "critical"
        assert eval_violations[0]["category"] == "dangerous_builtin"


class TestCausalFilterDangerousImports:
    """Dangerous module imports must be flagged."""

    def test_import_socket_fails_high(self):
        code = "import socket\ns = socket.socket()\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        import_violations = [
            v for v in violations if v["category"] == "dangerous_import"
        ]
        assert len(import_violations) >= 1
        assert import_violations[0]["severity"] == "high"


class TestCausalFilterSyntaxError:
    """Unparseable code should return a parse_error."""

    def test_syntax_error_returns_parse_error(self):
        code = "def broken(\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        assert "Syntax error" in summary
        assert len(violations) == 1
        assert violations[0]["category"] == "parse_error"


class TestCausalFilterEdgeCases:
    """Edge cases for dotted imports and attribute calls."""

    def test_import_http_client_detected(self):
        code = "import http.client\n"
        passed, _summary, violations = check_causal_filter(code)
        assert passed is False
        assert any("http.client" in v["issue"] for v in violations)

    def test_from_http_client_detected(self):
        code = "from http.client import HTTPConnection\n"
        passed, _summary, violations = check_causal_filter(code)
        assert passed is False
        assert any("http.client" in v["issue"] for v in violations)

    def test_indirect_attribute_call_not_false_positive(self):
        code = (
            "class Wrapper:\n"
            "    def __init__(self, target):\n"
            "        self.target = target\n"
            "\n"
            "w = Wrapper(None)\n"
            "w.target.system('echo harmless in test')\n"
        )
        passed, _summary, violations = check_causal_filter(code)
        assert passed is True
        assert violations == []

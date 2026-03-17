"""Edge-case tests for the AST causal filter."""

from agent_xray_watcher import check_causal_filter


class TestCausalFilterEmptyAndTrivial:
    """Edge cases around empty / whitespace-only / comment-only code."""

    def test_empty_string_passes(self):
        passed, summary, violations = check_causal_filter("")
        assert passed is True
        assert summary == "OK"
        assert violations == []

    def test_whitespace_only_passes(self):
        passed, summary, violations = check_causal_filter("   \n\n  \t\n")
        assert passed is True
        assert summary == "OK"
        assert violations == []

    def test_comment_only_passes(self):
        code = "# This is just a comment\n# Nothing dangerous here\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is True

    def test_docstring_only_passes(self):
        code = '"""Module docstring."""\n'
        passed, summary, violations = check_causal_filter(code)
        assert passed is True


class TestCausalFilterMultipleViolations:
    """Multiple violations in the same file."""

    def test_import_and_call_both_flagged(self):
        code = "import subprocess\nsubprocess.call(['ls'])\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        categories = {v["category"] for v in violations}
        assert "dangerous_import" in categories
        assert "dangerous_call" in categories
        assert len(violations) >= 2

    def test_multiple_dangerous_imports(self):
        code = "import socket\nimport subprocess\nimport shutil\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        assert len(violations) == 3
        modules = {v["issue"] for v in violations}
        assert any("socket" in m for m in modules)
        assert any("subprocess" in m for m in modules)
        assert any("shutil" in m for m in modules)

    def test_multiple_dangerous_builtins(self):
        code = "eval('1')\nexec('pass')\ncompile('1', '<>', 'eval')\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        assert len(violations) == 3
        for v in violations:
            assert v["severity"] == "critical"
            assert v["category"] == "dangerous_builtin"

    def test_violations_sorted_by_line(self):
        code = "exec('a')\nimport socket\neval('b')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        lines = [v["line"] for v in violations]
        assert lines == sorted(lines)


class TestCausalFilterImportVariants:
    """Various import styles that should be flagged."""

    def test_from_import(self):
        code = "from subprocess import Popen\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        assert violations[0]["category"] == "dangerous_import"

    def test_from_import_star(self):
        code = "from socket import *\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_aliased_import(self):
        code = "import socket as s\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_submodule_import_flagged(self):
        code = "import subprocess.foo\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_dotted_submodule_import_flagged(self):
        """http.client is in DANGEROUS_MODULES and gets matched directly."""
        code = "import http.client\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_ctypes_import(self):
        code = "import ctypes\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        assert violations[0]["severity"] == "high"

    def test_pickle_import(self):
        code = "import pickle\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_paramiko_import(self):
        code = "import paramiko\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_safe_import_passes(self):
        code = "import json\nimport os\nimport sys\nimport hashlib\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is True
        assert violations == []


class TestCausalFilterDangerousCallVariants:
    """Various dangerous function call patterns."""

    def test_exec_flagged(self):
        code = "exec('print(1)')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        assert violations[0]["category"] == "dangerous_builtin"

    def test_compile_flagged(self):
        code = "compile('1+1', '<string>', 'eval')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        assert violations[0]["category"] == "dangerous_builtin"

    def test_dunder_import_flagged(self):
        code = "__import__('os')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        assert violations[0]["category"] == "dangerous_builtin"

    def test_os_popen(self):
        code = "import os\nos.popen('ls')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False
        call_violations = [v for v in violations if v["category"] == "dangerous_call"]
        assert any("os.popen" in v["issue"] for v in call_violations)

    def test_os_remove(self):
        code = "import os\nos.remove('/tmp/file')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_shutil_rmtree(self):
        code = "import shutil\nshutil.rmtree('/tmp/dir')\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_socket_create_connection(self):
        code = "import socket\nsocket.create_connection(('localhost', 80))\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is False

    def test_safe_function_call_passes(self):
        code = "x = len([1, 2, 3])\nprint(x)\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is True


class TestCausalFilterSyntaxEdgeCases:
    """Syntax error and parse edge cases."""

    def test_null_byte_in_code(self):
        code = "x = 1\x00\n"
        passed, summary, violations = check_causal_filter(code)
        # Should either parse error or pass — must not crash
        assert isinstance(passed, bool)
        assert isinstance(violations, list)

    def test_incomplete_function_def(self):
        code = "def foo(:\n"
        passed, summary, violations = check_causal_filter(code)
        assert passed is False
        assert "Syntax error" in summary

    def test_unicode_code_passes(self):
        code = "# 日本語コメント\nx = '你好'\nprint(x)\n"
        passed, _, violations = check_causal_filter(code)
        assert passed is True

    def test_very_long_clean_code(self):
        lines = [f"x_{i} = {i}\n" for i in range(500)]
        code = "".join(lines)
        passed, _, violations = check_causal_filter(code)
        assert passed is True
        assert violations == []

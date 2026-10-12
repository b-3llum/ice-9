"""Tests for the best-effort guarded Python executor."""

from __future__ import annotations

from ice_9.tools.python_exec import BLOCKED_PATTERNS, _normalise, execute_python


class TestNormalise:
    def test_strips_whitespace_and_lowercases(self):
        assert _normalise("os . System (") == "os.system("


class TestBenign:
    def test_runs_simple_code(self):
        r = execute_python("print(40 + 2)")
        assert r.success
        assert r.stdout.strip() == "42"

    def test_returncode_nonzero_on_error(self):
        r = execute_python("raise SystemExit(3)")
        assert r.returncode == 3


class TestBlocklist:
    def test_blocks_os_system(self):
        r = execute_python('import os; os.system("id")')
        assert r.returncode == 1
        assert "Blocked" in r.stderr

    def test_blocks_whitespace_evasion(self):
        r = execute_python('import os; os . system ("id")')
        assert r.returncode == 1

    def test_blocks_case_variant_popen(self):
        r = execute_python('import subprocess; subprocess.Popen(["ls"])')
        assert r.returncode == 1

    def test_blocks_double_quoted_etc_path(self):
        r = execute_python('open("/etc/passwd").read()')
        assert r.returncode == 1

    def test_blocks_single_quoted_etc_path(self):
        r = execute_python("open('/etc/shadow').read()")
        assert r.returncode == 1

    def test_blocks_dynamic_import(self):
        r = execute_python("__import__('os').getcwd()")
        assert r.returncode == 1

    def test_blocks_eval(self):
        r = execute_python('eval("1+1")')
        assert r.returncode == 1

    def test_patterns_have_no_internal_whitespace(self):
        # Patterns are matched against a whitespace-stripped copy, so they
        # must not themselves contain whitespace.
        for p in BLOCKED_PATTERNS:
            assert p == "".join(p.split())


class TestTimeout:
    def test_timeout_returns_124(self):
        r = execute_python("while True:\n    pass\n", timeout=1)
        assert r.returncode == 124
        assert "timed out" in r.stderr

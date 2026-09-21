"""Sandboxed Python code execution for the TARS agent.

Runs user/agent-generated Python in an isolated subprocess with
basic safety checks and timeout enforcement.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Patterns blocked from execution for safety
BLOCKED_PATTERNS: list[str] = [
    "os.system(",
    "subprocess.call(",
    "subprocess.run(",
    "subprocess.Popen(",
    "shutil.rmtree(",
    "os.remove(",
    "os.unlink(",
    "__import__('os')",
    "eval(",
    "exec(",
    "open('/etc",
    "open('/root",
    "open('/proc",
]


@dataclass
class PythonResult:
    """Result from a sandboxed Python execution."""

    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Combined stdout + stderr for convenient access."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(f"[stderr] {self.stderr.strip()}")
        return "\n".join(parts) if parts else "(no output)"


def execute_python(
    code: str,
    timeout: int = 30,
) -> PythonResult:
    """Execute Python code in a subprocess with restrictions.

    Args:
        code: Python source code to run.
        timeout: Maximum execution time in seconds.

    Returns:
        PythonResult with stdout, stderr, and return code.
    """
    # Basic safety: block dangerous patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern in code:
            return PythonResult(
                stdout="",
                stderr=f"Blocked: code contains disallowed pattern '{pattern}'",
                returncode=1,
            )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False,
    ) as f:
        f.write(code)
        script_path = f.name

    try:
        result = subprocess.run(
            ["python3", script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tempfile.gettempdir(),
        )
        return PythonResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return PythonResult(
            stdout="",
            stderr=f"Execution timed out after {timeout}s",
            returncode=124,
        )
    except FileNotFoundError:
        return PythonResult(
            stdout="",
            stderr="python3 binary not found",
            returncode=127,
        )
    finally:
        Path(script_path).unlink(missing_ok=True)

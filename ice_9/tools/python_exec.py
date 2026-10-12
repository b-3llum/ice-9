"""Best-effort guarded Python execution for the TARS agent.

Runs agent-generated Python in a separate subprocess with a timeout and a
working directory under the system temp dir. A substring *blocklist* screens
out the most obvious destructive calls before execution.

SECURITY NOTE: the blocklist is a speed bump, NOT a security boundary. A
determined caller can bypass any substring check (string concatenation,
``getattr``, attribute walks, alternate imports). Do not run untrusted,
adversarial code here and rely on this screen to contain it — real
containment needs OS-level isolation (a locked-down container, seccomp, or a
tool such as nsjail/firejail). The screen exists to catch accidental
foot-guns in agent-written code, not to sandbox an attacker.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Obvious destructive / escape patterns screened before execution. Matching is
# whitespace-insensitive (see _normalise), so "os.system (" and "os . system("
# are caught too. These are written without internal whitespace. This list is a
# best-effort foot-gun screen, not an exhaustive sandbox (see the module docstring).
BLOCKED_PATTERNS: list[str] = [
    # Shelling out
    "os.system(",
    "os.popen(",
    "subprocess.call(",
    "subprocess.run(",
    "subprocess.popen(",       # matches subprocess.Popen( after lowercasing
    "subprocess.check_output(",
    "subprocess.check_call(",
    "pty.spawn(",
    # Destructive filesystem ops
    "shutil.rmtree(",
    "os.remove(",
    "os.unlink(",
    "os.rmdir(",
    "os.removedirs(",
    # Dynamic code execution / import escapes
    "eval(",
    "exec(",
    "compile(",
    "__import__(",
    "importlib.import_module(",
    # Reading sensitive host paths (both quote styles)
    "open('/etc",
    'open("/etc',
    "open('/root",
    'open("/root',
    "open('/proc",
    'open("/proc',
    "open('/sys",
    'open("/sys',
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


def _normalise(code: str) -> str:
    """Collapse whitespace and lowercase for blocklist matching.

    Removes every whitespace character so ``os.system (`` and ``os . system(``
    reduce to the same token as ``os.system(``, and lowercases so ``Popen``
    matches ``popen``. Used only for screening — the original source is what
    actually runs.
    """
    return "".join(code.split()).lower()


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
    # Best-effort screen: reject the most obvious destructive patterns.
    # Matched against a whitespace-stripped, lowercased copy so trivial spacing
    # or case tricks don't slip past. This is NOT a security boundary.
    normalised = _normalise(code)
    for pattern in BLOCKED_PATTERNS:
        if pattern in normalised:
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

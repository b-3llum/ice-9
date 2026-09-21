"""Execution backend — run tool commands locally or over SSH.

The SSH backend lets a campaign run its tools on a remote host you control
(e.g. an AWS EC2 attack box), so scans originate from that instance's IP and
use the tooling installed there. It is a thin wrapper: a tool's command is
transformed into an `ssh user@host '<command>'` invocation, and the normal
streaming/subprocess machinery in ToolWrapper.run() is otherwise unchanged.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass

# Standard non-interactive SSH options (also used by tools/remote.py).
_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]


@dataclass
class ExecutionBackend:
    """How and where tool commands are executed."""

    backend: str = "local"  # "local" | "ssh"
    host: str = ""
    user: str = "root"
    port: int = 22
    key_file: str | None = None

    @property
    def is_remote(self) -> bool:
        return self.backend == "ssh" and bool(self.host)

    def wrap(self, cmd: list[str]) -> list[str]:
        """Return the argv to actually spawn for a tool command.

        Local: the command unchanged. Remote: an ssh invocation that runs the
        command on the configured host, letting the remote PATH resolve the
        binary (so any locally-resolved absolute path in cmd[0] is dropped).
        """
        if not self.is_remote:
            return cmd
        remote_cmd = shlex.join([os.path.basename(cmd[0]), *cmd[1:]])
        ssh = ["ssh", *_SSH_OPTS]
        if self.key_file:
            ssh += ["-i", os.path.expanduser(self.key_file)]
        if self.port and self.port != 22:
            ssh += ["-p", str(self.port)]
        ssh += [f"{self.user}@{self.host}", remote_cmd]
        return ssh

    def describe(self) -> str:
        return f"ssh {self.user}@{self.host}" if self.is_remote else "local"


_backend = ExecutionBackend()


def set_backend(backend: ExecutionBackend) -> None:
    """Set the process-wide execution backend (called once at startup)."""
    global _backend
    _backend = backend


def get_backend() -> ExecutionBackend:
    return _backend

"""Execute tools on remote machines via SSH."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class RemoteHost:
    """SSH connection parameters for a remote machine."""

    hostname: str
    user: str = "root"
    port: int = 22
    key_file: str | None = None


@dataclass
class RemoteResult:
    """Result from a remote command execution."""

    stdout: str
    stderr: str
    returncode: int
    host: str

    @property
    def success(self) -> bool:
        return self.returncode == 0


def remote_exec(
    host: RemoteHost,
    command: str,
    timeout: int = 120,
) -> RemoteResult:
    """Execute a command on a remote host via SSH.

    Args:
        host: Target host connection info.
        command: Shell command to run on the remote host.
        timeout: Maximum execution time in seconds.

    Returns:
        RemoteResult with stdout, stderr, return code, and hostname.
    """
    ssh_cmd: list[str] = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
    ]

    if host.key_file:
        ssh_cmd.extend(["-i", host.key_file])
    if host.port != 22:
        ssh_cmd.extend(["-p", str(host.port)])

    ssh_cmd.append(f"{host.user}@{host.hostname}")
    ssh_cmd.append(command)

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return RemoteResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            host=host.hostname,
        )
    except subprocess.TimeoutExpired:
        return RemoteResult(
            stdout="",
            stderr=f"SSH command timed out after {timeout}s",
            returncode=124,
            host=host.hostname,
        )
    except FileNotFoundError:
        return RemoteResult(
            stdout="",
            stderr="ssh binary not found",
            returncode=127,
            host=host.hostname,
        )


def remote_exec_multi(
    hosts: list[RemoteHost],
    command: str,
    timeout: int = 120,
) -> list[RemoteResult]:
    """Execute the same command on multiple hosts sequentially."""
    return [remote_exec(host, command, timeout) for host in hosts]

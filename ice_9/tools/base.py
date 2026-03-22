"""Abstract base class for tool wrappers."""

from __future__ import annotations

import subprocess
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool: str
    target: str
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    started_at: datetime
    completed_at: datetime
    parsed: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.return_code == 0

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()


class ToolWrapper(ABC):
    """Base class for all tool integrations."""

    name: str = "unknown"
    description: str = ""
    binary: str = ""  # CLI binary name
    att_ck_ids: list[str] = []  # Default ATT&CK techniques this tool maps to

    def __init__(self) -> None:
        self._binary_path: Optional[str] = None

    def is_available(self) -> bool:
        """Check if the tool binary is installed and accessible."""
        return shutil.which(self.binary) is not None

    def get_binary_path(self) -> str:
        """Get the full path to the tool binary."""
        if not self._binary_path:
            self._binary_path = shutil.which(self.binary) or self.binary
        return self._binary_path

    @abstractmethod
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build the command-line arguments for execution."""
        ...

    @abstractmethod
    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse tool output into structured data."""
        ...

    def run(
        self,
        target: str,
        timeout: int = 300,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute the tool and return structured results."""
        from ice_9.core.events import event_bus, Event, EventType

        cmd = self.build_command(target, **kwargs)
        started = datetime.utcnow()

        event_bus.emit(Event(
            type=EventType.TOOL_START,
            data={"tool": self.name, "target": target, "command": " ".join(cmd)},
        ))

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

            stdout_lines: list[str] = []
            batch: list[str] = []

            for line in proc.stdout:
                stdout_lines.append(line)
                batch.append(line.rstrip())
                if len(batch) >= 5:
                    event_bus.emit(Event(
                        type=EventType.TOOL_OUTPUT,
                        data={"tool": self.name, "target": target, "lines": batch, "total_lines": len(stdout_lines)},
                    ))
                    batch = []

            if batch:
                event_bus.emit(Event(
                    type=EventType.TOOL_OUTPUT,
                    data={"tool": self.name, "target": target, "lines": batch, "total_lines": len(stdout_lines)},
                ))

            stderr_output = proc.stderr.read()
            proc.wait(timeout=timeout)
            completed = datetime.utcnow()

            result = ToolResult(
                tool=self.name,
                target=target,
                command=cmd,
                return_code=proc.returncode,
                stdout="".join(stdout_lines),
                stderr=stderr_output,
                started_at=started,
                completed_at=completed,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            completed = datetime.utcnow()
            result = ToolResult(
                tool=self.name,
                target=target,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                started_at=started,
                completed_at=completed,
            )
        except FileNotFoundError:
            completed = datetime.utcnow()
            result = ToolResult(
                tool=self.name,
                target=target,
                command=cmd,
                return_code=-2,
                stdout="",
                stderr=f"Binary not found: {self.binary}",
                started_at=started,
                completed_at=completed,
            )

        # Parse output if successful
        if result.success:
            result.parsed = self.parse_output(result)

        event_bus.emit(Event(
            type=EventType.TOOL_COMPLETE if result.success else EventType.TOOL_ERROR,
            data={
                "tool": self.name,
                "target": target,
                "success": result.success,
                "duration": result.duration_seconds,
                "return_code": result.return_code,
            },
        ))

        return result

    def get_info(self) -> dict[str, Any]:
        """Get tool metadata."""
        resolved = shutil.which(self.binary)
        return {
            "name": self.name,
            "description": self.description,
            "binary": self.binary,
            "available": resolved is not None,
            "binary_path": resolved,
            "att_ck_ids": self.att_ck_ids,
        }

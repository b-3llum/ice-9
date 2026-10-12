"""CrackMapExec / NetExec network authentication testing wrapper."""

from __future__ import annotations

from typing import Any

from ice_9.tools.base import (
    ToolResult,
    ToolWrapper,
    resolve_binary,
    validate_arg_list,
    validate_target,
)

# Protocols supported by NetExec / CrackMapExec (the first positional arg).
_VALID_PROTOCOLS = frozenset({
    "smb", "winrm", "ldap", "ssh", "ftp", "mssql", "rdp", "vnc", "wmi", "nfs",
})
# Remote execution methods accepted by --exec-method.
_VALID_EXEC_METHODS = frozenset({"smbexec", "wmiexec", "atexec", "mmcexec"})


class CrackMapExecWrapper(ToolWrapper):
    """CrackMapExec/NetExec — SMB/WinRM/LDAP/SSH authentication testing."""

    name = "crackmapexec"
    description = "Network auth testing — credential spraying, share enumeration, command execution"
    binary = "nxc"  # NetExec (successor to CrackMapExec)
    att_ck_ids = [
        "T1110",      # Brute Force
        "T1110.003",  # Password Spraying
        "T1021.002",  # Remote Services: SMB
        "T1135",      # Network Share Discovery
    ]

    def __init__(self) -> None:
        super().__init__()
        # Fall back to crackmapexec if nxc not available
        if not resolve_binary("nxc"):
            self.binary = "crackmapexec"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build CrackMapExec command."""
        cmd = [self.get_binary_path()]

        # Protocol (first positional). Validated against the known set so a
        # stray or flag-like value can't slip into argv as the protocol.
        protocol = kwargs.get("protocol", "smb")
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(
                f"Unknown protocol: {protocol!r} — "
                f"valid protocols: {', '.join(sorted(_VALID_PROTOCOLS))}"
            )
        cmd.append(protocol)

        # Target (positional) — reject flag-like values so a '-'-prefixed
        # value can't be parsed by nxc as an option instead of the target.
        cmd.append(validate_target(target))

        # Authentication
        username = kwargs.get("username")
        password = kwargs.get("password")
        nt_hash = kwargs.get("nt_hash")
        userfile = kwargs.get("userfile")
        passfile = kwargs.get("passfile")

        if username:
            cmd.extend(["-u", username])
        elif userfile:
            cmd.extend(["-u", userfile])

        if password:
            cmd.extend(["-p", password])
        elif passfile:
            cmd.extend(["-p", passfile])
        elif nt_hash:
            cmd.extend(["-H", nt_hash])

        # Domain
        domain = kwargs.get("domain")
        if domain:
            cmd.extend(["-d", domain])

        # Actions
        action = kwargs.get("action")
        if action == "shares":
            cmd.append("--shares")
        elif action == "users":
            cmd.append("--users")
        elif action == "groups":
            cmd.append("--groups")
        elif action == "sessions":
            cmd.append("--sessions")
        elif action == "loggedon":
            cmd.append("--loggedon-users")
        elif action == "pass-pol":
            cmd.append("--pass-pol")
        elif action == "rid-brute":
            cmd.append("--rid-brute")
        elif action == "sam":
            cmd.append("--sam")
        elif action == "lsa":
            cmd.append("--lsa")
        elif action == "exec":
            exec_cmd = kwargs.get("exec_command", "whoami")
            exec_method = kwargs.get("exec_method", "smbexec")
            if exec_method not in _VALID_EXEC_METHODS:
                raise ValueError(
                    f"Unknown exec_method: {exec_method!r} — "
                    f"valid methods: {', '.join(sorted(_VALID_EXEC_METHODS))}"
                )
            cmd.extend(["-x", exec_cmd, "--exec-method", exec_method])

        # Spider
        spider = kwargs.get("spider")
        if spider:
            cmd.extend(["--spider", spider])
            depth = kwargs.get("spider_depth", 3)
            cmd.extend(["--spider-depth", str(depth)])

        # Extra args
        cmd.extend(validate_arg_list(kwargs.get("args"), "args"))

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse CrackMapExec / NetExec output.

        Produces a per-host ``hosts`` list — what the phase analyzers consume
        (``ip``/``protocol``/``os``/``signing``/``pwned``/``admin``/``shares``,
        each share ``{name, readable, writable}``) — plus the flat aggregates
        kept for backward compatibility. nxc/CME print one line per host as
        ``PROTO  IP  PORT  NAME  <message>``; hosts are keyed by IP.
        """
        lines = result.stdout.strip().splitlines()

        hosts: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        shares: list[dict[str, str]] = []
        credentials: list[dict[str, Any]] = []
        exec_results: list[str] = []

        def _host(ip: str) -> dict[str, Any]:
            if ip not in hosts:
                hosts[ip] = {
                    "ip": ip, "protocol": None, "os": None, "signing": None,
                    "pwned": False, "admin": False, "shares": [],
                }
                order.append(ip)
            return hosts[ip]

        for raw in lines:
            line = raw.rstrip()
            stripped = line.strip()
            parts = stripped.split()

            # --- Flat aggregates (kept for backward compatibility) ---
            if "[+]" in line or "[-]" in line or "[*]" in line:
                if "Pwn3d!" in line:
                    credentials.append({"line": stripped, "admin": True})
                elif "[+]" in line:
                    credentials.append({"line": stripped, "admin": False})
            if ("READ" in line or "WRITE" in line) and len(parts) >= 3:
                shares.append({
                    "name": parts[0] if not parts[0].startswith("[") else parts[-3],
                    "permissions": stripped,
                })
            if stripped and not any(m in line for m in ("[+]", "[-]", "[*]", "SMB")):
                exec_results.append(stripped)

            # --- Structured per-host parse: PROTO IP PORT NAME <message...> ---
            if (
                len(parts) < 4
                or parts[0].lower() not in _VALID_PROTOCOLS
                or not parts[2].isdigit()
            ):
                continue

            ip = parts[1]
            msg = " ".join(parts[4:])
            msg_low = msg.lower()
            host = _host(ip)
            if host["protocol"] is None:
                host["protocol"] = parts[0].upper()

            # Host banner line carries the OS string and SMB signing status.
            if "(signing:" in msg_low:
                host["signing"] = "(signing:true)" in msg_low
            if msg.startswith("[*]") and ("(name:" in msg_low or "(domain:" in msg_low):
                os_text = msg[3:].strip()
                cut = os_text.find(" (")
                host["os"] = os_text[:cut].strip() if cut != -1 else os_text

            # Admin / command-execution capability.
            if "Pwn3d!" in msg:
                host["pwned"] = True
                host["admin"] = True

            # Share-enumeration rows: "<ShareName>  <PERMS>  [remark]".
            if (
                not msg.startswith(("[*]", "[+]", "[-]"))
                and parts[4:]
                and parts[4] not in ("Share", "-----")
                and ("READ" in msg or "WRITE" in msg)
            ):
                host["shares"].append({
                    "name": parts[4],
                    "readable": "READ" in msg,
                    "writable": "WRITE" in msg,
                })

        return {
            "hosts": [hosts[ip] for ip in order],
            "credentials": credentials,
            "admin_access": [c for c in credentials if c.get("admin")],
            "shares": shares,
            "exec_results": exec_results,
            "raw_lines": len(lines),
        }

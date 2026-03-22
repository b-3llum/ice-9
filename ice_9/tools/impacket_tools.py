"""Impacket protocol-level tools wrapper."""

from __future__ import annotations

import json
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper, resolve_binary


class ImpacketTool(ToolWrapper):
    """Base for Impacket script wrappers.

    Handles both naming conventions:
      - impacket-secretsdump  (system/distro packages)
      - secretsdump.py        (pip install impacket)
    """

    def __init__(self) -> None:
        super().__init__()

        # If the primary binary isn't found, try the .py variant
        if not resolve_binary(self.binary):
            # "impacket-secretsdump" -> "secretsdump.py"
            alt = self.binary.replace("impacket-", "") + ".py"
            if resolve_binary(alt):
                self.binary = alt

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        lines = result.stdout.strip().splitlines()
        interesting = [
            l.strip() for l in lines
            if l.strip() and not l.startswith("Impacket")
            and not l.startswith("[*] ")
        ]
        return {"results": interesting, "raw_lines": len(lines)}


class SecretsDump(ImpacketTool):
    """impacket-secretsdump — extract credentials from remote systems."""

    name = "secretsdump"
    description = "Extract SAM, LSA secrets, cached creds, NTDS.dit from targets"
    binary = "impacket-secretsdump"
    att_ck_ids = ["T1003.001", "T1003.002", "T1003.003", "T1003.004"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        domain = kwargs.get("domain", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        nt_hash = kwargs.get("nt_hash", "")

        # Build auth string: domain/user:pass@target
        auth = ""
        if domain:
            auth += f"{domain}/"
        if username:
            auth += username
        if password:
            auth += f":{password}"
        elif nt_hash:
            cmd.extend(["-hashes", f":{nt_hash}"])
        auth += f"@{target}"
        cmd.append(auth)

        # Options
        if kwargs.get("just_dc"):
            cmd.append("-just-dc")
        if kwargs.get("just_dc_ntlm"):
            cmd.append("-just-dc-ntlm")
        if kwargs.get("sam"):
            cmd.append("-sam")
        if kwargs.get("lsa"):
            cmd.append("-lsa")

        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-outputfile", output_file])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        lines = result.stdout.strip().splitlines()
        hashes = []
        lsa_secrets = []
        cached_creds = []

        section = None
        for line in lines:
            stripped = line.strip()
            if "SAM hashes" in line or "NTDS.DIT" in line:
                section = "hashes"
            elif "LSA Secrets" in line:
                section = "lsa"
            elif "Cached Credentials" in line:
                section = "cached"
            elif ":::" in stripped and section == "hashes":
                hashes.append(stripped)
            elif section == "lsa" and stripped and not stripped.startswith("["):
                lsa_secrets.append(stripped)
            elif section == "cached" and stripped and ":" in stripped:
                cached_creds.append(stripped)

        return {
            "hashes": hashes,
            "hash_count": len(hashes),
            "lsa_secrets": lsa_secrets[:20],
            "cached_credentials": cached_creds,
        }


class GetNPUsers(ImpacketTool):
    """impacket-GetNPUsers — AS-REP roasting."""

    name = "getnpusers"
    description = "AS-REP roasting — get TGTs for accounts without pre-auth"
    binary = "impacket-GetNPUsers"
    att_ck_ids = ["T1558.004"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        domain = kwargs.get("domain", target)
        cmd.append(f"{domain}/")

        dc_ip = kwargs.get("dc_ip", target)
        cmd.extend(["-dc-ip", dc_ip])

        username = kwargs.get("username")
        password = kwargs.get("password")
        if username:
            cmd[-1] = f"{domain}/{username}"
            if password:
                cmd[-1] += f":{password}"
        else:
            # No auth — request all users
            cmd.append("-no-pass")

        usersfile = kwargs.get("usersfile")
        if usersfile:
            cmd.extend(["-usersfile", usersfile])

        # Hashcat-compatible output
        cmd.extend(["-format", "hashcat"])

        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-outputfile", output_file])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        lines = result.stdout.strip().splitlines()
        hashes = [l.strip() for l in lines if "$krb5asrep$" in l]
        return {
            "asrep_hashes": hashes,
            "hash_count": len(hashes),
        }


class GetUserSPNs(ImpacketTool):
    """impacket-GetUserSPNs — Kerberoasting."""

    name = "getuserspns"
    description = "Kerberoasting — request TGS tickets for service accounts"
    binary = "impacket-GetUserSPNs"
    att_ck_ids = ["T1558.003"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        domain = kwargs.get("domain", target)
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        nt_hash = kwargs.get("nt_hash", "")

        auth = f"{domain}/{username}"
        if password:
            auth += f":{password}"
        cmd.append(auth)

        if nt_hash:
            cmd.extend(["-hashes", f":{nt_hash}"])

        dc_ip = kwargs.get("dc_ip", target)
        cmd.extend(["-dc-ip", dc_ip])

        # Request TGS tickets
        if kwargs.get("request", True):
            cmd.append("-request")

        cmd.extend(["-outputfile", kwargs.get("output_file", "/tmp/kerberoast.txt")])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        lines = result.stdout.strip().splitlines()
        spns = []
        hashes = [l.strip() for l in lines if "$krb5tgs$" in l]

        for line in lines:
            if "SPN" not in line and "/" in line and "@" not in line:
                spns.append(line.strip())

        return {
            "spn_accounts": spns,
            "tgs_hashes": hashes,
            "hash_count": len(hashes),
        }


class PsExec(ImpacketTool):
    """impacket-psexec — remote command execution via SMB."""

    name = "psexec"
    description = "Remote command execution via SMB (PSEXEC-style)"
    binary = "impacket-psexec"
    att_ck_ids = ["T1021.002", "T1569.002"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        domain = kwargs.get("domain", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        nt_hash = kwargs.get("nt_hash", "")

        auth = ""
        if domain:
            auth += f"{domain}/"
        auth += username
        if password:
            auth += f":{password}"
        auth += f"@{target}"
        cmd.append(auth)

        if nt_hash:
            cmd.extend(["-hashes", f":{nt_hash}"])

        # Command to execute
        exec_cmd = kwargs.get("command")
        if exec_cmd:
            cmd.extend(["-c", exec_cmd])

        return cmd


class WmiExec(ImpacketTool):
    """impacket-wmiexec — remote command execution via WMI."""

    name = "wmiexec"
    description = "Remote command execution via WMI"
    binary = "impacket-wmiexec"
    att_ck_ids = ["T1047"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        domain = kwargs.get("domain", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        nt_hash = kwargs.get("nt_hash", "")

        auth = ""
        if domain:
            auth += f"{domain}/"
        auth += username
        if password:
            auth += f":{password}"
        auth += f"@{target}"
        cmd.append(auth)

        if nt_hash:
            cmd.extend(["-hashes", f":{nt_hash}"])

        exec_cmd = kwargs.get("command")
        if exec_cmd:
            cmd.extend(["-c", exec_cmd])

        return cmd


class NTLMRelayx(ImpacketTool):
    """impacket-ntlmrelayx — NTLM relay attacks."""

    name = "ntlmrelayx"
    description = "NTLM relay attack framework"
    binary = "impacket-ntlmrelayx"
    att_ck_ids = ["T1557.001"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        # Target file or single target
        if target.endswith(".txt"):
            cmd.extend(["-tf", target])
        else:
            cmd.extend(["-t", target])

        # Options
        if kwargs.get("smb2support", True):
            cmd.append("-smb2support")

        if kwargs.get("socks"):
            cmd.append("-socks")

        if kwargs.get("delegate_access"):
            cmd.append("--delegate-access")

        exec_cmd = kwargs.get("command")
        if exec_cmd:
            cmd.extend(["-c", exec_cmd])

        return cmd

# Daily Changelog

## 2026-03-22 (run 2) — Code Quality: Impacket Auth Deduplication

**Focus:** Category B — Code Quality (impacket_tools.py duplication)

**Changes:**

- `ice_9/tools/impacket_tools.py`: Extracted `ImpacketTool._build_auth()` static method that builds the NTLM auth string (`[domain/]username[:password][@target]`) and optional `-hashes` args. Refactored `SecretsDump`, `GetUserSPNs`, `PsExec`, and `WmiExec` to use it, eliminating ~40 lines of duplicated auth construction logic. Removed unused `json` import. Added `include_target` parameter to support GetUserSPNs which omits `@target` from its auth string.
- `tests/test_tools/test_impacket_tools.py`: New file — 18 tests covering `_build_auth` helper (full auth, hash-only, password+hash, no domain, no password, include_target=False, empty inputs) and `build_command` for all four refactored classes.

**Behavioral note:** SecretsDump previously used `elif` for hash handling (hash args only added when no password present). The refactored version always passes hash args when `nt_hash` is set, matching PsExec/WmiExec behavior. Impacket itself handles the precedence, so this is a correctness improvement.

**Test results:** 94 passed (up from 76), 0 failures, 101 warnings (all `datetime.utcnow()` deprecation).

**Recommended next run focus:**
- Category A: Path traversal in `output_file` kwargs across nmap, amass, subfinder, theharvester, bloodhound, impacket_tools — none validate that the path stays within an allowed directory. Add a shared `validate_output_path()` utility in `tools/base.py`.
- Category A: `metasploit.py:103-104` bare `except Exception: pass` in `_authenticate()`.
- Category A: `metasploit.py:125` `search_modules` interpolates `query` into URL without encoding.
- Category B: `GetNPUsers.build_command` has unusual logic (mutates `cmd[-1]` by index) — could be simplified but has a different auth pattern than the other 4 tools.

**Issues noticed but not fixed:**
- `base.py:121,161` — `datetime.utcnow()` deprecation (101 warnings in test suite)
- `custom.py` — generic tool runner accepts arbitrary args without validation (lower risk since no `shell=True`)
- `impacket_tools.py:297` — `NTLMRelayx` uses `target.endswith(".txt")` to decide between `-tf` and `-t`, fragile heuristic

## 2026-03-22 — Security: Tool Wrapper Input Validation

**Focus:** Category A — Bugs and Security (tool wrappers)

**Changes:**

- `ice_9/tools/metasploit.py`: Fixed command injection vulnerability. The `build_command` method joined msfconsole commands with semicolons into a single `-x` string, allowing injection via module paths, option keys/values, or targets. Now uses a temporary resource file (`-r`) with newline-separated commands. Added regex validation for module paths, option keys, and option values.
- `ice_9/tools/responder.py`: Fixed logic bug where the `disable` kwarg loop ignored the service variable and always appended `--disable-ess`. Now correctly generates `--disable-smb`, `--disable-http`, etc. Added service name validation against an allowlist. Separated ESS disabling into its own `disable_ess` kwarg.
- `tests/test_tools/test_metasploit.py`: New file — 17 tests covering resource file generation and input validation (semicolons, backticks, `$()`, option key/value injection, valid paths).
- `tests/test_tools/test_responder.py`: Added 5 tests for the disable service logic (multi-service, single, invalid, whitespace, ESS).

**Test results:** 76 passed (up from 59), 0 failures.

**Recommended next run focus:**
- Category A: Audit `custom.py` — the generic tool runner accepts arbitrary `pre_args`/`post_args`/`args` lists without validation. Since these are passed directly to subprocess as list elements (no `shell=True`), the risk is lower but worth reviewing if any caller interpolates user input into individual args.
- Category A: Path traversal in `output_file` kwargs across nmap, amass, subfinder, theharvester, bloodhound — none validate that the path stays within an allowed directory.
- Category B: `impacket_tools.py` has 6 nearly identical `build_command` implementations that could share a common auth-string builder.

**Issues noticed but not fixed:**
- `metasploit.py:98` — hardcoded username `"msf"` in `_authenticate()`, should use `self.password` logic or a username field
- `metasploit.py:103-104` — bare `except Exception: pass` in `_authenticate()` swallows all errors silently
- `metasploit.py:125` — `search_modules` interpolates `query` into URL without encoding (`f"/modules/search?query={query}"`)
- `base.py:121,161` — `datetime.utcnow()` deprecation warnings (101 warnings in test suite)

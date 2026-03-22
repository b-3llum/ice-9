# Daily Changelog

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

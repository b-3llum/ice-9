# Daily Changelog

## 2026-10-11 — Security: Output-Path Confinement + Tool Correctness

**Focus:** Category A — Bugs and Security (path traversal, msfrpc hardening, GetNPUsers bug)

**Changes:**

- `ice_9/tools/base.py`: Added `validate_output_path()` and `ice9_data_dir()`. Several wrappers pass a caller-supplied output location straight to an offensive binary that then *writes* to it, so an AI agent / REST client / phase module could redirect that write anywhere the process can reach (`~/.ssh/authorized_keys`, a systemd unit, a cron file) — an arbitrary-file-write primitive. The new helper expands `~`, collapses `..`, resolves symlinks in any existing prefix, and requires the result to stay within an allowed root (the ice_9 data dir — honouring `ICE9_HOME` — plus the system temp dir and `/tmp`). Relative paths resolve against the data dir, never the process CWD. Empty paths and null bytes are rejected.
- `ice_9/tools/{bloodhound,subfinder,theharvester}.py` and `ice_9/tools/impacket_tools.py` (`SecretsDump`, `GetNPUsers`, `GetUserSPNs`): route every `output_file` / `output_dir` kwarg through `validate_output_path()`. Existing defaults (`/tmp/bloodhound`, `/tmp/kerberoast.txt`) are unchanged and remain valid.
- `ice_9/tools/impacket_tools.py` — `GetNPUsers.build_command`: fixed a correctness bug. The old code appended the principal as `domain/`, then `-dc-ip <ip>`, then overwrote `cmd[-1]` with `domain/user` — which clobbered the `-dc-ip` *value* instead of the principal. With a username the tool was invoked with an empty principal and a credential string where the DC IP belonged. The principal is now built in full and appended once; `-dc-ip` is left intact.
- `ice_9/tools/metasploit.py`: replaced the bare `except Exception: pass` in `_authenticate()` with specific handling (connection error → log + False; non-200 → log + False; non-JSON body → log + False) via a module `logging` logger, so a down RPC service is distinguishable from a bad password. `search_modules()` now percent-encodes the query (`urllib.parse.quote(..., safe="")`) before placing it in the URL, so spaces/`&`/`#`/`?` are sent as data rather than altering the request. Added a configurable `username` field (default `"msf"`) instead of the hardcoded literal in the auth call.
- Tests: new `tests/test_tools/test_output_path.py` (16 tests — allowed roots, traversal/escape rejection, empty/null-byte, `ICE9_HOME`, and wrapper-level rejection). Added `TestGetNPUsers` + `TestImpacketOutputPaths` to `test_impacket_tools.py` (11 tests, including a regression test for the `-dc-ip` clobber). Added `TestSearchModules` + `TestAuthenticate` to `test_metasploit.py` (URL encoding, username, and all four auth outcomes).

**Test results:** 212 passed (up from 178), 0 failures. `ruff check ice_9 tests` clean.

**Recommended next run focus:**
- Category A: `impacket_tools.py` `NTLMRelayx` uses `target.endswith(".txt")` to pick `-tf` vs `-t` — fragile; an explicit `targets_file` kwarg would be clearer and safer.
- Category A: `custom.py` generic runner accepts arbitrary `pre_args`/`post_args`/`args` without validation (lower risk — no `shell=True`, passed as list elements).
- Category A: `config/settings.py` does not read `ICE9_HOME` even though the README documents it as the data-dir override; `validate_output_path`/`ice9_data_dir` now honour it, so settings should too for consistency.
- Category B: `base.py:121,161`-era `datetime.utcnow()` deprecation warnings (if any remain in the suite).

**Issues noticed but not fixed:**
- `metasploit.py` `_http = httpx.Client(verify=False)` disables TLS verification for the local msfrpc connection — expected for a self-signed localhost service, but worth a config flag if remote msfrpcd is ever supported.
- `bloodhound.py` imports `re` inside `parse_output` loop body rather than at module scope.

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

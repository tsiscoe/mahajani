# Contributing to Mahajani

Thank you for helping audit, harden, and extend **Mahajani**. Because Mahajani is cryptographic authentication and network boundary infrastructure, every pull request must preserve challenge-response replay invariants, virtual root confinement, and bounded socket resource consumption.

---

## 1. Security & Code Quality Guardrails

1. **Strict Single-Use Nonce Invariant (`src/auth.rs`):**
   - Every session challenge (`speakeasy-nonce-<hex32>`) must be atomically removed from `active_challenges` before signature evaluation so neither valid nor failed `PASS` payloads can ever be replayed.
2. **Pre-Authentication Command Isolation (`src/ftp.rs`):**
   - No filesystem or passive data listener command (`PWD`, `CWD`, `PASV`, `LIST`, `RETR`, `STOR`, `DELE`) may execute before `self.authenticated == true`.
3. **Virtual Root Confinement (`resolve_safe_path`):**
   - Every user-supplied path must pass lexical filtering (`:`, leading `/` or `\`, `\0`), relative stack normalization (`..` underflow rejection), and canonical prefix verification against `root_dir`.
4. **Bounded Socket & Buffer Resources:**
   - Never replace `read_line_capped(&mut reader, &mut line, 4096)` with unbounded `BufRead::read_line()`.
   - Preserve `ConnectionGuard` RAII accounting and socket read/write timeouts on all TCP streams.

---

## 2. Development & Verification Workflow

Before opening a Pull Request, run the full verification suite locally:

```powershell
# 1. Check formatting
cargo fmt --check

# 2. Build release binary and verify zero compilation warnings
cargo check --all-targets

# 3. Execute the 10-Gate Runtime & Security Hardening Self-Test Suite
cargo run --release -- --test

# 4. Run Clippy static analysis
cargo clippy --all-targets
```

---

## 3. Priority Security Hardening Backlog (`RED_DAWN_INDEPENDENT_AUDIT.md`)

Contributors looking to harden Mahajani further should consult [**RED_DAWN_INDEPENDENT_AUDIT.md**](RED_DAWN_INDEPENDENT_AUDIT.md), which specifies actionable remediation blueprints for six advanced vectors:
- **`SEC-06`:** Implement `AuthManager::clear_challenge()` inside `Drop for FtpSession` and add TTL/capacity bounds on `active_challenges`.
- **`SEC-07`:** Convert passive data listener `accept()` (`accept_data_connection`) to non-blocking polling with a 30-second `Instant` deadline and data-stream read/write timeouts.
- **`SEC-08`:** Bind passive data connections to the authenticated control peer IP and optional per-transfer token.
- **`SEC-09`:** Hold a single registry lock across `SITE REGISTER` existence checks and file creation using `OpenOptions::new().write(true).create_new(true)`.
- **`SEC-10` & `SEC-11`:** Make `canonicalize()` strictly fail-closed and add Windows reserved device name / trailing dot-space / reparse-point regression tests.

---

## 4. License Agreement

By contributing to **Mahajani**, you agree that your contributions will be licensed under the [MIT License](LICENSE).

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

# 3. Execute the 13-Gate Runtime & Security Hardening Self-Test Suite
cargo run --release -- --test

# 4. Run Clippy static analysis
cargo clippy --all-targets
```

---

## 3. Red-Dawn Security Hardening Invariants (`RED_DAWN_INDEPENDENT_AUDIT.md`)

All pull requests must preserve the six remediated Red-Dawn security invariants documented in [**RED_DAWN_INDEPENDENT_AUDIT.md**](RED_DAWN_INDEPENDENT_AUDIT.md):
- **`SEC-06`:** Preserve `AuthManager::clear_challenge()` inside `Drop for FtpSession` and the 60-second TTL / 128-entry capacity bounds on `active_challenges`.
- **`SEC-07`:** Keep passive data listener `accept()` (`accept_data_connection`) non-blocking with a 10-second `Instant` deadline and 30-second data-stream read/write timeouts.
- **`SEC-08`:** Preserve passive data connection control-peer IP verification and `SITE DATATOKEN <token>` preamble enforcement.
- **`SEC-09`:** Hold a single registry lock across `SITE REGISTER` existence checks and file creation using `OpenOptions::new().write(true).create_new(true)`.
- **`SEC-10` & `SEC-11`:** Keep `canonicalize()` strictly fail-closed alongside `symlink_metadata()` checks and Windows reserved device name / trailing dot-space / `~` 8.3 alias rejection.

---

## 4. License Agreement

By contributing to **Mahajani**, you agree that your contributions will be licensed under the [MIT License](LICENSE).

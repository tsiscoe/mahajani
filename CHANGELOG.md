# Changelog

All notable changes to **Mahajani** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-10-29

### Security & Hardening (`red-dawn-remediated`)
- **`SEC-06` (Unauthenticated Challenge Eviction & Capacity Bounds):** Added `AuthManager::clear_challenge()` invoked automatically via `impl Drop for FtpSession` and `QUIT`, plus a 60-second challenge TTL and 128-entry LRU eviction ceiling.
- **`SEC-07` (Non-Blocking `PASV` Accept Deadlines):** Converted `accept_data_connection()` to non-blocking `TcpListener::accept()` polling with a 10-second `Instant` deadline and 30-second data stream read/write timeouts.
- **`SEC-08` (Passive Data-Channel Peer & Token Binding):** Enforced control-peer IP matching on accepted passive sockets and added `SITE DATATOKEN <token>` requiring a `TOKEN <token>\r\n` preamble before streaming bytes.
- **`SEC-09` (Atomic Key Enrollment):** Held a single `authorized_keys` mutex lock across existence check and insertion, persisting keys exclusively via `OpenOptions::new().write(true).create_new(true)` + `sync_all()`.
- **`SEC-10` & `SEC-11` (Fail-Closed Canonical Confinement & Windows Hygiene):** Made `canonicalize()` strictly fail-closed, added component-by-component `symlink_metadata()` reparse rejection, re-validated active directories on `LIST`, and blocked reserved Windows device names (`CON`, `NUL`, `COM1`..`9`, `LPT1`..`9`), trailing dots/spaces, and `~` 8.3 shortname aliases.
- **13-Gate Automated Verification Suite (`src/self_test.rs`):** Expanded `--test` from 10 to 13 live TCP gates verifying `SEC-06` through `SEC-11`.

---

## [1.0.0] - 2026-10-29

### Added
- **Asymmetric Challenge-Response Authentication Engine (`src/auth.rs`, `src/keygen.rs`):**
  - Ephemeral 128-bit CSPRNG challenge nonce generation (`speakeasy-nonce-<32_hex_chars>`) issued on `USER <username>` and atomically consumed on `PASS` for single-use replay protection.
  - Dual-mode public-key verification supporting ASCII-armored **OpenPGP Cleartext Signed Messages** (`pgp v0.21.0`, RFC 4880 / RFC 9580) and **1024-bit RSA PKCS#1 v1.5 SHA-256** digital signatures (`rsa v0.9`, Base64 or Hex encoded).
  - Dynamic zero-downtime public key discovery across `./authorized_keys/*.{asc,pgp,pub}` and thread-safe `Mutex<HashMap<String, AuthorizedKey>>` caching.
- **In-Band Public Key Provisioning (`SITE REGISTER` / `SITE PUBKEY`):**
  - Network-socket public key enrollment supporting raw and Base64-wrapped OpenPGP public key blocks.
  - Strict `[a-zA-Z0-9_-]` username sanitization and existing-account overwrite protection (`550`).
- **Hardened RFC 959 FTP Control & Passive Data Server (`src/ftp.rs`):**
  - Multi-threaded TCP server (`127.0.0.1:2121` default) with a 64-connection `AtomicUsize` concurrency ceiling (`ConnectionGuard`), 30-second socket timeouts, and a 4,096-byte control line buffer cap (`read_line_capped`).
  - Three-stage virtual root confinement and Path Traversal IDS (`resolve_safe_path`) across `CWD`, `RETR`, `STOR`, and `DELE`, rejecting `:`, leading `/` or `\`, `\0`, `..` root escapes, and canonical prefix mismatches.
- **10-Gate Runtime & Security Self-Test Suite (`src/self_test.rs`):**
  - Automated loopback TCP verification (`--test` / `-t`) proving unauthenticated command blocking, forged signature rejection (`mallory` vs. `alice`), valid RSA-1024 login, `PASV`/`STOR`/`RETR` binary integrity, traversal defense, and `SITE REGISTER` overwrite protection.
- **Companion Operational & Audit Tooling (`tools/`):**
  - `tools/encrypt_payload.py`: OpenPGP 1024-bit authority key generator and `.pgp` payload signer/encryptor.
  - `tools/fetch_keyserver.py`: HKP/HTTPS OpenPGP keyserver resolver (`https://pgp.mit.edu/pks/lookup`).
  - `tools/surveillance_worker.py`: Out-of-band filesystem and honeypot tamper/access audit daemon.
- **Comprehensive Documentation & Security Audit Suite:**
  - Full documentation suite (`README.md`, `ARCHITECTURE.md`, `INSTALL.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `MISSION_DOSSIER.md`, `RED_DAWN_INDEPENDENT_AUDIT.md`, `llms.txt`, and `LICENSE`).

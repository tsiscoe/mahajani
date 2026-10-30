# Changelog

All notable changes to **Mahajani** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

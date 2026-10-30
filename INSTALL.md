# Installing & Configuring Mahajani

This guide covers building **Mahajani** from source, running the 10-gate cryptographic verification suite, configuring the `./authorized_keys` and `./ftp_data` directories, setting up the companion Python keyserver/encryption tools, and troubleshooting common issues.

---

## 1. System Prerequisites

- **Rust Toolchain:** Rust `1.85+` (2024 Edition) and `cargo`.
  - Verify with:
    ```powershell
    rustc --version
    cargo --version
    ```
  - If not installed, download via [rustup.rs](https://rustup.rs/).
- **Zero External C/OpenSSL Dependencies:** Mahajani's Rust server uses 100% pure-Rust cryptographic crates (`pgp`, `rsa`, `sha2`, `base64`, `hex`, `rand`). No C compiler, OpenSSL installation, or `pkg-config` is required to build and run the server.
- **Python 3.10+ (Optional — Companion Tooling Only):**
  - Required only if you use the helper scripts in `tools/` (`encrypt_payload.py`, `fetch_keyserver.py`, `surveillance_worker.py`).
  - Install the Python OpenPGP dependency:
    ```powershell
    pip install pgpy
    ```

---

## 2. Building & Installing from Source

### Option A: Standalone Release Binary Build (Recommended)
Compile the optimized release binary into `target/release/mahajani.exe` (Windows) or `target/release/mahajani` (Linux/macOS):

```powershell
git clone https://github.com/tsiscoe/mahajani.git
cd mahajani
cargo build --release
```

### Option B: Global Cargo Install
Install the `mahajani` binary directly into `~/.cargo/bin`:

```powershell
git clone https://github.com/tsiscoe/mahajani.git
cd mahajani
cargo install --path .
```

---

## 3. Running the 10-Gate Verification Suite

Before deploying or exposing the server, execute the built-in end-to-end TCP verification harness (`--test` or `-t`):

```powershell
cargo run --release -- --test
```

This spawns an ephemeral test instance on `127.0.0.1:22123`, generates valid (`alice`) and forged (`mallory`) 1024-bit RSA keypairs, and verifies all 10 runtime and security gates (banner, unauthenticated command blocking, forged signature rejection, valid challenge-response login, `PASV`/`STOR`/`RETR` binary transfer integrity, `CWD`/`STOR`/`DELE` path traversal blocking, and `SITE REGISTER` overwrite/traversal protection).

---

## 4. Server Directory Layout & Key Provisioning

When launched, Mahajani automatically creates and manages two working directories relative to the current working directory:
- `./authorized_keys/` — Stores authorized user public keys (`<username>.asc`, `<username>.pgp`, or `<username>.pub`).
- `./ftp_data/` — The confined virtual root directory served to authenticated FTP clients.

### Launching the Server
```powershell
# Start on default loopback endpoint (127.0.0.1:2121)
cargo run --release

# Or specify a custom bind address and port
cargo run --release -- --addr 127.0.0.1:2121
```

> **Note:** If `./authorized_keys/` does not contain a key for `alice` on startup, Mahajani automatically generates an in-memory 1024-bit RSA keypair for `alice` so local health checks can run immediately.

### Three Ways to Authorize a Client Public Key

1. **Drop an ASCII-Armored Public Key on Disk (Zero-Downtime Hot-Reload):**
   Save the user's OpenPGP public key as `./authorized_keys/<username>.asc`. `AuthManager::has_user()` dynamically checks disk on every `USER` command without requiring a server restart.
2. **In-Band Network Registration (`SITE REGISTER`):**
   Connect to port `2121` and send a Base64-encoded ASCII-armored OpenPGP public key:
   ```text
   SITE REGISTER <username> <base64_encoded_armored_pubkey>
   ```
3. **Fetch from an External HKP Keyserver (`tools/fetch_keyserver.py`):**
   ```powershell
   python tools/fetch_keyserver.py <username_or_key_id> -d ./authorized_keys -s https://pgp.mit.edu/pks/lookup
   ```

---

## 5. Companion Operational Scripts (`tools/`)

### 5.1 Encrypting & Signing Target Payloads (`tools/encrypt_payload.py`)
Generates a 1024-bit RSA OpenPGP Service Authority keypair (`authority_secret.asc` / `authority_public.asc`) and seals any file into a signed + AES-256 encrypted `.pgp` container:

```powershell
python tools/encrypt_payload.py ./raw_secret.bin -o ./ftp_data/target.pgp -k ./keys
```

### 5.2 Out-of-Band FileSystem & Honeypot Surveillance (`tools/surveillance_worker.py`)
Polls monitored directories for unauthorized file creation or out-of-band modification (`mtime`, `atime`, `size`) and logs `[BREACH_ALERT]` events to `.audit.log`:

```powershell
python tools/surveillance_worker.py ./ftp_data ./authorized_keys -l .audit.log -i 1.0
```

---

## 6. Troubleshooting

### `530 User '<name>' not found in OpenPGP authorized registry`
- **Cause:** No key matching `<name>` exists in memory or inside `./authorized_keys/<name>.{asc,pgp,pub}`, or the `.asc` file could not be parsed as a valid OpenPGP `SignedPublicKey`.
- **Resolution:** Ensure the file contains a valid `-----BEGIN PGP PUBLIC KEY BLOCK-----` header and matches the lowercase username stem, or enroll via `SITE REGISTER`.

### `530 Authentication failed: Challenge mismatch!`
- **Cause:** Each `USER <name>` command generates a new `speakeasy-nonce-<hex32>` challenge, and every `PASS` attempt atomically consumes the active challenge.
- **Resolution:** Ensure your client signs the exact nonce string (`speakeasy-nonce-...`, without trailing periods or extra whitespace) returned by the immediately preceding `331` response.

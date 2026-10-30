# Red-Dawn independent security audit

**Auditor:** OpenAI Codex  
**Date:** 2026-10-16  
**Target:** `tsiscoe/mahajani`, `Red-Dawn` at `6168ad0fe54982f744207dff17f3fb58321c2279`  
**Base:** `origin/main` at `3ace09955373a7d63b2e68df7c19acffc7a4ca09`  
**Scope:** `src/auth.rs`, `src/ftp.rs`, `src/main.rs`, `src/keygen.rs`, `src/self_test.rs`; code review and local tool availability check. No target service or live user data was touched.

## Solution framework and decision gates

1. Identify all untrusted ingress: FTP control commands, public key payloads, passive data sockets, filesystem entries and configuration paths.
2. Trace each ingress to authentication, key registry, passive listener, file I/O and logging sinks. Treat canonicalization as a time-of-check operation, not a confinement primitive.
3. Classify each result as **CONFIRMED**, **NEEDS_VALIDATION**, or **REJECTED**. A static code path can confirm missing cleanup or missing checks; platform-specific exploitability requires runtime evidence.
4. Gate merge on an enforced enrollment policy, bounded state/resources, authenticated data peer binding, filesystem confinement, and negative tests. A human owner must decide whether public enrollment and local-only FTP are intended product policies.

## Verification record

- Clone and branch checkout succeeded; `HEAD` equals the supplied commit. `origin/main` was fetched; the initial `main..Red-Dawn` command failed only because a local `main` name was absent. `git diff origin/main..Red-Dawn --stat` completed.
- `cargo check` and `cargo run -- --test` were attempted; both failed before execution because `cargo` is not installed or on PATH. No build or runtime pass is claimed.
- `git diff --check origin/main..Red-Dawn` found one whitespace warning in `.gitignore` (new blank line at EOF); this is not a security finding.
- The built-in test exercises a happy path and a few direct traversal strings. It does not exercise challenge cleanup, concurrent registration, passive data races, accept timeouts, symlinks, Windows aliases, or malformed OpenPGP keys. Its `10/10` banner is not an independent security gate.

## Detailed findings

### SEC-06 — HIGH — Unauthenticated challenge accumulation — CONFIRMED

**CWE:** CWE-400, Uncontrolled Resource Consumption. **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (conditional on the service being reachable; default bind is loopback).

**Location:** `src/auth.rs:24,126-132,136-140`; `src/ftp.rs:164-175,184-217,225-239`.

**Primitive:** An unauthenticated client sends `USER alice`, receives a nonce, then disconnects without `PASS`. `issue_challenge` inserts a new random session ID into a process-global `HashMap`. The only removal is inside `verify_signature`; disconnect and `QUIT` never remove it. Repeating across connections grows the map without a lifetime or entry limit. The 64 simultaneous connection ceiling does not bound cumulative entries.

**Minimal patch blueprint:** Add `AuthManager::clear_challenge(&self, session_id: &str)` that removes from `active_challenges`; implement `Drop for FtpSession` to call it. Also cap outstanding challenges or expire them by timestamp so abrupt termination and long-lived clients cannot make the map unbounded. Add a regression test that issues `USER`, disconnects, and checks the count returns to zero.

### SEC-07 — HIGH — Passive accept blocks a worker indefinitely — CONFIRMED

**CWE:** CWE-400. **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (a valid account is needed for `PASV`; open enrollment lowers the practical barrier).

**Location:** `src/ftp.rs:45-63,347-366,368-371,418-420,462-464,519-535`.

**Primitive:** An authenticated client sends `PASV`, then `LIST`, `RETR`, or `STOR` without opening the advertised data connection. `accept_data_connection` calls blocking `TcpListener::accept()` with no deadline. The 30-second timeout applies to the control `TcpStream`, which is not being read here. Up to 64 such sessions permanently occupy all worker slots. `ConnectionGuard` correctly decrements on unwind or normal return, but cannot run while the thread is blocked.

**Minimal patch blueprint:** Set the passive listener nonblocking and poll `accept()` against an `Instant` deadline, sleeping briefly on `WouldBlock`; return `425` and close the listener at expiry. Apply read/write timeouts to the accepted data socket too. Bound total and per-transfer bytes/time so a connected peer cannot hold the worker with an endless transfer. Test 64 idle passive transfers followed by a fresh control connection.

### SEC-08 — HIGH — Passive data connection is not tied to the control peer — CONFIRMED

**CWE:** CWE-306, Missing Authentication for Critical Function. **CVSS v3.1:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L` (local race and a victim transfer are required).

**Location:** `src/ftp.rs:347-366,519-529,368-397,418-440,462-484`.

**Primitive:** `PASV` advertises a loopback port. The first process connecting to it is accepted; the data socket carries no credential, token or peer binding. A local process that learns or scans the port can connect first. `RETR`/`LIST` then send the authenticated user's data to that process; `STOR` reads attacker-supplied bytes. Binding the listener to `127.0.0.1` limits the race to the same host but does not authenticate local processes. An attacker cannot bind the already-bound port; connecting first is the issue.

**Minimal patch blueprint:** At minimum, compare the accepted data peer IP to the control peer IP and reject mismatches, with a bounded accept loop. Because all local processes share `127.0.0.1`, that check does not solve the local race. For meaningful protection, require a per-transfer random data-channel token before file operations (documenting nonstandard FTP behavior), or replace plain FTP with a transport that authenticates both channels. Add a two-client race regression test.

### SEC-09 — HIGH — Public key enrollment permits identity squatting and concurrent overwrite — CONFIRMED

**CWE:** CWE-862, Missing Authorization; CWE-367, Time-of-check Time-of-use Race Condition. **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (impact assumes usernames confer access and remote binding is enabled).

**Location:** `src/ftp.rs:286-308`; `src/auth.rs:69-95,103-123`.

**Primitive:** `SITE REGISTER` is dispatched before the authentication guard. Anyone with a parseable key can claim any unregistered name. The new `has_user` check and `fs::write`/`HashMap::insert` are separate operations; two concurrent registrations of the same name can both pass the check and the later write/insert wins. `fs::write` errors are ignored, so a successful FTP response does not prove a durable key. Existing invalid `.asc` files are not treated as reserved names by `has_user` and can be overwritten.

**Minimal patch blueprint:** Define enrollment authority first (administrator provisioning, one-time invitation token, or an approved identity proof). Within that policy, hold one registry lock across existence check and insertion and create the key file with `OpenOptions::new().write(true).create_new(true)`; handle every I/O error and roll back if persistence fails. Reject or quarantine any pre-existing filename even when its contents are malformed. Test simultaneous same-name registration and a write failure. A mutex alone cannot prevent identity squatting.

### SEC-10 — MEDIUM — Canonical path checks are fail-open and race file access — NEEDS_VALIDATION

**CWE:** CWE-22, Path Traversal; CWE-367. **CVSS v3.1:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (depends on an attacker-controlled symlink/junction or concurrent filesystem mutation).

**Location:** `src/ftp.rs:77-123,331-336,376-379,404-425,453-469,497-506`.

**Primitive:** If `root.canonicalize()` fails, or an existing path or parent cannot be canonicalized, the resolver still returns `Ok`. For a dangling symlink, `exists()` can be false and the parent can be inside the root, yet `File::create` follows the final symlink. After any successful check, a separate actor can swap a directory for a symlink/junction before `File::open`, `File::create`, `remove_file`, or `LIST` uses the path. `LIST` directly joins the previously accepted current directory, so a post-`CWD` swap is also unchecked. This requires filesystem control outside the FTP protocol; the exploit was not run on this host.

**Minimal patch blueprint:** First, return `Err(())` on every canonicalization failure. For actual confinement, operate relative to an opened root directory handle and reject reparse points/symlinks while traversing components; open the final target through the verified handle rather than reopening a pathname after a check. On Windows, use handle-based APIs with reparse-point inspection; on Unix, use `openat2`/`RESOLVE_BENEATH` or equivalent. Apply the same invariant to `LIST`. Test dangling links, link replacement races and Windows junctions.

### SEC-11 — MEDIUM — Windows path aliases need target-runtime tests — NEEDS_VALIDATION

**CWE:** CWE-22. **CVSS v3.1:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (hypothetical until the Rust/Windows path behavior and root mutation model are exercised).

**Location:** `src/ftp.rs:77-123`.

**Primitive:** Colon rejection blocks ordinary NTFS alternate data stream syntax and drive prefixes. Leading backslash rejection blocks direct UNC/device paths. The resolver does not reject trailing dots/spaces or reserved Windows device names. Canonicalization may normalize 8.3 aliases and existing targets, but fail-open branches and create paths deserve Windows-specific probes. There is no named directory denylist for an 8.3 alias to bypass. A nonexistent nested parent normally makes `File::create` fail; it is not, by itself, an escape.

**Minimal patch blueprint:** Reject Windows-reserved component spellings, trailing dots/spaces and device names before constructing paths; keep the handle-based confinement fix from SEC-10 as the primary guard. Test `file.txt:stream`, `::$DATA`, `PROGRA~1`, `.. `, `file.txt.`, `file.txt `, `\\?\\`, `\\.\\`, nested missing parents and junctions on the intended Windows filesystem.

## Defensive claims that held in source review

- **Nonce entropy/replay:** `issue_challenge` uses 16 random bytes from `rand::thread_rng`; `verify_signature` removes the nonce before validating the signature. A captured signature for one nonce is not directly reusable in another session. The outstanding-map leak in SEC-06 remains.
- **Pre-auth data paths:** The `_ if !self.authenticated` arm precedes `PWD`, `CWD`, `PASV`, `LIST`, `RETR`, `STOR` and `DELE`. `USER` alone does not grant those commands. `SITE REGISTER` is the deliberate exception, covered in SEC-09.
- **Connection guard:** The guard is created at worker start and drops on normal return or unwind; the counter is not decremented while a worker remains blocked. Process abort and OS termination are outside Rust destructor guarantees.
- **PASV port churn:** Each session holds only its latest `TcpListener`; repeated `PASV` replaces and closes the prior listener. It does not accumulate unbounded simultaneous listeners within one session.
- **Error leakage:** Authentication failures echo parser/debug detail and, on challenge mismatch, the expected nonce and supplied message (`src/auth.rs:160-167`, `src/ftp.rs:261-265`). File open/create errors expose OS error text (`src/ftp.rs:442-445,486-489`) but no path is constructed into those particular responses. These should be made generic; no host-path disclosure was established from the reviewed code. No honeypot/tripwire timing claim can be validated without a running target and explicit deployment configuration.
- **OpenPGP key validity:** Parsing a `SignedPublicKey` is the only enrollment gate. This review did not establish whether the `pgp` library checks revocation, expiration, self-certifications or subkey suitability on this call path. Add malformed/revoked/expired/key-without-signing-capability corpus tests before claiming those cases safe.

## Patch sketches and limits

These are reviewable Rust edits, not tested changes to the target branch. They close the named local failure paths; the data-channel protocol and enrollment authority require product decisions before a complete patch can be specified.

```rust
// SEC-06, in AuthManager:
pub fn clear_challenge(&self, session_id: &str) {
    self.active_challenges.lock().unwrap().remove(session_id);
}

// SEC-06, in ftp.rs:
impl Drop for FtpSession {
    fn drop(&mut self) {
        self.auth_manager.clear_challenge(&self.session_id);
    }
}
```

```rust
// SEC-07, replace blocking listener.accept() in accept_data_connection:
use std::io::ErrorKind;
use std::time::Instant;
listener.set_nonblocking(true).ok()?;
let deadline = Instant::now() + Duration::from_secs(30);
loop {
    match listener.accept() {
        Ok((stream, _)) => {
            stream.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
            stream.set_write_timeout(Some(Duration::from_secs(30))).ok()?;
            return Some(stream);
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(_) => {
            self.send_resp(425, "Passive data connection timed out.");
            return None;
        }
    }
}
```

For SEC-08, an IP comparison is a useful remote-peer filter but cannot separate processes sharing `127.0.0.1`. The smallest complete fix needs a client-visible data-channel binding protocol; adding one without agreement would break ordinary FTP clients. For SEC-09, an atomic `create_new(true)` and a registry lock prevent same-name overwrites, but they do not establish who is allowed to claim a name. The human owner must define that authority before those edits can be considered a security fix. For SEC-10, a fail-closed `canonicalize` edit is necessary but not sufficient against link swapping; a handle-relative filesystem implementation is the required boundary. For SEC-11, patch syntax depends on the Windows component policy selected after runtime tests.

## Final merge recommendation

**NO-GO for merging `Red-Dawn` into `main` as production hardening.** SEC-06 through SEC-09 leave resource and identity boundaries open even though the five targeted patches improve direct traversal checks, connection counting and command line size. Make enrollment policy a human decision, repair the confirmed paths, run the Windows filesystem and parser probes, and rerun `cargo check`, the self test and adversarial regressions in a Rust-equipped environment. The current verdict is **ACTIONABLE-VULNERABILITIES-FOUND**, with build and dynamic validation explicitly unverified.

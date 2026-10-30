use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use rand::RngCore;
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use sha2::Sha256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Maximum outstanding unauthenticated session challenges (`SEC-06` bound)
const MAX_ACTIVE_CHALLENGES: usize = 128;
/// Challenge time-to-live before automatic expiry (`SEC-06` bound)
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// Represents an authorized OpenPGP public key or 1024-bit RSA public key
#[derive(Clone)]
pub enum AuthorizedKey {
    OpenPgp(SignedPublicKey),
    Rsa1024(VerifyingKey<Sha256>),
}

/// Authentication manager holding authorized keys and active session challenges
pub struct AuthManager {
    keys_dir: PathBuf,
    authorized_keys: Mutex<HashMap<String, AuthorizedKey>>,
    active_challenges: Mutex<HashMap<String, (String, Instant)>>, // session_id -> (challenge_nonce, issued_at)
}

impl AuthManager {
    pub fn new<P: AsRef<Path>>(keys_dir: P) -> Self {
        let dir = keys_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).ok();
        let mgr = Self {
            keys_dir: dir,
            authorized_keys: Mutex::new(HashMap::new()),
            active_challenges: Mutex::new(HashMap::new()),
        };
        mgr.load_keys();
        mgr
    }

    /// Load authorized keys from keys_dir (e.g. alice.asc, bob.asc, etc.)
    pub fn load_keys(&self) {
        if let Ok(entries) = fs::read_dir(&self.keys_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("asc")
                    || path.extension().and_then(|e| e.to_str()) == Some("pgp")
                    || path.extension().and_then(|e| e.to_str()) == Some("pub")
                {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let username = stem.to_lowercase();
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok((pubkey, _)) = SignedPublicKey::from_string(&content) {
                                println!("[AUTH] Loaded OpenPGP public key for user: {}", username);
                                self.authorized_keys.lock().unwrap().insert(username, AuthorizedKey::OpenPgp(pubkey));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Register an in-memory key (e.g. for testing)
    pub fn register_key(&self, username: &str, key: AuthorizedKey) {
        self.authorized_keys.lock().unwrap().insert(username.to_lowercase(), key);
    }

    /// Parse raw or base64-wrapped ASCII-armored OpenPGP public key (`SEC-09` helper)
    fn parse_armored_pubkey(content: &str) -> Result<(SignedPublicKey, String), String> {
        if let Ok((pubkey, _)) = SignedPublicKey::from_string(content) {
            return Ok((pubkey, content.to_string()));
        }
        if let Ok(decoded_bytes) = BASE64.decode(content.trim()) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                if let Ok((pubkey, _)) = SignedPublicKey::from_string(&decoded_str) {
                    return Ok((pubkey, decoded_str));
                }
            }
        }
        Err("Failed to parse public key as ASCII-armored OpenPGP SignedPublicKey".to_string())
    }

    /// Register public key content dynamically (`SEC-09`: atomic registry lock + `create_new(true)`)
    pub fn register_pubkey_content(&self, username: &str, content: &str) -> Result<(), String> {
        let uname = username.trim().to_lowercase();
        if uname.is_empty() {
            return Err("Empty username".to_string());
        }
        if !uname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err("Security violation: Username contains invalid characters (only alphanumeric, underscores, hyphens permitted)".to_string());
        }

        // Check if user already exists before parsing key so overwrite attempts fail immediately (`SEC-09`)
        if self.has_user(&uname) {
            return Err(format!("Security violation: User '{}' already registered. Overwriting public keys is prohibited.", uname));
        }

        // Parse and validate OpenPGP public key structure before taking registry write lock
        let (pubkey, canonical_armored) = Self::parse_armored_pubkey(content)?;

        // Hold a single registry lock across existence check, file creation, and insertion (`SEC-09`)
        let mut guard = self.authorized_keys.lock().unwrap();
        if guard.contains_key(&uname) {
            return Err(format!("Security violation: User '{}' already registered. Overwriting public keys is prohibited.", uname));
        }
        for ext in &["asc", "pgp", "pub"] {
            let candidate = self.keys_dir.join(format!("{}.{}", uname, ext));
            if candidate.exists() {
                return Err(format!("Security violation: User '{}' key file already exists on disk. Overwriting public keys is prohibited.", uname));
            }
        }

        let keyfile = self.keys_dir.join(format!("{}.asc", uname));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&keyfile)
            .map_err(|e| format!("Security violation or I/O error creating key file for '{}': {}", uname, e))?;

        if let Err(e) = file.write_all(canonical_armored.as_bytes()).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&keyfile);
            return Err(format!("Failed to persist public key for '{}': {}", uname, e));
        }

        guard.insert(uname.clone(), AuthorizedKey::OpenPgp(pubkey));
        println!("[AUTH] Atomically registered OpenPGP public key for '{}'", uname);
        Ok(())
    }

    /// Check if a user is recognized, checking memory cache and dynamic disk files
    pub fn has_user(&self, username: &str) -> bool {
        let uname = username.to_lowercase();
        let mut guard = self.authorized_keys.lock().unwrap();
        if guard.contains_key(&uname) {
            return true;
        }
        // Check disk dynamically
        for ext in &["asc", "pgp", "pub"] {
            let candidate = self.keys_dir.join(format!("{}.{}", uname, ext));
            if candidate.exists() {
                if let Ok(content) = fs::read_to_string(&candidate) {
                    if let Ok((pubkey, _)) = SignedPublicKey::from_string(&content) {
                        println!("[AUTH] Dynamically loaded OpenPGP public key from disk for user: {}", uname);
                        guard.insert(uname, AuthorizedKey::OpenPgp(pubkey));
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Generate and register a bounded cryptographic challenge nonce for a session (`SEC-06`)
    pub fn issue_challenge(&self, session_id: &str) -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let challenge = format!("speakeasy-nonce-{}", hex::encode(bytes));
        let now = Instant::now();

        let mut map = self.active_challenges.lock().unwrap();
        // Evict expired challenges (`SEC-06`)
        map.retain(|_, (_, issued_at)| now.duration_since(*issued_at) < CHALLENGE_TTL);

        // Enforce hard capacity ceiling by evicting the oldest entry if full (`SEC-06`)
        if map.len() >= MAX_ACTIVE_CHALLENGES && !map.contains_key(session_id) {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }

        map.insert(session_id.to_string(), (challenge.clone(), now));
        challenge
    }

    /// Explicitly remove a session's challenge nonce on disconnect or `QUIT` (`SEC-06`)
    pub fn clear_challenge(&self, session_id: &str) {
        self.active_challenges.lock().unwrap().remove(session_id);
    }

    /// Return the current number of active unauthenticated challenges (used by verification gates)
    pub fn active_challenge_count(&self) -> usize {
        let now = Instant::now();
        let mut map = self.active_challenges.lock().unwrap();
        map.retain(|_, (_, issued_at)| now.duration_since(*issued_at) < CHALLENGE_TTL);
        map.len()
    }

    /// Verify signed challenge submitted via PASS command
    pub fn verify_signature(&self, session_id: &str, username: &str, pass_input: &str) -> Result<(), String> {
        let (challenge, issued_at) = {
            let mut map = self.active_challenges.lock().unwrap();
            map.remove(session_id).ok_or_else(|| "No active challenge nonce for session. Issue USER first.".to_string())?
        };

        if Instant::now().duration_since(issued_at) >= CHALLENGE_TTL {
            return Err("Challenge nonce expired. Issue USER again.".to_string());
        }

        let key = {
            let map = self.authorized_keys.lock().unwrap();
            map.get(&username.to_lowercase()).cloned()
        }.ok_or_else(|| format!("User '{}' not authorized in OpenPGP registry", username))?;

        // 1. Try decoding as base64 if needed
        let raw_input = pass_input.trim();
        let decoded_str = if let Ok(bytes) = BASE64.decode(raw_input) {
            String::from_utf8(bytes).unwrap_or_else(|_| raw_input.to_string())
        } else {
            raw_input.to_string()
        };

        match key {
            AuthorizedKey::OpenPgp(pubkey) => {
                // Check if input is OpenPGP CleartextSignedMessage
                if decoded_str.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
                    let (msg, _) = CleartextSignedMessage::from_string(&decoded_str)
                        .map_err(|_| "Failed to parse OpenPGP CleartextSignedMessage".to_string())?;
                    
                    if msg.text().trim() != challenge.trim() {
                        return Err("Challenge nonce mismatch".to_string());
                    }

                    msg.verify(&pubkey)
                        .map_err(|_| "OpenPGP signature verification failed".to_string())?;

                    Ok(())
                } else {
                    Err("Expected OpenPGP cleartext signed message or base64 armored payload containing signed challenge nonce".to_string())
                }
            }
            AuthorizedKey::Rsa1024(verifying_key) => {
                // Verify 1024-bit RSA signature directly over challenge
                let sig_bytes = if let Ok(b) = BASE64.decode(raw_input) {
                    b
                } else if let Ok(b) = hex::decode(raw_input) {
                    b
                } else {
                    return Err("Failed to parse signature: expected base64 or hex".to_string());
                };

                let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| "Invalid RSA signature format".to_string())?;

                verifying_key.verify(challenge.as_bytes(), &sig)
                    .map_err(|_| "RSA 1024 signature verification failed".to_string())?;

                Ok(())
            }
        }
    }
}

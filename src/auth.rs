use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use rand::RngCore;
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use sha2::Sha256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

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
    active_challenges: Mutex<HashMap<String, String>>, // session_id -> challenge_nonce
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

    /// Register public key content dynamically (from SITE command or external upload)
    pub fn register_pubkey_content(&self, username: &str, content: &str) -> Result<(), String> {
        let uname = username.trim().to_lowercase();
        if uname.is_empty() {
            return Err("Empty username".to_string());
        }
        if !uname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err("Security violation: Username contains invalid characters (only alphanumeric, underscores, hyphens permitted)".to_string());
        }
        if self.has_user(&uname) {
            return Err(format!("Security violation: User '{}' already registered. Overwriting public keys is prohibited.", uname));
        }
        // Try parsing as OpenPGP SignedPublicKey
        if let Ok((pubkey, _)) = SignedPublicKey::from_string(content) {
            let keyfile = self.keys_dir.join(format!("{}.asc", uname));
            let _ = fs::write(&keyfile, content);
            self.authorized_keys.lock().unwrap().insert(uname.clone(), AuthorizedKey::OpenPgp(pubkey));
            println!("[AUTH] Successfully registered OpenPGP public key for '{}'", uname);
            return Ok(());
        }
        // Try decoding base64 if it's base64 encoded armored text
        if let Ok(decoded_bytes) = BASE64.decode(content.trim()) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                if let Ok((pubkey, _)) = SignedPublicKey::from_string(&decoded_str) {
                    let keyfile = self.keys_dir.join(format!("{}.asc", uname));
                    let _ = fs::write(&keyfile, &decoded_str);
                    self.authorized_keys.lock().unwrap().insert(uname.clone(), AuthorizedKey::OpenPgp(pubkey));
                    println!("[AUTH] Successfully registered base64-wrapped OpenPGP public key for '{}'", uname);
                    return Ok(());
                }
            }
        }
        Err("Failed to parse public key as ASCII-armored OpenPGP SignedPublicKey".to_string())
    }

    /// Check if a user is recognized, checking memory cache and dynamic disk files
    pub fn has_user(&self, username: &str) -> bool {
        let uname = username.to_lowercase();
        if self.authorized_keys.lock().unwrap().contains_key(&uname) {
            return true;
        }
        // Check disk dynamically
        for ext in &["asc", "pgp", "pub"] {
            let candidate = self.keys_dir.join(format!("{}.{}", uname, ext));
            if candidate.exists() {
                if let Ok(content) = fs::read_to_string(&candidate) {
                    if let Ok((pubkey, _)) = SignedPublicKey::from_string(&content) {
                        println!("[AUTH] Dynamically loaded OpenPGP public key from disk for user: {}", uname);
                        self.authorized_keys.lock().unwrap().insert(uname, AuthorizedKey::OpenPgp(pubkey));
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Generate and register a cryptographic challenge nonce for a session
    pub fn issue_challenge(&self, session_id: &str) -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let challenge = format!("speakeasy-nonce-{}", hex::encode(bytes));
        let mut map = self.active_challenges.lock().unwrap();
        map.insert(session_id.to_string(), challenge.clone());
        challenge
    }

    /// Verify signed challenge submitted via PASS command
    pub fn verify_signature(&self, session_id: &str, username: &str, pass_input: &str) -> Result<(), String> {
        let challenge = {
            let mut map = self.active_challenges.lock().unwrap();
            map.remove(session_id).ok_or_else(|| "No active challenge nonce for session. Issue USER first.".to_string())?
        };

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
                        .map_err(|e| format!("Failed to parse OpenPGP CleartextSignedMessage: {:?}", e))?;
                    
                    if msg.text().trim() != challenge.trim() {
                        return Err(format!("Challenge mismatch! Expected '{}', got '{}'", challenge, msg.text().trim()));
                    }

                    msg.verify(&pubkey)
                        .map_err(|e| format!("OpenPGP signature verification failed: {:?}", e))?;

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
                    .map_err(|e| format!("Invalid signature format: {:?}", e))?;

                verifying_key.verify(challenge.as_bytes(), &sig)
                    .map_err(|e| format!("RSA 1024 signature verification failed: {:?}", e))?;

                Ok(())
            }
        }
    }
}

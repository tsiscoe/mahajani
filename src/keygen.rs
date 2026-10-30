use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[derive(Clone)]
pub struct KeyPair1024 {
    pub signing_key: SigningKey<Sha256>,
    pub verifying_key: VerifyingKey<Sha256>,
}

impl KeyPair1024 {
    /// Generate a 1024-bit RSA key pair (matching OpenPGP/RSA requirements)
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("RSA 1024 generation failed");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign challenge nonce and return base64 signature
    pub fn sign_challenge(&self, challenge: &str) -> String {
        let mut rng = rand::thread_rng();
        let signature = self.signing_key.sign_with_rng(&mut rng, challenge.as_bytes());
        BASE64.encode(signature.to_vec())
    }
}

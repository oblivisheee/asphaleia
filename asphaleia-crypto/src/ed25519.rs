use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Debug)]
pub struct Ed25519 {
    signing_key: SigningKey,
}

impl Ed25519 {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.verifying_key().verify(message, signature)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        self.signing_key.to_keypair_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ed25519 = Ed25519::new();
        assert_eq!(ed25519.to_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes() {
        let ed25519 = Ed25519::new();
        let bytes = ed25519.to_bytes();
        let ed25519_from_bytes = Ed25519::from_bytes(&bytes).unwrap();
        assert_eq!(ed25519.to_bytes(), ed25519_from_bytes.to_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let ed25519 = Ed25519::new();
        let message = b"Hello, world!";
        let signature = ed25519.sign(message);
        assert!(ed25519.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let ed25519 = Ed25519::new();
        let message = b"Hello, world!";
        let signature = ed25519.sign(message);
        let different_message = b"Different message";
        assert!(ed25519.verify(different_message, &signature).is_err());
    }

    #[test]
    fn test_verifying_key() {
        let ed25519 = Ed25519::new();
        let verifying_key = ed25519.verifying_key();
        assert_eq!(verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_to_keypair_bytes() {
        let ed25519 = Ed25519::new();
        let keypair_bytes = ed25519.to_keypair_bytes();
        assert_eq!(keypair_bytes.len(), 64);
    }
}

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Error, Key, Nonce,
};

pub struct AES<T: AeadCore + Aead + KeyInit> {
    cipher: T,
}

impl<T: AeadCore + Aead + KeyInit> AES<T> {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self {
            cipher: T::new(Key::<T>::from_slice(key.as_ref())),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let nonce = match nonce {
            Some(n) => Nonce::from_slice(n).to_owned(),
            None => T::generate_nonce(&mut OsRng),
        };
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < 12 {
            return Err(Error);
        }

        let (nonce, encrypted_data) = ciphertext.split_at(12);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), encrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};
    use hkdf::Hkdf;
    use ring::rand::{SecureRandom, SystemRandom};
    use zeroize::Zeroizing;
    fn generate_key(key_size: usize) -> Zeroizing<Vec<u8>> {
        let salt = [0u8; 32];
        let mut key_material = vec![0u8; 32];
        SystemRandom::new().fill(&mut key_material).unwrap();

        let mut key = Zeroizing::new(vec![0u8; key_size]);
        let hkdf = Hkdf::<sha3::Sha3_256>::new(Some(&salt), &key_material);
        hkdf.expand(&[], &mut key).unwrap();

        key
    }

    /*fn derive_key(master_key: &[u8], info: &[u8], output_length: usize) -> Zeroizing<Vec<u8>> {
        let hk = Hkdf::<sha3::Sha3_256>::new(None, master_key);
        let mut okm = Zeroizing::new(vec![0u8; output_length]);
        hk.expand(info, &mut okm)
            .expect("HKDF-SHA256 should never fail");
        okm
    }*/

    #[test]
    fn test_encrypt_decrypt_aes256() {
        let plaintext = b"Hello, World!";
        let key = generate_key(32);
        let aes = AES::<Aes256Gcm>::new(&key);
        let ciphertext = aes.encrypt(plaintext, None).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_aes128() {
        let plaintext = b"Hello, World!";
        let key = generate_key(16);
        let aes = AES::<Aes128Gcm>::new(&key);
        let ciphertext = aes.encrypt(plaintext, None).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_block_size() {
        let plaintext = b"A".repeat(16); // Exactly one block
        let key = generate_key(32);
        let aes = AES::<Aes256Gcm>::new(&key);
        let ciphertext = aes.encrypt(&plaintext, None).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_custom_nonce() {
        let plaintext = b"Hello, World!";
        let key = generate_key(32);
        let aes = AES::<Aes256Gcm>::new(&key);
        let custom_nonce = [1u8; 12];
        let ciphertext = aes.encrypt(plaintext, Some(&custom_nonce)).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(&ciphertext[..12], &custom_nonce);
    }

    #[test]
    fn test_uninitialized_cipher() {
        let key = generate_key(32);
        let aes = AES::<Aes256Gcm>::new(&key);
        let plaintext = b"Hello, World!";
        assert!(aes.encrypt(plaintext, None).is_ok());
        assert!(aes.decrypt(b"Invalid ciphertext").is_err());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let key = generate_key(32);
        let aes = AES::<Aes256Gcm>::new(&key);
        assert!(aes.decrypt(b"Too short").is_err());
    }
}

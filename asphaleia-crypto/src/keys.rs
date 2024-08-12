use super::hash::Sha256;
use hex::{FromHex, ToHex};
use hkdf::Hkdf;
use ring::rand::SecureRandom;
use sha3::Sha3_256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Error, Debug)]
pub enum KeyManagementError {
    #[error("Lock poisoned")]
    LockPoisoned,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Failed to generate random key")]
    RandomGenerationFailed,
}

#[derive(Clone)]
pub struct KeyManagementSystem {
    keys: Arc<RwLock<HashMap<Sha256, BTreeMap<Sha256, KeyAndDerived>>>>,
}

impl KeyManagementSystem {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_key(
        &self,
        name: Sha256,
        version: Sha256,
        key_and_derived: KeyAndDerived,
    ) -> Result<(), KeyManagementError> {
        self.keys
            .write()
            .map_err(|_| KeyManagementError::LockPoisoned)?
            .entry(name)
            .or_insert_with(BTreeMap::new)
            .insert(version, key_and_derived);
        Ok(())
    }

    pub fn rotate_keys(&self) -> Result<(), KeyManagementError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyManagementError::LockPoisoned)?;
        for versions in keys.values_mut() {
            for key_and_derived in versions.values_mut() {
                key_and_derived.rotate();
            }
        }
        Ok(())
    }

    pub fn get_key(
        &self,
        name: &Sha256,
        version: &Sha256,
    ) -> Result<Option<KeyAndDerived>, KeyManagementError> {
        self.keys
            .read()
            .map_err(|_| KeyManagementError::LockPoisoned)
            .map(|keys| {
                keys.get(name)
                    .and_then(|versions| versions.get(version).cloned())
            })
    }

    pub fn remove_key(
        &self,
        name: &Sha256,
        version: &Sha256,
    ) -> Result<Option<KeyAndDerived>, KeyManagementError> {
        self.keys
            .write()
            .map_err(|_| KeyManagementError::LockPoisoned)
            .map(|mut keys| {
                keys.get_mut(name)
                    .and_then(|versions| versions.remove(version))
            })
    }

    pub fn list_keys(&self) -> Result<Vec<(Sha256, Vec<Sha256>)>, KeyManagementError> {
        self.keys
            .read()
            .map_err(|_| KeyManagementError::LockPoisoned)
            .map(|keys| {
                keys.iter()
                    .map(|(name, versions)| (name.clone(), versions.keys().cloned().collect()))
                    .collect()
            })
    }
}

#[derive(Clone)]
pub struct KeyAndDerived {
    key: Key,
    derived_keys: BTreeMap<Sha256, DerivedKey>,
}

impl KeyAndDerived {
    pub fn new(key: Key) -> Self {
        Self {
            key,
            derived_keys: BTreeMap::new(),
        }
    }

    pub fn add_derived_key(&mut self, name: Sha256, derived_key: DerivedKey) {
        self.derived_keys.insert(name, derived_key);
    }

    pub fn get_derived_key(&self, name: &Sha256) -> Option<&DerivedKey> {
        self.derived_keys.get(name)
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn rotate(&mut self) {
        let new_key = Key::generate(self.key.len()).expect("Failed to generate new key");
        self.key = new_key;
        for derived_key in self.derived_keys.values_mut() {
            *derived_key = derived_key.rotate_key();
        }
    }
}

impl Drop for KeyAndDerived {
    fn drop(&mut self) {
        self.key.zeroize();
        for derived_key in self.derived_keys.values_mut() {
            derived_key.zeroize();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKey(Zeroizing<Vec<u8>>);

impl DerivedKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn to_key(&self) -> Key {
        Key(self.0.clone())
    }

    pub fn generate(key_size: usize) -> Result<Self, KeyManagementError> {
        let mut key = Zeroizing::new(vec![0u8; key_size]);
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| KeyManagementError::RandomGenerationFailed)?;
        Ok(Self(key))
    }
}

impl Zeroize for DerivedKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ManageKey for DerivedKey {
    fn derive(&self, salt: Option<&[u8]>, info: &[u8], output_length: usize) -> DerivedKey {
        let hk = Hkdf::<Sha3_256>::new(salt, &self.0);
        let mut okm = Zeroizing::new(vec![0u8; output_length]);
        hk.expand(info, &mut okm)
            .expect("HKDF-SHA3-256 should never fail");
        DerivedKey(okm)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn xor(&self, other: &Self) -> Result<Self, KeyManagementError> {
        if self.len() != other.len() {
            return Err(KeyManagementError::InvalidKeyLength);
        }
        let xored = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();
        Ok(DerivedKey(Zeroizing::new(xored)))
    }

    fn rotate_key(&mut self) -> Self {
        Self::generate(self.len()).expect("Failed to generate new derived key")
    }

    fn to_key_and_derived(&self) -> KeyAndDerived {
        KeyAndDerived::new(self.clone().to_key())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key(Zeroizing<Vec<u8>>);

impl Key {
    pub fn generate(key_size: usize) -> Result<Self, KeyManagementError> {
        let mut key = Zeroizing::new(vec![0u8; key_size]);
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| KeyManagementError::RandomGenerationFailed)?;
        Ok(Self(key))
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl From<Key> for Vec<u8> {
    fn from(key: Key) -> Self {
        key.0.to_vec()
    }
}

impl ManageKey for Key {
    fn derive(&self, salt: Option<&[u8]>, info: &[u8], output_length: usize) -> DerivedKey {
        let hk = Hkdf::<Sha3_256>::new(salt, &self.0);
        let mut okm = Zeroizing::new(vec![0u8; output_length]);
        hk.expand(info, &mut okm)
            .expect("HKDF-SHA3-256 should never fail");
        DerivedKey(okm)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn xor(&self, other: &Self) -> Result<Self, KeyManagementError> {
        if self.len() != other.len() {
            return Err(KeyManagementError::InvalidKeyLength);
        }
        let xored = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();
        Ok(Key(Zeroizing::new(xored)))
    }

    fn rotate_key(&mut self) -> Self {
        Self::generate(self.len()).expect("Failed to generate new key")
    }

    fn to_key_and_derived(&self) -> KeyAndDerived {
        KeyAndDerived::new(self.clone())
    }
}

impl ToHex for Key {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for Key {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Vec::from_hex(hex).map(|bytes| Self(Zeroizing::new(bytes)))
    }
}

pub trait ManageKey: Sized + Zeroize {
    fn derive(&self, salt: Option<&[u8]>, info: &[u8], output_length: usize) -> DerivedKey;
    fn rotate_key(&mut self) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn xor(&self, other: &Self) -> Result<Self, KeyManagementError>;
    fn to_key_and_derived(&self) -> KeyAndDerived;
}

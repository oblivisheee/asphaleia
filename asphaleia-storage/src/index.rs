use crate::backup::{Backup, BackupError};
use crate::cache::{CacheConfig, CacheManager};
use crate::fragment::{Fragment, FragmentError, Metadata};
use crate::versioning::VersionControl;
use asphaleia_crypto::hash::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Decompression error: {0}")]
    Decompression(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Version not found")]
    VersionNotFound,
    #[error("Backup error: {0}")]
    BackupError(#[from] BackupError),
    #[error("Fragment error: {0}")]
    FragmentError(#[from] FragmentError),
}

pub struct StorageIndex {
    backup: Backup,
    cache: CacheManager,
    version_control: VersionControl,
}

impl StorageIndex {
    pub fn new(
        cache_config: CacheConfig,
        max_versions: Option<usize>,
    ) -> Result<Self, StorageError> {
        let fragment = Fragment::new("zstd".to_string(), 3, None);
        let backup = Backup::new(fragment, max_versions)?;
        let cache = CacheManager::new(cache_config);
        let version_control = VersionControl::new(max_versions);

        Ok(Self {
            backup,
            cache,
            version_control,
        })
    }

    pub fn insert(
        &mut self,
        value: Vec<u8>,
        key: Option<Sha256>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut fragment = self
            .backup
            .get_latest_version()
            .ok_or(StorageError::VersionNotFound)?
            .clone();
        let key = key.unwrap_or_else(|| Sha256::new(&value));
        let result = fragment.insert(value, key)?;
        let _ = self.cache.insert(fragment.clone());
        self.backup.add_version(fragment.clone())?;
        self.version_control.add_version(fragment);
        Ok(result)
    }

    pub fn get(&mut self, key: &Sha256) -> Result<Vec<u8>, StorageError> {
        if let Some(fragment) = self.cache.get(key) {
            fragment.get(key)?.ok_or(StorageError::KeyNotFound)
        } else {
            let fragment = self
                .backup
                .get_latest_version()
                .ok_or(StorageError::VersionNotFound)?
                .clone();
            let _ = self.cache.insert(fragment.clone());
            fragment.get(key)?.ok_or(StorageError::KeyNotFound)
        }
    }

    pub fn remove(&mut self, key: &Sha256) -> Result<Vec<u8>, StorageError> {
        let mut fragment = self
            .backup
            .get_latest_version()
            .ok_or(StorageError::VersionNotFound)?
            .clone();
        let result = fragment.remove(key).ok_or(StorageError::KeyNotFound)?;
        let _ = self.cache.insert(fragment.clone());
        self.backup.add_version(fragment.clone())?;
        self.version_control.add_version(fragment);
        Ok(result)
    }

    pub fn create_new_version(&mut self) -> Result<(), StorageError> {
        let fragment = self
            .backup
            .get_latest_version()
            .ok_or(StorageError::VersionNotFound)?
            .clone();
        self.backup.add_version(fragment.clone())?;
        Ok(())
    }

    pub fn rollback(&mut self, version: u64) -> Result<Fragment, StorageError> {
        let fragment = self.backup.rollback(version)?;
        self.cache.clear();
        let unwrapped_fragment = fragment.ok_or(StorageError::VersionNotFound)?;
        let _ = self.cache.insert(unwrapped_fragment.clone());
        self.version_control.rollback(version);
        Ok(unwrapped_fragment)
    }

    pub fn save_to_disk(
        &mut self,
        path: &str,
        compression_level: Option<usize>,
    ) -> Result<(), StorageError> {
        Ok(self.backup.save_to_disk(path, compression_level)?)
    }

    pub fn load_from_disk(path: &str, cache_config: CacheConfig) -> Result<Self, StorageError> {
        let backup = Backup::load_from_disk(path)?;
        let mut cache = CacheManager::new(cache_config);
        let _ = cache.load_from_backup(&backup);
        let mut version_control = VersionControl::new(backup.get_max_versions());
        if let Some(fragment) = backup.get_latest_version() {
            version_control.add_version(fragment.clone());
        }
        Ok(Self {
            backup,
            cache,
            version_control,
        })
    }

    pub fn get_metadata(&self) -> Result<&Metadata, StorageError> {
        self.backup
            .get_latest_version()
            .ok_or(StorageError::VersionNotFound)
            .map(|f| f.get_metadata())
    }

    pub fn get_version_history(&self) -> Vec<&Fragment> {
        self.version_control
            .get_history()
            .into_iter()
            .map(|v| &v.fragment)
            .collect()
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn evict_expired_cache(&mut self) {
        self.cache.evict_expired();
    }

    pub fn set_max_versions(&mut self, max_versions: Option<usize>) {
        self.backup.set_max_versions(max_versions);
        self.version_control.set_max_versions(max_versions);
    }

    pub fn get_max_versions(&self) -> Option<usize> {
        self.backup.get_max_versions()
    }

    pub fn clear_history(&mut self) {
        self.backup.clear_history();
        self.version_control.clear_history();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_storage_index_insert_and_get() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value = b"test data".to_vec();
        let key = Sha256::new(&value);

        index.insert(value.clone(), Some(key))?;
        let retrieved = index.get(&key)?;

        assert_eq!(retrieved, value);
        Ok(())
    }

    #[test]
    fn test_storage_index_remove() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value = b"test data".to_vec();
        let key = Sha256::new(&value);

        index.insert(value.clone(), Some(key))?;
        let removed = index.remove(&key)?;

        assert_eq!(removed, value);
        assert!(matches!(index.get(&key), Err(StorageError::KeyNotFound)));
        Ok(())
    }

    #[test]
    fn test_storage_index_rollback() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value1 = b"test data 1".to_vec();
        let value2 = b"test data 2".to_vec();
        let key1 = Sha256::new(&value1);
        let key2 = Sha256::new(&value2);

        index.insert(value1.clone(), Some(key1))?;
        index.create_new_version()?;
        index.insert(value2.clone(), Some(key2))?;
        index.create_new_version()?;
        println!("{}", index.get_version_history().len());
        index.rollback(2)?;

        assert_eq!(index.get(&key1)?, value1);
        assert!(matches!(index.get(&key2), Err(StorageError::KeyNotFound)));
        Ok(())
    }

    #[test]
    fn test_storage_index_save_and_load() -> Result<(), StorageError> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test_storage.bin");
        let path = file_path.to_str().unwrap();

        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value = b"test data".to_vec();
        let key = Sha256::new(&value);

        index.insert(value.clone(), Some(key))?;
        index.save_to_disk(path, None)?;

        let mut loaded_index = StorageIndex::load_from_disk(path, CacheConfig::default())?;
        assert_eq!(loaded_index.get(&key)?, value);

        Ok(())
    }

    #[test]
    fn test_storage_index_metadata_and_version_history() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value1 = b"test data 1".to_vec();
        let value2 = b"test data 2".to_vec();
        let key1 = Sha256::new(&value1);
        let key2 = Sha256::new(&value2);

        index.insert(value1, Some(key1))?;
        index.create_new_version()?;
        index.insert(value2, Some(key2))?;
        index.create_new_version()?;

        let metadata = index.get_metadata()?;
        assert_eq!(metadata.size, 2);

        let history = index.get_version_history();
        assert_eq!(history.len(), 3);
        Ok(())
    }

    #[test]
    fn test_storage_index_cache_operations() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        let value = b"test data".to_vec();
        let key = Sha256::new(&value);

        index.insert(value.clone(), Some(key))?;
        assert_eq!(index.get(&key)?, value);

        index.clear_cache();
        assert_eq!(index.get(&key)?, value);

        std::thread::sleep(Duration::from_secs(2));
        index.evict_expired_cache();
        assert_eq!(index.get(&key)?, value);

        Ok(())
    }

    #[test]
    fn test_storage_index_max_versions() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        index.set_max_versions(Some(3));

        for i in 0..5 {
            let value = format!("test data {}", i).into_bytes();
            index.insert(value, None)?;
            index.create_new_version()?;
        }

        assert_eq!(index.get_version_history().len(), 3);
        assert_eq!(index.get_max_versions(), Some(3));

        index.set_max_versions(Some(5));
        assert_eq!(index.get_max_versions(), Some(5));

        Ok(())
    }

    #[test]
    fn test_storage_index_clear_history() -> Result<(), StorageError> {
        let mut index = StorageIndex::new(CacheConfig::default(), None)?;
        println!("{}", index.get_version_history().len());
        for i in 0..5 {
            let value = format!("test data {}", i).into_bytes();
            index.insert(value, None)?;
            index.create_new_version()?;
            println!("{}", index.get_version_history().len());
        }

        assert_eq!(index.get_version_history().len(), 6);

        index.clear_history();
        assert_eq!(index.get_version_history().len(), 1);

        Ok(())
    }
}

use crate::backup::Backup;
use crate::fragment::Fragment;
use asphaleia_crypto::hash::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Failed to insert fragment: {0}")]
    InsertionError(String),
    #[error("Failed to load from backup: {0}")]
    BackupLoadError(String),
}

pub struct CacheEntry {
    fragment: Fragment,
    last_accessed: Instant,
}

pub struct CacheConfig {
    pub max_size: usize,
    pub ttl: Duration,
    pub eviction_strategy: EvictionStrategy,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1024 * 1024 * 1024,
            ttl: Duration::from_secs(300),
            eviction_strategy: EvictionStrategy::LeastRecentlyUsed,
        }
    }
}
pub enum EvictionStrategy {
    LeastRecentlyUsed,
    FirstInFirstOut,
}

pub struct CacheManager {
    cache: HashMap<Sha256, CacheEntry>,
    config: CacheConfig,
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: HashMap::new(),
            config,
        }
    }

    pub fn get(&mut self, key: &Sha256) -> Option<&Fragment> {
        if let Some(entry) = self.cache.get_mut(key) {
            entry.last_accessed = Instant::now();
            Some(&entry.fragment)
        } else {
            None
        }
    }

    pub fn insert(&mut self, fragment: Fragment) -> Result<(), CacheError> {
        let key = Sha256::new(
            &fragment
                .to_bytes()
                .map_err(|e| CacheError::InsertionError(e.to_string()))?,
        );
        let entry = CacheEntry {
            fragment,
            last_accessed: Instant::now(),
        };

        if self.cache.len() >= self.config.max_size {
            self.evict()?;
        }

        self.cache.insert(key, entry);
        Ok(())
    }

    pub fn remove(&mut self, key: &Sha256) -> Option<Fragment> {
        self.cache.remove(key).map(|entry| entry.fragment)
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, entry| now.duration_since(entry.last_accessed) < self.config.ttl);
    }

    fn evict(&mut self) -> Result<(), CacheError> {
        match self.config.eviction_strategy {
            EvictionStrategy::LeastRecentlyUsed => self.evict_lru(),
            EvictionStrategy::FirstInFirstOut => self.evict_fifo(),
        }
    }

    fn evict_lru(&mut self) -> Result<(), CacheError> {
        if let Some(oldest_key) = self
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| *key)
        {
            self.cache.remove(&oldest_key);
            Ok(())
        } else {
            Err(CacheError::InsertionError(
                "Failed to evict LRU item".to_string(),
            ))
        }
    }

    fn evict_fifo(&mut self) -> Result<(), CacheError> {
        if let Some(first_key) = self.cache.keys().next().cloned() {
            self.cache.remove(&first_key);
            Ok(())
        } else {
            Err(CacheError::InsertionError(
                "Failed to evict FIFO item".to_string(),
            ))
        }
    }

    pub fn load_from_backup(&mut self, backup: &Backup) -> Result<(), CacheError> {
        if let Some(fragment) = backup.get_latest_version() {
            self.insert(fragment.clone())?;
        }
        Ok(())
    }

    pub fn get_size(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn contains_key(&self, key: &Sha256) -> bool {
        self.cache.contains_key(key)
    }

    pub fn update_config(&mut self, config: CacheConfig) {
        self.config = config;
    }
}

use super::{
    compression::{compress_bytes, decompress_bytes},
    fragment::{Fragment, FragmentError},
    versioning::VersionControl,
};

use asphaleia_crypto::hash::Sha256;
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
    time::SystemTime,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::Error),
    #[error("Fragment error: {0}")]
    FragmentError(#[from] FragmentError),
    #[error("No versions found")]
    NoVersionsFound,
}

#[derive(Serialize, Deserialize)]
struct BackupMetadata {
    creation_date: SystemTime,
    fragment_count: usize,
    total_size: usize,
    version_count: usize,
    compression_level: Option<usize>,
    max_versions: Option<usize>,
}

pub struct Backup {
    metadata: BackupMetadata,
    version_control: VersionControl,
    hash: Sha256,
}

impl Backup {
    pub fn new(fragment: Fragment, max_versions: Option<usize>) -> Result<Self, BackupError> {
        let mut version_control = VersionControl::new(max_versions);
        version_control.add_version(fragment.clone());

        let metadata = BackupMetadata {
            creation_date: SystemTime::now(),
            fragment_count: 1,
            total_size: fragment.len(),
            version_count: 1,
            compression_level: None,
            max_versions,
        };

        let hash = Sha256::new(&fragment.to_bytes()?);

        Ok(Self {
            metadata,
            version_control,
            hash,
        })
    }
    //TODO: Fix add_version. Move `self.version_control.add_version(fragment.clone());` to index.rs and adapt.
    pub fn add_version(&mut self, fragment: Fragment) -> Result<(), BackupError> {
        self.version_control.add_version(fragment.clone());
        self.metadata.fragment_count = self.version_control.get_version_count();
        self.metadata.total_size += fragment.len();
        self.metadata.version_count = self.version_control.get_version_count();
        self.update_hash()?;
        Ok(())
    }

    pub fn rollback(&mut self, version: u64) -> Result<Option<Fragment>, BackupError> {
        let result = self.version_control.rollback(version);
        if let Some(fragment) = &result {
            self.metadata.fragment_count = self.version_control.get_version_count();
            self.metadata.total_size = fragment.len();
            self.metadata.version_count = self.version_control.get_version_count();
            self.update_hash()?;
        }
        Ok(result)
    }

    pub fn get_latest_version(&self) -> Option<&Fragment> {
        self.version_control
            .get_latest_version()
            .map(|v| &v.fragment)
    }

    pub fn save_to_disk(&mut self, path: &str, level: Option<usize>) -> Result<(), BackupError> {
        let backup_dir = Path::new(path);
        create_dir_all(backup_dir)?;

        let metadata_path = backup_dir.join("metadata.json");
        let mut metadata_file = File::create(metadata_path)?;
        let metadata_json = serde_json::to_string(&self.metadata)?;
        metadata_file.write_all(metadata_json.as_bytes())?;

        let versions_path = backup_dir.join("versions.bin");
        let mut versions_file = File::create(versions_path)?;
        let versions_data = bincode::serialize(&self.version_control)?;
        let level_compression = level.unwrap_or(3);
        let compressed = compress_bytes(&versions_data, level_compression.try_into().unwrap())?;
        self.metadata.compression_level = Some(level_compression);
        versions_file.write_all(&compressed)?;

        Ok(())
    }

    pub fn load_from_disk(path: &str) -> Result<Self, BackupError> {
        let backup_dir = Path::new(path);

        let metadata_path = backup_dir.join("metadata.json");
        let mut metadata_file = File::open(metadata_path)?;
        let mut metadata_json = String::new();
        metadata_file.read_to_string(&mut metadata_json)?;
        let metadata: BackupMetadata = serde_json::from_str(&metadata_json)?;

        let versions_path = backup_dir.join("versions.bin");
        let mut versions_file = File::open(versions_path)?;
        let mut compressed_versions_data = Vec::new();
        versions_file.read_to_end(&mut compressed_versions_data)?;
        let versions_data = decompress_bytes(&compressed_versions_data)?;
        let version_control: VersionControl = bincode::deserialize(&versions_data)?;

        let latest_fragment = version_control
            .get_latest_version()
            .ok_or(BackupError::NoVersionsFound)?
            .fragment
            .clone();
        let hash = Sha256::new(&latest_fragment.to_bytes()?);

        Ok(Self {
            metadata,
            version_control,
            hash,
        })
    }

    fn update_hash(&mut self) -> Result<(), BackupError> {
        if let Some(latest_version) = self.version_control.get_latest_version() {
            self.hash = Sha256::new(&latest_version.fragment.to_bytes()?);
        }
        Ok(())
    }

    pub fn set_max_versions(&mut self, max_versions: Option<usize>) {
        self.version_control.set_max_versions(max_versions);
        self.metadata.max_versions = max_versions;
    }

    pub fn get_max_versions(&self) -> Option<usize> {
        self.version_control.get_max_versions()
    }

    pub fn clear_history(&mut self) {
        self.version_control.clear_history();
        if let Some(latest_version) = self.version_control.get_latest_version() {
            self.metadata.fragment_count = 1;
            self.metadata.total_size = latest_version.fragment.len();
            self.metadata.version_count = 1;
        }
    }

    pub fn get_history(&self) -> Vec<&Fragment> {
        self.version_control
            .get_history()
            .iter()
            .map(|v| &v.fragment)
            .collect()
    }
}

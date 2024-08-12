use super::compression::{
    compress_bytes, compress_bytes_with_dict, decompress_bytes, decompress_bytes_with_dict,
};
use super::table::Table;
use asphaleia_crypto::hash::Sha256;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FragmentError {
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Decompression error: {0}")]
    DecompressionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Metadata {
    pub creation_date: SystemTime,
    pub last_modified: SystemTime,
    pub compression: String,
    pub compression_level: i32,
    pub compression_dict: Option<Vec<u8>>,
    pub size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fragment {
    table: Table,
    hash: Sha256,
    metadata: Metadata,
}

impl Fragment {
    pub fn new(
        compression: String,
        compression_level: i32,
        compression_dict: Option<Vec<u8>>,
    ) -> Self {
        let table = Table::new();
        let hash = Sha256::new(&table.to_bytes());
        let now = SystemTime::now();
        let metadata = Metadata {
            creation_date: now,
            last_modified: now,
            compression,
            compression_level,
            compression_dict,
            size: 0,
        };
        Self {
            table,
            hash,
            metadata,
        }
    }

    pub fn get_hash(&self) -> &Sha256 {
        &self.hash
    }

    pub fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn insert(
        &mut self,
        value: Vec<u8>,
        key: Sha256,
    ) -> Result<Option<Vec<u8>>, FragmentError> {
        let compressed_value = match &self.metadata.compression_dict {
            Some(dict) => compress_bytes_with_dict(&value, self.metadata.compression_level, dict)
                .map_err(|e| FragmentError::CompressionError(e.to_string()))?,
            None => compress_bytes(&value, self.metadata.compression_level)
                .map_err(|e| FragmentError::CompressionError(e.to_string()))?,
        };
        let result = self.table.insert(compressed_value, key);
        self.update_hash();
        self.metadata.size = self.table.len();
        Ok(result)
    }

    pub fn get(&self, key: &Sha256) -> Result<Option<Vec<u8>>, FragmentError> {
        self.table
            .get(key)
            .map(|compressed_value| match &self.metadata.compression_dict {
                Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string())),
                None => decompress_bytes(compressed_value)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string())),
            })
            .transpose()
    }

    pub fn remove(&mut self, key: &Sha256) -> Option<Vec<u8>> {
        let result = self.table.remove(key);
        self.update_hash();
        self.metadata.size = self.table.len();

        result.map(|compressed| match &self.metadata.compression_dict {
            Some(dict) => {
                decompress_bytes_with_dict(&compressed, dict).expect("Failed to decompress value")
            }
            None => decompress_bytes(&compressed).expect("Failed to decompress value"),
        })
    }

    pub fn contains_key(&self, key: &Sha256) -> bool {
        self.table.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn clear(&mut self) {
        self.table.clear();
        self.update_hash();
        self.metadata.size = 0;
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<(&Sha256, Vec<u8>), FragmentError>> {
        self.table.iter().map(|(key, compressed_value)| {
            let decompressed_value = match &self.metadata.compression_dict {
                Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                None => decompress_bytes(compressed_value)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
            };
            Ok((key, decompressed_value))
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&Sha256, &mut Vec<u8>)> {
        self.table.iter_mut()
    }

    pub fn keys(&self) -> impl Iterator<Item = &Sha256> {
        self.table.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = Result<Vec<u8>, FragmentError>> + '_ {
        self.table
            .values()
            .map(|compressed_value| match &self.metadata.compression_dict {
                Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string())),
                None => decompress_bytes(compressed_value)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string())),
            })
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Vec<u8>> {
        self.table.values_mut()
    }

    pub fn entry(
        &mut self,
        key: Sha256,
    ) -> std::collections::btree_map::Entry<'_, Sha256, Vec<u8>> {
        self.table.entry(key)
    }

    pub fn append(&mut self, other: &mut Fragment) {
        self.table.append(&mut other.table);
        self.update_hash();
        self.metadata.size = self.table.len();
    }

    pub fn range<R>(
        &self,
        range: R,
    ) -> impl Iterator<Item = Result<(&Sha256, Vec<u8>), FragmentError>>
    where
        R: std::ops::RangeBounds<Sha256>,
    {
        self.table.range(range).map(|(key, compressed_value)| {
            let decompressed_value = match &self.metadata.compression_dict {
                Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                None => decompress_bytes(compressed_value)
                    .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
            };
            Ok((key, decompressed_value))
        })
    }

    pub fn range_mut<R>(&mut self, range: R) -> impl Iterator<Item = (&Sha256, &mut Vec<u8>)>
    where
        R: std::ops::RangeBounds<Sha256>,
    {
        self.table.range_mut(range)
    }

    pub fn first_key_value(&self) -> Result<Option<(&Sha256, Vec<u8>)>, FragmentError> {
        self.table
            .first_key_value()
            .map(|(key, compressed_value)| {
                let decompressed_value = match &self.metadata.compression_dict {
                    Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                    None => decompress_bytes(compressed_value)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                };
                Ok((key, decompressed_value))
            })
            .transpose()
    }

    pub fn last_key_value(&self) -> Result<Option<(&Sha256, Vec<u8>)>, FragmentError> {
        self.table
            .last_key_value()
            .map(|(key, compressed_value)| {
                let decompressed_value = match &self.metadata.compression_dict {
                    Some(dict) => decompress_bytes_with_dict(compressed_value, dict)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                    None => decompress_bytes(compressed_value)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                };
                Ok((key, decompressed_value))
            })
            .transpose()
    }

    pub fn first_entry(
        &mut self,
    ) -> Option<std::collections::btree_map::OccupiedEntry<'_, Sha256, Vec<u8>>> {
        self.table.first_entry()
    }

    pub fn last_entry(
        &mut self,
    ) -> Option<std::collections::btree_map::OccupiedEntry<'_, Sha256, Vec<u8>>> {
        self.table.last_entry()
    }

    pub fn pop_first(&mut self) -> Result<Option<(Sha256, Vec<u8>)>, FragmentError> {
        let result = self.table.pop_first();
        self.update_hash();
        self.metadata.size = self.table.len();
        result
            .map(|(key, compressed_value)| {
                let decompressed_value = match &self.metadata.compression_dict {
                    Some(dict) => decompress_bytes_with_dict(&compressed_value, dict)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                    None => decompress_bytes(&compressed_value)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                };
                Ok((key, decompressed_value))
            })
            .transpose()
    }

    pub fn pop_last(&mut self) -> Result<Option<(Sha256, Vec<u8>)>, FragmentError> {
        let result = self.table.pop_last();
        self.update_hash();
        self.metadata.size = self.table.len();
        result
            .map(|(key, compressed_value)| {
                let decompressed_value = match &self.metadata.compression_dict {
                    Some(dict) => decompress_bytes_with_dict(&compressed_value, dict)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                    None => decompress_bytes(&compressed_value)
                        .map_err(|e| FragmentError::DecompressionError(e.to_string()))?,
                };
                Ok((key, decompressed_value))
            })
            .transpose()
    }

    fn update_hash(&mut self) {
        self.hash = Sha256::new(&self.table.to_bytes());
        self.metadata.last_modified = SystemTime::now();
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, FragmentError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.table.to_bytes());
        bytes.extend_from_slice(self.hash.as_bytes());
        bytes.extend_from_slice(&bincode::serialize(&self.metadata)?);
        Ok(bytes)
    }
}

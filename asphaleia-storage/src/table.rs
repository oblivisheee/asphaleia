use asphaleia_crypto::hash::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Table {
    table: BTreeMap<Sha256, Vec<u8>>,
}

impl Table {
    pub fn new() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, value: Vec<u8>, key: Sha256) -> Option<Vec<u8>> {
        self.table.insert(key, value)
    }

    pub fn get(&self, key: &Sha256) -> Option<&Vec<u8>> {
        self.table.get(key)
    }

    pub fn remove(&mut self, key: &Sha256) -> Option<Vec<u8>> {
        self.table.remove(key)
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
        self.table.clear()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Sha256, &Vec<u8>)> {
        self.table.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&Sha256, &mut Vec<u8>)> {
        self.table.iter_mut()
    }

    pub fn keys(&self) -> impl Iterator<Item = &Sha256> {
        self.table.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.table.values()
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

    pub fn append(&mut self, other: &mut Table) {
        self.table.append(&mut other.table)
    }

    pub fn range<R>(&self, range: R) -> impl Iterator<Item = (&Sha256, &Vec<u8>)>
    where
        R: std::ops::RangeBounds<Sha256>,
    {
        self.table.range(range)
    }

    pub fn range_mut<R>(&mut self, range: R) -> impl Iterator<Item = (&Sha256, &mut Vec<u8>)>
    where
        R: std::ops::RangeBounds<Sha256>,
    {
        self.table.range_mut(range)
    }

    pub fn first_key_value(&self) -> Option<(&Sha256, &Vec<u8>)> {
        self.table.first_key_value()
    }

    pub fn last_key_value(&self) -> Option<(&Sha256, &Vec<u8>)> {
        self.table.last_key_value()
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

    pub fn pop_first(&mut self) -> Option<(Sha256, Vec<u8>)> {
        self.table.pop_first()
    }

    pub fn pop_last(&mut self) -> Option<(Sha256, Vec<u8>)> {
        self.table.pop_last()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (key, value) in self.table.iter() {
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }
}

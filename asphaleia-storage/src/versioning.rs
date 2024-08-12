use crate::fragment::Fragment;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Version {
    pub creation_date: u64,
    pub version: u64,
    pub fragment: Fragment,
}

impl Version {
    pub fn new(fragment: Fragment) -> Self {
        Self {
            creation_date: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            version: 1,
            fragment,
        }
    }

    pub fn increment(&mut self) {
        self.version += 1;
        self.creation_date = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
    }
}

#[derive(Serialize, Deserialize)]
pub struct VersionControl {
    versions: Vec<Version>,
    max_versions: Option<usize>,
}

impl VersionControl {
    pub fn new(max_versions: Option<usize>) -> Self {
        let mut versions: Vec<Version> = Vec::new();
        versions.push(Self::genesis_version());

        Self {
            versions,
            max_versions,
        }
    }

    pub fn add_version(&mut self, fragment: Fragment) {
        let new_version = if let Some(last_version) = self.versions.last() {
            let mut version = last_version.clone();
            version.increment();
            version.fragment = fragment;
            version
        } else {
            Version::new(fragment)
        };
        self.versions.push(new_version);

        if let Some(max) = self.max_versions {
            while self.versions.len() > max {
                self.versions.remove(0);
            }
        }
    }

    pub fn get_version(&self, version: u64) -> Option<&Version> {
        self.versions.iter().find(|v| v.version == version)
    }

    fn genesis_version() -> Version {
        Version {
            creation_date: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            version: 0,
            fragment: Fragment::new("zstd  ".to_string(), 3, None),
        }
    }

    pub fn get_latest_version(&self) -> Option<&Version> {
        self.versions.last()
    }

    pub fn rollback(&mut self, version: u64) -> Option<Fragment> {
        if let Some(index) = self.versions.iter().position(|v| v.version == version) {
            let rollback_version = self.versions[index].clone();
            self.versions.truncate(index + 1);
            Some(rollback_version.fragment)
        } else {
            None
        }
    }

    pub fn get_history(&self) -> Vec<&Version> {
        self.versions.iter().collect()
    }

    pub fn get_version_count(&self) -> usize {
        self.versions.len()
    }

    pub fn clear_history(&mut self) {
        if let Some(latest) = self.versions.last().cloned() {
            self.versions.clear();
            self.versions.push(latest);
        }
    }

    pub fn set_max_versions(&mut self, max_versions: Option<usize>) {
        self.max_versions = max_versions;
        if let Some(max) = max_versions {
            while self.versions.len() > max {
                self.versions.remove(0);
            }
        }
    }

    pub fn get_max_versions(&self) -> Option<usize> {
        self.max_versions
    }
}

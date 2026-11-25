use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::StoreError;

#[derive(Clone)]
pub struct BlobStore {
    root: Arc<PathBuf>,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(&self, data: &[u8]) -> Result<String, StoreError> {
        let digest = Sha256::digest(data);
        let id = hex(&digest);
        let path = self.path_for(&id);
        if path.exists() {
            return Ok(id);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self
            .root
            .join("tmp")
            .join(format!("{}-{}", id, Uuid::new_v4()));
        {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            file.write_all(data)?;
            file.sync_all()?;
        }
        fs::rename(&temp, &path)?;
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::Config("invalid blob id".into()));
        }
        let mut file = File::open(self.path_for(id))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn path_for(&self, id: &str) -> PathBuf {
        self.root.join(&id[..2]).join(&id[2..4]).join(id)
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        if valid_id(id) {
            let path = self.path_for(id);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    pub fn copy_to(&self, target: &Path) -> Result<(), StoreError> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(self.root.as_path())? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "tmp" {
                continue;
            }
            let destination = target.join(name);
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &destination)?;
            }
        }
        Ok(())
    }
}

fn copy_dir(source: &Path, target: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_and_reads() {
        let directory = tempfile::tempdir().unwrap();
        let store = BlobStore::new(directory.path()).unwrap();
        let first = store.put(b"hello").unwrap();
        let second = store.put(b"hello").unwrap();
        assert_eq!(first, second);
        assert_eq!(store.get(&first).unwrap(), b"hello");
        assert!(store.get("../etc/passwd").is_err());
    }
}

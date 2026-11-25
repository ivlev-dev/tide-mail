use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::StoreError;

#[derive(Debug, Clone, Default)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub prefix: String,
    pub allow_http: bool,
}

enum Backend {
    Local(PathBuf),
    S3 {
        store: Arc<dyn ObjectStore>,
        runtime: tokio::runtime::Runtime,
        prefix: String,
    },
}

#[derive(Clone)]
pub struct BlobStore {
    backend: Arc<Backend>,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            backend: Arc::new(Backend::Local(root)),
        })
    }

    pub fn s3(config: S3Config) -> Result<Self, StoreError> {
        if config.bucket.is_empty() {
            return Err(StoreError::Config("S3 bucket is empty".into()));
        }
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(config.bucket.clone())
            .with_region(config.region.clone());
        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint.clone());
        }
        if let Some(key) = &config.access_key_id {
            builder = builder.with_access_key_id(key.clone());
        }
        if let Some(secret) = &config.secret_access_key {
            builder = builder.with_secret_access_key(secret.clone());
        }
        if config.allow_http {
            builder = builder.with_allow_http(true);
        }
        let store = builder
            .build()
            .map_err(|error| StoreError::Internal(error.to_string()))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(StoreError::Io)?;
        Ok(Self {
            backend: Arc::new(Backend::S3 {
                store: Arc::new(store),
                runtime,
                prefix: config.prefix.trim_matches('/').to_string(),
            }),
        })
    }

    pub fn put(&self, data: &[u8]) -> Result<String, StoreError> {
        let id = hash(data);
        match self.backend.as_ref() {
            Backend::Local(root) => {
                let path = local_path(root, &id);
                if path.exists() {
                    return Ok(id);
                }
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let temp = root.join("tmp").join(format!("{}-{}", id, Uuid::new_v4()));
                {
                    let mut file = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&temp)?;
                    file.write_all(data)?;
                    file.sync_all()?;
                }
                fs::rename(&temp, &path)?;
            }
            Backend::S3 {
                store,
                runtime,
                prefix,
            } => {
                runtime
                    .block_on(store.put(&object_path(prefix, &id), data.to_vec().into()))
                    .map_err(|error| StoreError::Internal(error.to_string()))?;
            }
        }
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::Config("invalid blob id".into()));
        }
        match self.backend.as_ref() {
            Backend::Local(root) => {
                let mut file = File::open(local_path(root, id))?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(data)
            }
            Backend::S3 {
                store,
                runtime,
                prefix,
            } => runtime
                .block_on(async {
                    let result = store.get(&object_path(prefix, id)).await?;
                    result.bytes().await
                })
                .map(|bytes| bytes.to_vec())
                .map_err(|error| StoreError::Internal(error.to_string())),
        }
    }

    pub fn path_for(&self, id: &str) -> Option<PathBuf> {
        match self.backend.as_ref() {
            Backend::Local(root) => Some(local_path(root, id)),
            Backend::S3 { .. } => None,
        }
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        if !valid_id(id) {
            return Ok(());
        }
        match self.backend.as_ref() {
            Backend::Local(root) => {
                let path = local_path(root, id);
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
            Backend::S3 {
                store,
                runtime,
                prefix,
            } => {
                runtime
                    .block_on(store.delete(&object_path(prefix, id)))
                    .map_err(|error| StoreError::Internal(error.to_string()))?;
            }
        }
        Ok(())
    }

    pub fn list_ids(&self) -> Result<Vec<String>, StoreError> {
        match self.backend.as_ref() {
            Backend::Local(root) => {
                let mut ids = Vec::new();
                for first in fs::read_dir(root)? {
                    let first = first?;
                    if !first.file_type()?.is_dir() || first.file_name() == "tmp" {
                        continue;
                    }
                    for second in fs::read_dir(first.path())? {
                        let second = second?;
                        if !second.file_type()?.is_dir() {
                            continue;
                        }
                        for entry in fs::read_dir(second.path())? {
                            let entry = entry?;
                            let name = entry.file_name().to_string_lossy().to_string();
                            if valid_id(&name) {
                                ids.push(name);
                            }
                        }
                    }
                }
                Ok(ids)
            }
            Backend::S3 {
                store,
                runtime,
                prefix,
            } => {
                let prefix_path = if prefix.is_empty() {
                    None
                } else {
                    Some(ObjectPath::from(prefix.as_str()))
                };
                runtime
                    .block_on(async {
                        let mut stream = store.list(prefix_path.as_ref());
                        let mut ids = Vec::new();
                        while let Some(item) = stream.next().await {
                            let meta = item?;
                            let name = meta.location.filename().unwrap_or_default().to_string();
                            if valid_id(&name) {
                                ids.push(name);
                            }
                        }
                        Ok::<_, object_store::Error>(ids)
                    })
                    .map_err(|error| StoreError::Internal(error.to_string()))
            }
        }
    }

    pub fn modified(&self, id: &str) -> Result<SystemTime, StoreError> {
        match self.backend.as_ref() {
            Backend::Local(root) => Ok(fs::metadata(local_path(root, id))?.modified()?),
            Backend::S3 {
                store,
                runtime,
                prefix,
            } => {
                let meta = runtime
                    .block_on(store.head(&object_path(prefix, id)))
                    .map_err(|error| StoreError::Internal(error.to_string()))?;
                let seconds = meta.last_modified.timestamp().max(0) as u64;
                Ok(UNIX_EPOCH + Duration::from_secs(seconds))
            }
        }
    }

    pub fn copy_to(&self, target: &Path) -> Result<(), StoreError> {
        match self.backend.as_ref() {
            Backend::Local(root) => {
                fs::create_dir_all(target)?;
                for entry in fs::read_dir(root)? {
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
            Backend::S3 { .. } => {
                fs::create_dir_all(target)?;
                for id in self.list_ids()? {
                    let data = self.get(&id)?;
                    let destination = target.join(&id[..2]).join(&id[2..4]);
                    fs::create_dir_all(&destination)?;
                    fs::write(destination.join(&id), data)?;
                }
                Ok(())
            }
        }
    }
}

fn local_path(root: &Path, id: &str) -> PathBuf {
    root.join(&id[..2]).join(&id[2..4]).join(id)
}

fn object_path(prefix: &str, id: &str) -> ObjectPath {
    if prefix.is_empty() {
        ObjectPath::from(id)
    } else {
        ObjectPath::from(format!("{prefix}/{id}"))
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

fn hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex(&digest)
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

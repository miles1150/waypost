use crate::error::Result;
pub(crate) mod driver;
pub(crate) mod migrations;
pub(crate) mod queries;
pub(crate) mod rows;

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub size: u64,
    pub sha256: Vec<u8>,
    pub content_type: String,
}
#[allow(async_fn_in_trait)]
pub trait ObjectStore {
    async fn create_only(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: &str,
        expected_sha256: &[u8],
    ) -> Result<ObjectInfo>;
    async fn inspect(&self, key: &str) -> Result<Option<ObjectInfo>>;
    async fn read(&self, key: &str) -> Result<Vec<u8>>;
    async fn remove(&self, key: &str) -> Result<()>;
}

/// For products without blob storage (the keys product). Every call fails.
pub struct NoObjects;
impl ObjectStore for NoObjects {
    async fn create_only(&self, _: &str, _: &[u8], _: &str, _: &[u8]) -> Result<ObjectInfo> {
        Err(crate::error::Error::not_found())
    }
    async fn inspect(&self, _: &str) -> Result<Option<ObjectInfo>> {
        Err(crate::error::Error::not_found())
    }
    async fn read(&self, _: &str) -> Result<Vec<u8>> {
        Err(crate::error::Error::not_found())
    }
    async fn remove(&self, _: &str) -> Result<()> {
        Err(crate::error::Error::not_found())
    }
}

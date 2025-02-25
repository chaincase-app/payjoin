use std::path::Path;
use std::sync::Arc;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use payjoin::receive::PersisterId;
use payjoin::traits::Persister;
use serde::Serialize;
use sled::IVec;

pub(crate) mod error;
use error::*;

pub(crate) const DB_PATH: &str = "payjoin.sled";

pub(crate) struct Database(sled::Db);

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self(db))
    }

    /// Inserts the input and returns true if the input was seen before, false otherwise.
    pub(crate) fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let key = serialize(&input);
        let was_seen_before = self.0.insert(key.as_slice(), IVec::from(vec![]))?.is_some();
        self.0.flush()?;
        Ok(was_seen_before)
    }
}

#[derive(Clone)]
pub(crate) struct ReciverPersister(pub(crate) Arc<Database>);
impl Persister for ReciverPersister {
    type Key = PersisterId;
    type Error = crate::db::error::Error;
    fn save<T: Serialize>(&self, key: Self::Key, value: T) -> std::result::Result<(), Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions_history")?;
        let value = serde_json::to_string(&value).map_err(Error::Serialize)?;
        let key_bytes = key.to_bytes().map_err(Error::BitcoinConsensus)?;
        recv_tree.insert(key_bytes.as_slice(), IVec::from(value.as_str()))?;
        recv_tree.flush()?;
        Ok(())
    }
}

#[cfg(feature = "v2")]
mod v2;

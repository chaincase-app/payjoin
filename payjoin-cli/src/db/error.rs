use std::fmt;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::bitcoin;
use sled::Error as SledError;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) enum Error {
    BitcoinConsensus(bitcoin::consensus::encode::Error),
    Sled(SledError),
    Serialize(serde_json::Error),
    #[cfg(feature = "v2")]
    Deserialize(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BitcoinConsensus(e) => write!(f, "Bitcoin consensus error: {}", e),
            Error::Sled(e) => write!(f, "Database operation failed: {}", e),
            Error::Serialize(e) => write!(f, "Serialization failed: {}", e),
            #[cfg(feature = "v2")]
            Error::Deserialize(e) => write!(f, "Deserialization failed: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<SledError> for Error {
    fn from(error: SledError) -> Self { Error::Sled(error) }
}

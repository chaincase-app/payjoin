use std::error::Error;
use std::fmt::{self, Display};

/// Trait for types that can be serialized and deserialized
/// This trait is used to save and load types to and from a persistance layer.
pub trait Persistable: Sized {
    type Key;
    /// Serialize the type and return a tuple of the key and the serialized data.
    fn save(&self) -> Result<(Self::Key, Vec<u8>), PersistableError>;
    /// Deserialize the type from the serialized data.
    fn load(data: &[u8]) -> Result<Self, PersistableError>;
}

/// Error type for `Persistable` implementations
#[derive(Debug)]
pub enum PersistableError {
    Serialization(serde_json::Error),
    Io(std::io::Error),
}

impl Error for PersistableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl Display for PersistableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(e) => write!(f, "Serialization error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

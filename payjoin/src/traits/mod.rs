use serde::Serialize;

/// Trait for types that can save and load types to and from a persistance layer.
pub trait Persister: Sized {
    type Key;
    type Error: std::error::Error + Send + Sync + 'static;
    fn save<T: Serialize>(&self, key: Self::Key, value: T) -> Result<(), Self::Error>;
}

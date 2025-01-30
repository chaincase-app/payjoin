use core::fmt;
use std::error;

use super::Error;
use crate::hpke::HpkeError;
use crate::ohttp::OhttpEncapsulationError;
use crate::receive::JsonError;

/// Error that may occur during a v2 session typestate change
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SessionError(InternalSessionError);

impl From<InternalSessionError> for SessionError {
    fn from(value: InternalSessionError) -> Self { SessionError(value) }
}

impl From<InternalSessionError> for super::Error {
    fn from(e: InternalSessionError) -> Self { super::Error::Validation(e.into()) }
}

#[derive(Debug)]
pub(crate) enum InternalSessionError {
    /// Url parsing failed
    ParseUrl(crate::into_url::Error),
    /// The session has expired
    Expired(std::time::SystemTime),
    /// OHTTP Encapsulation failed
    OhttpEncapsulation(OhttpEncapsulationError),
    /// Hybrid Public Key Encryption failed
    Hpke(HpkeError),
    /// Unexpected response size
    UnexpectedResponseSize(usize),
    /// Unexpected status code
    UnexpectedStatusCode(http::StatusCode),
}

impl From<crate::into_url::Error> for SessionError {
    fn from(e: crate::into_url::Error) -> Self { InternalSessionError::ParseUrl(e).into() }
}

impl From<std::time::SystemTime> for Error {
    fn from(e: std::time::SystemTime) -> Self { InternalSessionError::Expired(e).into() }
}

impl From<OhttpEncapsulationError> for Error {
    fn from(e: OhttpEncapsulationError) -> Self {
        InternalSessionError::OhttpEncapsulation(e).into()
    }
}

impl From<HpkeError> for Error {
    fn from(e: HpkeError) -> Self { InternalSessionError::Hpke(e).into() }
}

impl JsonError for SessionError {
    fn to_json(&self) -> String {
        use InternalSessionError::*;

        use crate::receive::error::serialize_json_error;
        match &self.0 {
            ParseUrl(e) => serialize_json_error("url-error", e),
            Expired(_) => serialize_json_error("session-expired", self),
            OhttpEncapsulation(_) => serialize_json_error("ohttp-encapsulation-error", self),
            Hpke(_) => serialize_json_error("hpke-error", self),
            UnexpectedResponseSize(_) => serialize_json_error("unexpected-response-size", self),
            UnexpectedStatusCode(_) => serialize_json_error("unexpected-status-code", self),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSessionError::ParseUrl(e) => write!(f, "URL parsing failed: {}", e),
            InternalSessionError::Expired(expiry) => write!(f, "Session expired at {:?}", expiry),
            InternalSessionError::OhttpEncapsulation(e) =>
                write!(f, "OHTTP Encapsulation Error: {}", e),
            InternalSessionError::Hpke(e) => write!(f, "Hpke decryption failed: {}", e),
            InternalSessionError::UnexpectedResponseSize(size) => write!(
                f,
                "Unexpected response size {}, expected {} bytes",
                size,
                crate::directory::ENCAPSULATED_MESSAGE_BYTES
            ),
            InternalSessionError::UnexpectedStatusCode(status) =>
                write!(f, "Unexpected status code: {}", status),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalSessionError::ParseUrl(e) => Some(e),
            InternalSessionError::Expired(_) => None,
            InternalSessionError::OhttpEncapsulation(e) => Some(e),
            InternalSessionError::Hpke(e) => Some(e),
            InternalSessionError::UnexpectedResponseSize(_) => None,
            InternalSessionError::UnexpectedStatusCode(_) => None,
        }
    }
}

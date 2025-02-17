//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.

use reqwest::{Client, Proxy};

use crate::{OhttpKeys, Url};

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
pub async fn fetch_ohttp_keys(
    ohttp_relay: Url,
    payjoin_directory: Url,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.join(".well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.as_str())?;
    let client = Client::builder().proxy(proxy).build()?;
    let res = client.get(ohttp_keys_url).send().await?;
    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| Error(InternalError::InvalidOhttpKeys(e.to_string())))
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
#[cfg(feature = "_danger-local-https")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: Url,
    payjoin_directory: Url,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.join(".well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.as_str())?;
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(&cert_der)?)
        .proxy(proxy)
        .build()?;
    let res = client.get(ohttp_keys_url).send().await?;
    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| Error(InternalError::InvalidOhttpKeys(e.to_string())))
}

#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
enum InternalError {
    ParseUrl(crate::ParseError),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "_danger-local-https")]
    Rustls(rustls::Error),
    InvalidOhttpKeys(String),
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self { Self(InternalError::$to(value)) }
        }
    };
}

impl_from_error!(reqwest::Error, Reqwest);
impl_from_error!(crate::ParseError, ParseUrl);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "_danger-local-https")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            InvalidOhttpKeys(e) => {
                write!(f, "Invalid ohttp keys returned from payjoin directory: {}", e)
            }
            #[cfg(feature = "_danger-local-https")]
            Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => Some(e),
            ParseUrl(e) => Some(e),
            Io(e) => Some(e),
            InvalidOhttpKeys(_) => None,
            #[cfg(feature = "_danger-local-https")]
            Rustls(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self(value) }
}

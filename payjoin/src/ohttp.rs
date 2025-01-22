use std::ops::{Deref, DerefMut};
use std::{error, fmt};

use bitcoin::bech32::{self, EncodeError};
use bitcoin::key::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;

pub const ENCAPSULATED_MESSAGE_BYTES: usize = 8192;
const N_ENC: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE;
const N_T: usize = crate::hpke::POLY1305_TAG_SIZE;
const OHTTP_REQ_HEADER_BYTES: usize = 7;
pub const PADDED_BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (N_ENC + N_T + OHTTP_REQ_HEADER_BYTES);

pub(crate) fn ohttp_encapsulate(
    ohttp_keys: &mut ohttp::KeyConfig,
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<([u8; ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse), OhttpEncapsulationError> {
    use std::fmt::Write;

    let ctx = ohttp::ClientRequest::from_config(ohttp_keys)?;
    let url = url::Url::parse(target_resource)?;
    let authority_bytes = url.host().map_or_else(Vec::new, |host| {
        let mut authority = host.to_string();
        if let Some(port) = url.port() {
            write!(authority, ":{}", port).unwrap();
        }
        authority.into_bytes()
    });
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        url.path().as_bytes().to_vec(),
    );
    // None of our messages include headers, so we don't add them
    if let Some(body) = body {
        bhttp_message.write_content(body);
    }

    let mut bhttp_req = [0u8; PADDED_BHTTP_REQ_BYTES];
    let _ = bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req.as_mut_slice());
    let (encapsulated, ohttp_ctx) = ctx.encapsulate(&bhttp_req)?;

    let mut buffer = [0u8; ENCAPSULATED_MESSAGE_BYTES];
    let len = encapsulated.len().min(ENCAPSULATED_MESSAGE_BYTES);
    buffer[..len].copy_from_slice(&encapsulated[..len]);
    Ok((buffer, ohttp_ctx))
}

/// decapsulate ohttp, bhttp response and return http response body and status code
pub(crate) fn ohttp_decapsulate(
    res_ctx: ohttp::ClientResponse,
    ohttp_body: &[u8; ENCAPSULATED_MESSAGE_BYTES],
) -> Result<http::Response<Vec<u8>>, OhttpEncapsulationError> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let m: bhttp::Message = bhttp::Message::read_bhttp(&mut r)?;
    let mut builder = http::Response::builder();
    for field in m.header().iter() {
        builder = builder.header(field.name(), field.value());
    }
    builder
        .status(m.control().status().unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR.into()))
        .body(m.content().to_vec())
        .map_err(OhttpEncapsulationError::Http)
}

/// Error from de/encapsulating an Oblivious HTTP request or response.
#[derive(Debug)]
pub(crate) enum OhttpEncapsulationError {
    Http(http::Error),
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
}

impl From<http::Error> for OhttpEncapsulationError {
    fn from(value: http::Error) -> Self { Self::Http(value) }
}

impl From<ohttp::Error> for OhttpEncapsulationError {
    fn from(value: ohttp::Error) -> Self { Self::Ohttp(value) }
}

impl From<bhttp::Error> for OhttpEncapsulationError {
    fn from(value: bhttp::Error) -> Self { Self::Bhttp(value) }
}

impl From<url::ParseError> for OhttpEncapsulationError {
    fn from(value: url::ParseError) -> Self { Self::ParseUrl(value) }
}

impl fmt::Display for OhttpEncapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => e.fmt(f),
            Ohttp(e) => e.fmt(f),
            Bhttp(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
        }
    }
}

impl error::Error for OhttpEncapsulationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => Some(e),
            Ohttp(e) => Some(e),
            Bhttp(e) => Some(e),
            ParseUrl(e) => Some(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OhttpKeys(pub ohttp::KeyConfig);

impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: &[u8]) -> Result<Self, ohttp::Error> {
        ohttp::KeyConfig::decode(bytes).map(Self)
    }
}

const KEM_ID: &[u8] = b"\x00\x16"; // DHKEM(secp256k1, HKDF-SHA256)
const SYMMETRIC_LEN: &[u8] = b"\x00\x04"; // 4 bytes
const SYMMETRIC_KDF_AEAD: &[u8] = b"\x00\x01\x00\x03"; // KDF(HKDF-SHA256), AEAD(ChaCha20Poly1305)

impl fmt::Display for OhttpKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.encode().map_err(|_| fmt::Error)?;
        let key_id = bytes[0];
        let pubkey = &bytes[3..68];

        let compressed_pubkey =
            bitcoin::secp256k1::PublicKey::from_slice(pubkey).map_err(|_| fmt::Error)?.serialize();

        let mut buf = vec![key_id];
        buf.extend_from_slice(&compressed_pubkey);

        let oh_hrp: bech32::Hrp = bech32::Hrp::parse("OH").unwrap();

        crate::bech32::nochecksum::encode_to_fmt(f, oh_hrp, &buf).map_err(|e| match e {
            EncodeError::Fmt(e) => e,
            _ => fmt::Error,
        })
    }
}

impl TryFrom<&[u8]> for OhttpKeys {
    type Error = ParseOhttpKeysError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let key_id = *bytes.first().ok_or(ParseOhttpKeysError::InvalidFormat)?;
        let compressed_pk = bytes.get(1..34).ok_or(ParseOhttpKeysError::InvalidFormat)?;

        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(compressed_pk)
            .map_err(|_| ParseOhttpKeysError::InvalidPublicKey)?;

        let mut buf = vec![key_id];
        buf.extend_from_slice(KEM_ID);
        buf.extend_from_slice(&pubkey.serialize_uncompressed());
        buf.extend_from_slice(SYMMETRIC_LEN);
        buf.extend_from_slice(SYMMETRIC_KDF_AEAD);

        ohttp::KeyConfig::decode(&buf).map(Self).map_err(ParseOhttpKeysError::DecodeKeyConfig)
    }
}

impl std::str::FromStr for OhttpKeys {
    type Err = ParseOhttpKeysError;

    /// Parses a base64URL-encoded string into OhttpKeys.
    /// The string format is: key_id || compressed_public_key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO extract to utility function
        let oh_hrp: bech32::Hrp = bech32::Hrp::parse("OH").unwrap();

        let (hrp, bytes) =
            crate::bech32::nochecksum::decode(s).map_err(ParseOhttpKeysError::DecodeBech32)?;

        if hrp != oh_hrp {
            return Err(ParseOhttpKeysError::InvalidFormat);
        }

        Self::try_from(&bytes[..])
    }
}

impl PartialEq for OhttpKeys {
    fn eq(&self, other: &Self) -> bool {
        match (self.encode(), other.encode()) {
            (Ok(self_encoded), Ok(other_encoded)) => self_encoded == other_encoded,
            // If OhttpKeys::encode(&self) is Err, return false
            _ => false,
        }
    }
}

impl Eq for OhttpKeys {}

impl Deref for OhttpKeys {
    type Target = ohttp::KeyConfig;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for OhttpKeys {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<'de> serde::Deserialize<'de> for OhttpKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        OhttpKeys::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for OhttpKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.encode().map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }
}

#[derive(Debug)]
pub enum ParseOhttpKeysError {
    InvalidFormat,
    InvalidPublicKey,
    DecodeBech32(bech32::primitives::decode::CheckedHrpstringError),
    DecodeKeyConfig(ohttp::Error),
}

impl std::fmt::Display for ParseOhttpKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseOhttpKeysError::InvalidFormat => write!(f, "Invalid format"),
            ParseOhttpKeysError::InvalidPublicKey => write!(f, "Invalid public key"),
            ParseOhttpKeysError::DecodeBech32(e) => write!(f, "Failed to decode base64: {}", e),
            ParseOhttpKeysError::DecodeKeyConfig(e) => {
                write!(f, "Failed to decode KeyConfig: {}", e)
            }
        }
    }
}

impl std::error::Error for ParseOhttpKeysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseOhttpKeysError::DecodeBech32(e) => Some(e),
            ParseOhttpKeysError::DecodeKeyConfig(e) => Some(e),
            ParseOhttpKeysError::InvalidFormat | ParseOhttpKeysError::InvalidPublicKey => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ohttp_keys_roundtrip() {
        use std::str::FromStr;

        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::K256Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let keys = OhttpKeys(ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized = &keys.to_string();
        let deserialized = OhttpKeys::from_str(serialized).unwrap();
        assert_eq!(keys.encode().unwrap(), deserialized.encode().unwrap());
    }
}

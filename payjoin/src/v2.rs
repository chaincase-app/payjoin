use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::{error, fmt};

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};

pub const PADDED_MESSAGE_BYTES: usize = 7168; // 7KB

// Bech32 Human Readable Part for OHTTP
pub const OH_HRP: &str = "oh";
// Bech32 Human Readable Part for a Public Key
pub const PK_HRP: &str = "pk";

pub fn subdir(path: &str) -> String {
    let subdirectory: String;

    if let Some(pos) = path.rfind('/') {
        subdirectory = path[pos + 1..].to_string();
    } else {
        subdirectory = path.to_string();
    }

    let pubkey_id: String;

    if let Some(pos) = subdirectory.find('?') {
        pubkey_id = subdirectory[..pos].to_string();
    } else {
        pubkey_id = subdirectory;
    }
    pubkey_id
}

pub(crate) fn encode_bech32_pubkey(pubkey: &PublicKey) -> String {
    encode_bech32(&pubkey.serialize(), PK_HRP)
        .expect("unlikely bech32 encoding failed, using static HRP and PublicKey has max size")
}

fn encode_bech32(bytes: &[u8], expected_hrp: &str) -> Result<String, bech32::EncodeError> {
    use bech32::*;
    let hrp = Hrp::parse(expected_hrp).expect("Invalid static hrp");
    bech32::encode::<Bech32m>(hrp, bytes)
}

pub(crate) fn decode_bech32_pubkey(encoded: &str) -> Result<Vec<u8>, DecodeBech32Error> {
    decode_bech32(encoded, PK_HRP)
}

fn decode_bech32(encoded: &str, expected_hrp: &str) -> Result<Vec<u8>, DecodeBech32Error> {
    let (hrp, data) = bech32::decode(encoded)?;
    if hrp.as_str() != expected_hrp {
        Err(DecodeBech32Error::MismatchedHrp(hrp.to_string(), expected_hrp.to_string()))
    } else {
        Ok(data)
    }
}

#[derive(Debug)]
pub enum DecodeBech32Error {
    // The human readable part of the bech32 string did not match the expected value
    MismatchedHrp(String, String),
    // The bech32 string could not be decoded
    Decode(bech32::DecodeError),
}

impl fmt::Display for DecodeBech32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeBech32Error::*;

        match &self {
            MismatchedHrp(expected, actual) =>
                write!(f, "Expected HRP: {}, got: {}", expected, actual),
            Decode(e) => e.fmt(f),
        }
    }
}

impl error::Error for DecodeBech32Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use DecodeBech32Error::*;

        match &self {
            MismatchedHrp(_, _) => None,
            Decode(e) => Some(e),
        }
    }
}

impl From<bech32::DecodeError> for DecodeBech32Error {
    fn from(value: bech32::DecodeError) -> Self { Self::Decode(value) }
}

/// crypto context
///
/// <- Receiver S
/// -> Sender E, ES(payload), payload protected by knowledge of receiver key
/// <- Receiver E, EE(payload), payload protected by knowledge of sender & receiver key
#[cfg(feature = "send")]
pub fn encrypt_message_a(
    mut raw_msg: Vec<u8>,
    e_sec: SecretKey,
    s: PublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let secp = Secp256k1::new();
    let e_pub = e_sec.public_key(&secp);
    let es = SharedSecret::new(&s, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let msg = pad(&mut raw_msg)?;
    let payload = Payload { msg, aad };
    let c_t: Vec<u8> = cipher.encrypt(&nonce, payload)?;
    let mut message_a = e_pub.serialize().to_vec();
    message_a.extend(&nonce[..]);
    message_a.extend(&c_t[..]);
    Ok(message_a)
}

#[cfg(feature = "receive")]
pub fn decrypt_message_a(
    message_a: &[u8],
    s: SecretKey,
) -> Result<(Vec<u8>, PublicKey), HpkeError> {
    // let message a = [pubkey/AD][nonce][authentication tag][ciphertext]
    let e = PublicKey::from_slice(message_a.get(..33).ok_or(HpkeError::PayloadTooShort)?)?;
    let nonce = Nonce::from_slice(message_a.get(33..45).ok_or(HpkeError::PayloadTooShort)?);
    let es = SharedSecret::new(&e, &s);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let c_t = message_a.get(45..).ok_or(HpkeError::PayloadTooShort)?;
    let aad = &e.serialize();
    let payload = Payload { msg: c_t, aad };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok((buffer, e))
}

#[cfg(feature = "receive")]
pub fn encrypt_message_b(raw_msg: &mut Vec<u8>, re_pub: PublicKey) -> Result<Vec<u8>, HpkeError> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let ee = SharedSecret::new(&re_pub, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(&[0u8; 12]); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let msg = pad(raw_msg)?;
    let payload = Payload { msg, aad };
    let c_t = cipher.encrypt(nonce, payload)?;
    let mut message_b = e_pub.serialize().to_vec();
    message_b.extend(&nonce[..]);
    message_b.extend(&c_t[..]);
    Ok(message_b)
}

#[cfg(feature = "send")]
pub fn decrypt_message_b(message_b: &mut [u8], e: SecretKey) -> Result<Vec<u8>, HpkeError> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let re = PublicKey::from_slice(message_b.get(..33).ok_or(HpkeError::PayloadTooShort)?)?;
    let nonce = Nonce::from_slice(message_b.get(33..45).ok_or(HpkeError::PayloadTooShort)?);
    let ee = SharedSecret::new(&re, &e);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let payload = Payload {
        msg: message_b.get(45..).ok_or(HpkeError::PayloadTooShort)?,
        aad: &re.serialize(),
    };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok(buffer)
}

fn pad(msg: &mut Vec<u8>) -> Result<&[u8], HpkeError> {
    if msg.len() > PADDED_MESSAGE_BYTES {
        return Err(HpkeError::PayloadTooLarge);
    }
    while msg.len() < PADDED_MESSAGE_BYTES {
        msg.push(0);
    }
    Ok(msg)
}

/// Error from de/encrypting a v2 Hybrid Public Key Encryption payload.
#[derive(Debug)]
pub enum HpkeError {
    Secp256k1(bitcoin::secp256k1::Error),
    ChaCha20Poly1305(chacha20poly1305::aead::Error),
    InvalidKeyLength,
    PayloadTooLarge,
    PayloadTooShort,
}

impl From<bitcoin::secp256k1::Error> for HpkeError {
    fn from(value: bitcoin::secp256k1::Error) -> Self { Self::Secp256k1(value) }
}

impl From<chacha20poly1305::aead::Error> for HpkeError {
    fn from(value: chacha20poly1305::aead::Error) -> Self { Self::ChaCha20Poly1305(value) }
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HpkeError::*;

        match &self {
            Secp256k1(e) => e.fmt(f),
            ChaCha20Poly1305(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge =>
                write!(f, "Payload too large, max size is {} bytes", PADDED_MESSAGE_BYTES),
            PayloadTooShort => write!(f, "Payload too small"),
        }
    }
}

impl error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use HpkeError::*;

        match &self {
            Secp256k1(e) => Some(e),
            ChaCha20Poly1305(_) | InvalidKeyLength | PayloadTooLarge | PayloadTooShort => None,
        }
    }
}

pub fn ohttp_encapsulate(
    ohttp_keys: &mut ohttp::KeyConfig,
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<(Vec<u8>, ohttp::ClientResponse), OhttpEncapsulationError> {
    let ctx = ohttp::ClientRequest::from_config(ohttp_keys)?;
    let url = url::Url::parse(target_resource)?;
    let authority_bytes = url.host().map_or_else(Vec::new, |host| {
        let mut authority = host.to_string();
        if let Some(port) = url.port() {
            authority.push_str(&format!(":{}", port));
        }
        authority.into_bytes()
    });
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        url.path().as_bytes().to_vec(),
    );
    if let Some(body) = body {
        bhttp_message.write_content(body);
    }
    let mut bhttp_req = Vec::new();
    let _ = bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req);
    let encapsulated = ctx.encapsulate(&bhttp_req)?;
    Ok(encapsulated)
}

/// decapsulate ohttp, bhttp response and return http response body and status code
pub fn ohttp_decapsulate(
    res_ctx: ohttp::ClientResponse,
    ohttp_body: &[u8],
) -> Result<Vec<u8>, OhttpEncapsulationError> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let response = bhttp::Message::read_bhttp(&mut r)?;
    Ok(response.content().to_vec())
}

/// Error from de/encapsulating an Oblivious HTTP request or response.
#[derive(Debug)]
pub enum OhttpEncapsulationError {
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
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

impl fmt::Display for OhttpKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.encode().map_err(|_| fmt::Error)?;
        let bech32 = encode_bech32(&bytes, OH_HRP).map_err(|_| fmt::Error)?;
        write!(f, "{}", bech32)
    }
}

impl FromStr for OhttpKeys {
    type Err = DecodeOhttpKeysError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_bech32(s, OH_HRP)?;
        Self::decode(&bytes).map_err(DecodeOhttpKeysError::Ohttp)
    }
}

impl<'de> serde::Deserialize<'de> for OhttpKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Ok(OhttpKeys::from_str(&encoded).map_err(serde::de::Error::custom)?)
    }
}

impl serde::Serialize for OhttpKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

#[derive(Debug)]
pub enum DecodeOhttpKeysError {
    DecodeBech32(DecodeBech32Error),
    Ohttp(ohttp::Error),
}

impl fmt::Display for DecodeOhttpKeysError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeOhttpKeysError::*;

        match &self {
            DecodeBech32(e) => e.fmt(f),
            Ohttp(e) => e.fmt(f),
        }
    }
}

impl error::Error for DecodeOhttpKeysError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use DecodeOhttpKeysError::*;

        match &self {
            DecodeBech32(e) => Some(e),
            Ohttp(e) => Some(e),
        }
    }
}

impl From<DecodeBech32Error> for DecodeOhttpKeysError {
    fn from(value: DecodeBech32Error) -> Self { Self::DecodeBech32(value) }
}

impl From<ohttp::Error> for DecodeOhttpKeysError {
    fn from(value: ohttp::Error) -> Self { Self::Ohttp(value) }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ohttp_keys_roundtrip() {
        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::X25519Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let keys = OhttpKeys(ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized = serde_json::to_string(&keys).unwrap();
        let deserialized: OhttpKeys = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keys.encode().unwrap(), deserialized.encode().unwrap());
    }
}

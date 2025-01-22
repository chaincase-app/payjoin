use std::ops::Deref;
use std::{error, fmt};

use bitcoin::key::constants::{
    ELLSWIFT_ENCODING_SIZE, PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
use bitcoin::secp256k1;
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::SecpK256HkdfSha256;
use hpke::rand_core::OsRng;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};

pub const PADDED_MESSAGE_BYTES: usize = 7168;
pub const PADDED_PLAINTEXT_A_LENGTH: usize =
    PADDED_MESSAGE_BYTES - (ELLSWIFT_ENCODING_SIZE + PUBLIC_KEY_SIZE + POLY1305_TAG_SIZE);
pub const PADDED_PLAINTEXT_B_LENGTH: usize =
    PADDED_MESSAGE_BYTES - (ELLSWIFT_ENCODING_SIZE + POLY1305_TAG_SIZE);
pub const POLY1305_TAG_SIZE: usize = 16; // FIXME there is a U16 defined for poly1305, should bitcoin hpke re-export it?
pub const INFO_A: &[u8; 8] = b"PjV2MsgA";
pub const INFO_B: &[u8; 8] = b"PjV2MsgB";

pub type SecretKey = <SecpK256HkdfSha256 as hpke::Kem>::PrivateKey;
pub type PublicKey = <SecpK256HkdfSha256 as hpke::Kem>::PublicKey;
pub type EncappedKey = <SecpK256HkdfSha256 as hpke::Kem>::EncappedKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeyPair(pub HpkeSecretKey, pub HpkePublicKey);

impl From<HpkeKeyPair> for (HpkeSecretKey, HpkePublicKey) {
    fn from(value: HpkeKeyPair) -> Self { (value.0, value.1) }
}

impl HpkeKeyPair {
    pub fn from_secret_key(secret_key: &HpkeSecretKey) -> Self {
        let public_key = <SecpK256HkdfSha256 as hpke::Kem>::sk_to_pk(&secret_key.0);
        Self(secret_key.clone(), HpkePublicKey(public_key))
    }

    pub fn gen_keypair() -> Self {
        let (sk, pk) = <SecpK256HkdfSha256 as hpke::Kem>::gen_keypair(&mut OsRng);
        Self(HpkeSecretKey(sk), HpkePublicKey(pk))
    }
    pub fn secret_key(&self) -> &HpkeSecretKey { &self.0 }
    pub fn public_key(&self) -> &HpkePublicKey { &self.1 }
}

fn pubkey_from_compressed_bytes(pk_bytes: &[u8]) -> Result<HpkePublicKey, HpkeError> {
    let uncompressed_pk_bytes =
        secp256k1::PublicKey::from_slice(pk_bytes)?.serialize_uncompressed();

    Ok(HpkePublicKey(
        PublicKey::from_bytes(&uncompressed_pk_bytes)
            .expect("conversion to uncompressed pubkey must not fail"),
    ))
}

fn compressed_bytes_from_pubkey(pk: &HpkePublicKey) -> [u8; PUBLIC_KEY_SIZE] {
    let reply_pk_uncompressed = pk.to_bytes();
    secp256k1::PublicKey::from_slice(&reply_pk_uncompressed[..])
        .expect("parsing a pubkey immediately after serializing it must not fail")
        .serialize()
}

fn encapped_key_from_ellswift_bytes(encoded: &[u8]) -> Result<EncappedKey, HpkeError> {
    let mut buf = [0u8; ELLSWIFT_ENCODING_SIZE];
    buf.copy_from_slice(encoded);
    let ellswift = ElligatorSwift::from_array(buf);
    let pk = secp256k1::PublicKey::from_ellswift(ellswift);
    Ok(EncappedKey::from_bytes(pk.serialize_uncompressed().as_slice())?)
}

fn ellswift_bytes_from_encapped_key(
    enc: &EncappedKey,
) -> Result<[u8; ELLSWIFT_ENCODING_SIZE], HpkeError> {
    let uncompressed = enc.to_bytes();
    let pk = secp256k1::PublicKey::from_slice(&uncompressed)?;
    let ellswift = ElligatorSwift::from_pubkey(pk);
    Ok(ellswift.to_array())
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkeSecretKey(pub SecretKey);

impl Deref for HpkeSecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkeSecretKey([REDACTED])")
    }
}

impl serde::Serialize for HpkeSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkeSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkeSecretKey(
            SecretKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid secret key"))?,
        ))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkePublicKey(pub PublicKey);

impl HpkePublicKey {
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let compressed_key = secp256k1::PublicKey::from_slice(&self.0.to_bytes())
            .expect("Invalid public key from known valid bytes");
        compressed_key.serialize()
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        let compressed_key = secp256k1::PublicKey::from_slice(bytes)?;
        Ok(HpkePublicKey(PublicKey::from_bytes(
            compressed_key.serialize_uncompressed().as_slice(),
        )?))
    }
}

impl Deref for HpkePublicKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkePublicKey({:?})", self.0)
    }
}

impl serde::Serialize for HpkePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkePublicKey(
            PublicKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid public key"))?,
        ))
    }
}

/// Message A is sent from the sender to the receiver containing an Original PSBT payload
pub fn encrypt_message_a(
    body: &[u8],
    reply_pk: &HpkePublicKey,
    receiver_pk: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Base,
            &receiver_pk.0,
            INFO_A,
            &mut OsRng,
        )?;
    let mut body = body;
    pad_plaintext(&mut body, PADDED_PLAINTEXT_A_LENGTH)?;
    let mut plaintext = compressed_bytes_from_pubkey(reply_pk).to_vec();
    plaintext.extend(body);
    let ciphertext = encryption_context.seal(&plaintext, &[])?;
    let mut message_a = ellswift_bytes_from_encapped_key(&encapsulated_key)?.to_vec();
    message_a.extend(&ciphertext);
    Ok(message_a.to_vec())
}

pub fn decrypt_message_a(
    message_a: &[u8],
    receiver_sk: &HpkeSecretKey,
) -> Result<(Vec<u8>, HpkePublicKey), HpkeError> {
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(message_a);

    let mut enc_bytes = [0u8; ELLSWIFT_ENCODING_SIZE];
    cursor.read_exact(&mut enc_bytes).map_err(|_| HpkeError::PayloadTooShort)?;
    let enc = encapped_key_from_ellswift_bytes(&enc_bytes)?;

    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Base, &receiver_sk.0, &enc, INFO_A)?;

    let mut ciphertext = Vec::new();
    cursor.read_to_end(&mut ciphertext).map_err(|_| HpkeError::PayloadTooShort)?;
    let plaintext = decryption_ctx.open(&ciphertext, &[])?;

    let reply_pk = pubkey_from_compressed_bytes(&plaintext[..PUBLIC_KEY_SIZE])?;

    let body = &plaintext[PUBLIC_KEY_SIZE..];

    Ok((body.to_vec(), reply_pk))
}

/// Message B is sent from the receiver to the sender containing a Payjoin PSBT payload or an error
pub fn encrypt_message_b(
    mut plaintext: &[u8],
    receiver_keypair: &HpkeKeyPair,
    sender_pk: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Auth((
                receiver_keypair.secret_key().0.clone(),
                receiver_keypair.public_key().0.clone(),
            )),
            &sender_pk.0,
            INFO_B,
            &mut OsRng,
        )?;
    let plaintext: &[u8] = pad_plaintext(&mut plaintext, PADDED_PLAINTEXT_B_LENGTH)?;
    let ciphertext = encryption_context.seal(plaintext, &[])?;
    let mut message_b = ellswift_bytes_from_encapped_key(&encapsulated_key)?.to_vec();
    message_b.extend(&ciphertext);
    Ok(message_b.to_vec())
}

pub fn decrypt_message_b(
    message_b: &[u8],
    receiver_pk: &HpkePublicKey,
    sender_sk: &HpkeSecretKey,
) -> Result<Vec<u8>, HpkeError> {
    let enc = message_b.get(..ELLSWIFT_ENCODING_SIZE).ok_or(HpkeError::PayloadTooShort)?;
    let enc = encapped_key_from_ellswift_bytes(enc)?;
    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Auth(receiver_pk.0), &sender_sk.0, &enc, INFO_B)?;
    let plaintext = decryption_ctx
        .open(message_b.get(ELLSWIFT_ENCODING_SIZE..).ok_or(HpkeError::PayloadTooShort)?, &[])?;
    Ok(plaintext)
}

/// Error from de/encrypting a v2 Hybrid Public Key Encryption payload.
#[derive(Debug, PartialEq)]
pub enum HpkeError {
    Secp256k1(secp256k1::Error),
    Hpke(hpke::HpkeError),
    InvalidKeyLength,
    PayloadTooLarge { actual: usize, max: usize },
    PayloadTooShort,
}

impl From<hpke::HpkeError> for HpkeError {
    fn from(value: hpke::HpkeError) -> Self { Self::Hpke(value) }
}

impl From<secp256k1::Error> for HpkeError {
    fn from(value: secp256k1::Error) -> Self { Self::Secp256k1(value) }
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HpkeError::*;

        match &self {
            Hpke(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge { actual, max } => {
                write!(
                    f,
                    "Plaintext too large, max size is {} bytes, actual size is {} bytes",
                    max, actual
                )
            }
            PayloadTooShort => write!(f, "Payload too small"),
            Secp256k1(e) => e.fmt(f),
        }
    }
}

impl error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use HpkeError::*;

        match &self {
            Hpke(e) => Some(e),
            PayloadTooLarge { .. } => None,
            InvalidKeyLength | PayloadTooShort => None,
            Secp256k1(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn message_a_round_trip() {
        let mut plaintext = "foo".as_bytes().to_vec();

        let reply_keypair = HpkeKeyPair::gen_keypair();
        let receiver_keypair = HpkeKeyPair::gen_keypair();

        let message_a = encrypt_message_a(
            plaintext.clone(),
            reply_keypair.public_key(),
            receiver_keypair.public_key(),
        )
        .expect("encryption should work");
        assert_eq!(message_a.len(), PADDED_MESSAGE_BYTES);

        let decrypted = decrypt_message_a(&message_a, receiver_keypair.secret_key().clone())
            .expect("decryption should work");

        assert_eq!(decrypted.0.len(), PADDED_PLAINTEXT_A_LENGTH);

        // decrypted plaintext is padded, so pad the expected plaintext
        plaintext.resize(PADDED_PLAINTEXT_A_LENGTH, 0);
        assert_eq!(decrypted, (plaintext.to_vec(), reply_keypair.public_key().clone()));

        // ensure full plaintext round trips
        plaintext[PADDED_PLAINTEXT_A_LENGTH - 1] = 42;
        let message_a = encrypt_message_a(
            plaintext.clone(),
            reply_keypair.public_key(),
            receiver_keypair.public_key(),
        )
        .expect("encryption should work");

        let decrypted = decrypt_message_a(&message_a, receiver_keypair.secret_key().clone())
            .expect("decryption should work");

        assert_eq!(decrypted.0.len(), plaintext.len());
        assert_eq!(decrypted, (plaintext.to_vec(), reply_keypair.public_key().clone()));

        let unrelated_keypair = HpkeKeyPair::gen_keypair();
        assert_eq!(
            decrypt_message_a(&message_a, unrelated_keypair.secret_key().clone()),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );

        let mut corrupted_message_a = message_a.clone();
        corrupted_message_a[3] ^= 1; // corrupt dhkem
        assert_eq!(
            decrypt_message_a(&corrupted_message_a, receiver_keypair.secret_key().clone()),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );
        let mut corrupted_message_a = message_a.clone();
        corrupted_message_a[PADDED_MESSAGE_BYTES - 3] ^= 1; // corrupt aead ciphertext
        assert_eq!(
            decrypt_message_a(&corrupted_message_a, receiver_keypair.secret_key().clone()),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );

        plaintext.resize(PADDED_PLAINTEXT_A_LENGTH + 1, 0);
        assert_eq!(
            encrypt_message_a(
                plaintext.clone(),
                reply_keypair.public_key(),
                receiver_keypair.public_key(),
            ),
            Err(HpkeError::PayloadTooLarge {
                actual: PADDED_PLAINTEXT_A_LENGTH + 1,
                max: PADDED_PLAINTEXT_A_LENGTH,
            })
        );
    }

    #[test]
    fn message_b_round_trip() {
        let mut plaintext = "foo".as_bytes().to_vec();

        let reply_keypair = HpkeKeyPair::gen_keypair();
        let receiver_keypair = HpkeKeyPair::gen_keypair();

        let message_b =
            encrypt_message_b(plaintext.clone(), &receiver_keypair, reply_keypair.public_key())
                .expect("encryption should work");

        assert_eq!(message_b.len(), PADDED_MESSAGE_BYTES);

        let decrypted = decrypt_message_b(
            &message_b,
            receiver_keypair.public_key().clone(),
            reply_keypair.secret_key().clone(),
        )
        .expect("decryption should work");

        assert_eq!(decrypted.len(), PADDED_PLAINTEXT_B_LENGTH);
        // decrypted plaintext is padded, so pad the expected plaintext
        plaintext.resize(PADDED_PLAINTEXT_B_LENGTH, 0);
        assert_eq!(decrypted, plaintext.to_vec());

        plaintext[PADDED_PLAINTEXT_B_LENGTH - 1] = 42;
        let message_b =
            encrypt_message_b(plaintext.clone(), &receiver_keypair, reply_keypair.public_key())
                .expect("encryption should work");

        assert_eq!(message_b.len(), PADDED_MESSAGE_BYTES);

        let decrypted = decrypt_message_b(
            &message_b,
            receiver_keypair.public_key().clone(),
            reply_keypair.secret_key().clone(),
        )
        .expect("decryption should work");
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted, plaintext.to_vec());

        let unrelated_keypair = HpkeKeyPair::gen_keypair();
        assert_eq!(
            decrypt_message_b(
                &message_b,
                receiver_keypair.public_key().clone(),
                unrelated_keypair.secret_key().clone() // wrong decryption key
            ),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );
        assert_eq!(
            decrypt_message_b(
                &message_b,
                unrelated_keypair.public_key().clone(), // wrong auth key
                reply_keypair.secret_key().clone()
            ),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );

        let mut corrupted_message_b = message_b.clone();
        corrupted_message_b[3] ^= 1; // corrupt dhkem
        assert_eq!(
            decrypt_message_b(
                &corrupted_message_b,
                receiver_keypair.public_key().clone(),
                reply_keypair.secret_key().clone()
            ),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );
        let mut corrupted_message_b = message_b.clone();
        corrupted_message_b[PADDED_MESSAGE_BYTES - 3] ^= 1; // corrupt aead ciphertext
        assert_eq!(
            decrypt_message_b(
                &corrupted_message_b,
                receiver_keypair.public_key().clone(),
                reply_keypair.secret_key().clone()
            ),
            Err(HpkeError::Hpke(hpke::HpkeError::OpenError))
        );

        plaintext.resize(PADDED_PLAINTEXT_B_LENGTH + 1, 0);
        assert_eq!(
            encrypt_message_b(plaintext.clone(), &receiver_keypair, reply_keypair.public_key()),
            Err(HpkeError::PayloadTooLarge {
                actual: PADDED_PLAINTEXT_B_LENGTH + 1,
                max: PADDED_PLAINTEXT_B_LENGTH
            })
        );
    }

    /// Test that the encrypted payloads are uniform.
    ///
    /// This randomized test will generate a false negative with negligible probability
    /// if all encrypted messages share an identical bit at a given position by chance.
    /// It should fail deterministically if any bit position has a fixed value.
    #[test]
    fn test_encrypted_payload_bit_uniformity() {
        fn generate_messages(count: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let mut messages_a = Vec::with_capacity(count);
            let mut messages_b = Vec::with_capacity(count);

            for _ in 0..count {
                let sender_keypair = HpkeKeyPair::gen_keypair();
                let receiver_keypair = HpkeKeyPair::gen_keypair();
                let reply_keypair = HpkeKeyPair::gen_keypair();

                let plaintext_a = vec![0u8; PADDED_PLAINTEXT_A_LENGTH];
                let message_a = encrypt_message_a(
                    plaintext_a,
                    reply_keypair.public_key(),
                    receiver_keypair.public_key(),
                )
                .expect("encryption should work");

                let plaintext_b = vec![0u8; PADDED_PLAINTEXT_B_LENGTH];
                let message_b =
                    encrypt_message_b(plaintext_b, &receiver_keypair, sender_keypair.public_key())
                        .expect("encryption should work");

                messages_a.push(message_a);
                messages_b.push(message_b);
            }

            (messages_a, messages_b)
        }

        /// Compare each message to the first message, XOR the results,
        /// and OR this into an accumulator that starts as all 0x00s.
        fn check_uniformity(messages: Vec<Vec<u8>>) {
            assert!(!messages.is_empty(), "Messages vector should not be empty");
            let reference_message = &messages[0];
            let mut accumulator = vec![0u8; PADDED_MESSAGE_BYTES];

            for message in &messages[1..] {
                assert_eq!(
                    reference_message.len(),
                    message.len(),
                    "Message lengths should be equal"
                );
                for (acc, (&b_ref, &b)) in
                    accumulator.iter_mut().zip(reference_message.iter().zip(message.iter()))
                {
                    *acc |= b_ref ^ b;
                }
            }

            assert!(
                accumulator.iter().all(|&b| b == 0xFF),
                "All bits in the accumulator should be 1"
            );
        }

        let (messages_a, messages_b) = generate_messages(80);
        assert_eq!(messages_a[0].len(), messages_b[0].len());
        check_uniformity(messages_a);
        check_uniformity(messages_b);
    }
}

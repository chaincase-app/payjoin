//! Send BIP 77 Payjoin v2
//!
//! This module contains types and methods used to implement sending via [BIP77
//! Payjoin](https://github.com/bitcoin/bips/pull/1483).
//!
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Construct URI request parameters, a finalized “Original PSBT” paying .amount to .address
//! 3. (optional) Spawn a thread or async task that will broadcast the original PSBT fallback after
//!    delay (e.g. 1 minute) unless canceled
//! 4. Construct the [`Sender`] using [`SenderBuilder`] with the PSBT and payjoin uri
//! 5. Send the request(s) and receive response(s) by following on the extracted Context
//! 6. Sign and finalize the Payjoin Proposal PSBT
//! 7. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be
//! provided by custom implementations or copy the reference
//! [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind,
//! [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or
//! [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own
//! wallet and http client.

use bitcoin::hashes::{sha256, Hash};
pub use error::{CreateRequestError, EncapsulationError};
use error::{InternalCreateRequestError, InternalEncapsulationError};
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::BuildSenderError;
use super::*;
use crate::hpke::{decrypt_message_b, encrypt_message_a, HpkeSecretKey};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate};
use crate::send::v1;
use crate::uri::{ShortId, UrlExt};
use crate::{HpkeKeyPair, HpkePublicKey, IntoUrl, PjUri, Request};

mod error;

#[derive(Clone)]
pub struct SenderBuilder<'a>(v1::SenderBuilder<'a>);

impl<'a> SenderBuilder<'a> {
    /// Prepare the context from which to make Sender requests
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self { Self(v1::SenderBuilder::new(psbt, uri)) }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(self, disable: bool) -> Self {
        Self(self.0.always_disable_output_substitution(disable))
    }

    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(self, min_fee_rate: FeeRate) -> Result<Sender, BuildSenderError> {
        Ok(Sender {
            v1: self.0.build_recommended(min_fee_rate)?,
            reply_key: HpkeKeyPair::gen_keypair().0,
        })
    }

    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. If `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    ///
    /// `clamp_fee_contribution` decreases fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub fn build_with_additional_fee(
        self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
    ) -> Result<Sender, BuildSenderError> {
        Ok(Sender {
            v1: self.0.build_with_additional_fee(
                max_fee_contribution,
                change_index,
                min_fee_rate,
                clamp_fee_contribution,
            )?,
            reply_key: HpkeKeyPair::gen_keypair().0,
        })
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        self,
        min_fee_rate: FeeRate,
    ) -> Result<Sender, BuildSenderError> {
        Ok(Sender {
            v1: self.0.build_non_incentivizing(min_fee_rate)?,
            reply_key: HpkeKeyPair::gen_keypair().0,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender {
    /// The v1 Sender.
    v1: v1::Sender,
    /// The secret key to decrypt the receiver's reply.
    reply_key: HpkeSecretKey,
}

impl Sender {
    /// Extract serialized V1 Request and Context from a Payjoin Proposal
    pub fn extract_v1(&self) -> Result<(Request, v1::V1Context), url::ParseError> {
        self.v1.extract_v1()
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    ///
    /// This method requires the `rs` pubkey to be extracted from the endpoint
    /// and has no fallback to v1.
    pub fn extract_v2(
        &self,
        ohttp_relay: Url,
    ) -> Result<(Request, V2PostContext), CreateRequestError> {
        use crate::hpke::encrypt_message_a;
        use crate::ohttp::ohttp_encapsulate;
        use crate::send::PsbtContext;
        use crate::uri::UrlExt;
        if let Ok(expiry) = self.v1.endpoint.exp() {
            if std::time::SystemTime::now() > expiry {
                return Err(InternalCreateRequestError::Expired(expiry).into());
            }
        }
        let rs = self.extract_rs_pubkey()?;
        let url = self.v1.endpoint.clone();
        let body = serialize_v2_body(
            &self.v1.psbt,
            self.v1.disable_output_substitution,
            self.v1.fee_contribution,
            self.v1.min_fee_rate,
        )?;
        let hpke_ctx = HpkeContext::new(rs, &self.reply_key);
        let body = encrypt_message_a(
            body,
            &hpke_ctx.reply_pair.public_key().clone(),
            &hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.v1.endpoint.ohttp().map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "POST", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
        log::debug!("ohttp_relay_url: {:?}", ohttp_relay);
        Ok((
            Request::new_v2(&ohttp_relay, &body),
            V2PostContext {
                endpoint: self.v1.endpoint.clone(),
                psbt_ctx: PsbtContext {
                    original_psbt: self.v1.psbt.clone(),
                    disable_output_substitution: self.v1.disable_output_substitution,
                    fee_contribution: self.v1.fee_contribution,
                    payee: self.v1.payee.clone(),
                    min_fee_rate: self.v1.min_fee_rate,
                },
                hpke_ctx,
                ohttp_ctx,
            },
        ))
    }

    fn extract_rs_pubkey(
        &self,
    ) -> Result<HpkePublicKey, crate::uri::url_ext::ParseReceiverPubkeyParamError> {
        self.v1.endpoint.receiver_pubkey()
    }

    pub fn endpoint(&self) -> &Url { self.v1.endpoint() }
}

fn serialize_v2_body(
    psbt: &Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
) -> Result<Vec<u8>, CreateRequestError> {
    // Grug say localhost base be discarded anyway. no big brain needed.
    let base_url = Url::parse("http://localhost").expect("invalid URL");

    let placeholder_url = serialize_url(
        base_url,
        disable_output_substitution,
        fee_contribution,
        min_fee_rate,
        "2", // payjoin version
    )
    .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
    let query_params = placeholder_url.query().unwrap_or_default();
    let base64 = psbt.to_string();
    Ok(format!("{}\n{}", base64, query_params).into_bytes())
}

pub struct V2PostContext {
    /// The payjoin directory subdirectory to send the request to.
    endpoint: Url,
    psbt_ctx: PsbtContext,
    hpke_ctx: HpkeContext,
    ohttp_ctx: ohttp::ClientResponse,
}

impl V2PostContext {
    pub fn process_response(self, response: &[u8]) -> Result<V2GetContext, EncapsulationError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] = response
            .try_into()
            .map_err(|_| InternalEncapsulationError::InvalidSize(response.len()))?;
        let response = ohttp_decapsulate(self.ohttp_ctx, response_array)
            .map_err(InternalEncapsulationError::Ohttp)?;
        match response.status() {
            http::StatusCode::OK => {
                // return OK with new Typestate
                Ok(V2GetContext {
                    endpoint: self.endpoint,
                    psbt_ctx: self.psbt_ctx,
                    hpke_ctx: self.hpke_ctx,
                })
            }
            _ => Err(InternalEncapsulationError::UnexpectedStatusCode(response.status()))?,
        }
    }
}

#[derive(Debug, Clone)]
pub struct V2GetContext {
    /// The payjoin directory subdirectory to send the request to.
    endpoint: Url,
    psbt_ctx: PsbtContext,
    hpke_ctx: HpkeContext,
}

impl V2GetContext {
    pub fn extract_req(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        use crate::uri::UrlExt;
        let base_url = self.endpoint.clone();

        // TODO unify with receiver's fn subdir_path_from_pubkey
        let hash = sha256::Hash::hash(&self.hpke_ctx.reply_pair.public_key().to_compressed_bytes());
        let subdir: ShortId = hash.into();
        let url = base_url
            .join(&subdir.to_string())
            .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
        let body = encrypt_message_a(
            Vec::new(),
            &self.hpke_ctx.reply_pair.public_key().clone(),
            &self.hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.endpoint.ohttp().map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "GET", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;

        let url = ohttp_relay.into_url().map_err(InternalCreateRequestError::Url)?;
        Ok((Request::new_v2(&url, &body), ohttp_ctx))
    }

    pub fn process_response(
        &self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> Result<Option<Psbt>, ResponseError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] = response
            .try_into()
            .map_err(|_| InternalEncapsulationError::InvalidSize(response.len()))?;

        let response = ohttp_decapsulate(ohttp_ctx, response_array)
            .map_err(InternalEncapsulationError::Ohttp)?;
        let body = match response.status() {
            http::StatusCode::OK => response.body().to_vec(),
            http::StatusCode::ACCEPTED => return Ok(None),
            _ => return Err(InternalEncapsulationError::UnexpectedStatusCode(response.status()))?,
        };
        let psbt = decrypt_message_b(
            &body,
            self.hpke_ctx.receiver.clone(),
            self.hpke_ctx.reply_pair.secret_key().clone(),
        )
        .map_err(InternalEncapsulationError::Hpke)?;

        let proposal = Psbt::deserialize(&psbt).map_err(InternalProposalError::Psbt)?;
        let processed_proposal = self.psbt_ctx.clone().process_proposal(proposal)?;
        Ok(Some(processed_proposal))
    }
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone)]
struct HpkeContext {
    receiver: HpkePublicKey,
    reply_pair: HpkeKeyPair,
}

#[cfg(feature = "v2")]
impl HpkeContext {
    pub fn new(receiver: HpkePublicKey, reply_key: &HpkeSecretKey) -> Self {
        Self { receiver, reply_pair: HpkeKeyPair::from_secret_key(reply_key) }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hex::FromHex;
    use payjoin_test_utils::BoxError;

    use super::*;
    use crate::receive::v1::test::ORIGINAL_PSBT;
    use crate::receive::v2::test::SHARED_CONTEXT;

    const SERIALIZED_BODY: &str = "63484e696450384241484d43414141414159386e757447674a647959475857694245623435486f65396c5747626b78682f36624e694f4a6443447544414141414141442b2f2f2f2f41747956754155414141414146366b554865684a38476e536442554f4f7636756a584c72576d734a5244434867495165414141414141415871525233514a62627a30686e513849765130667074476e2b766f746e656f66544141414141414542494b6762317755414141414146366b55336b34656b47484b57524e6241317256357452356b455644564e4348415163584667415578347046636c4e56676f31575741644e3153594e583874706854414243477343527a424541694238512b41366465702b527a393276687932366c5430416a5a6e3450524c6938426639716f422f434d6b30774967502f526a3250575a3367456a556b546c6844524e415130675877544f3774396e2b563134705a366f6c6a554249514d566d7341616f4e5748564d5330324c6654536530653338384c4e697450613155515a794f6968592b464667414241425941464562324769753663344b4f35595730706677336c4770396a4d55554141413d0a763d32";

    fn create_sender_context() -> Result<super::Sender, BoxError> {
        let psbt = Psbt::from_str(ORIGINAL_PSBT)?;
        let endpoint = Url::parse("http://localhost:1234")?;
        Ok(super::Sender {
            v1: v1::Sender {
                psbt,
                endpoint,
                disable_output_substitution: false,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            reply_key: HpkeKeyPair::gen_keypair().0,
        })
    }

    #[test]
    fn sender_ser_de_roundtrip() -> Result<(), BoxError> {
        let sender = create_sender_context()?;
        let serialized = serde_json::to_string(&sender)?;
        let deserialized = serde_json::from_str(&serialized)?;
        assert!(sender == deserialized);
        Ok(())
    }

    #[test]
    fn test_serialize_v2() -> Result<(), BoxError> {
        let sender = create_sender_context()?;
        let body = serialize_v2_body(
            &sender.v1.psbt,
            sender.v1.disable_output_substitution,
            sender.v1.fee_contribution,
            sender.v1.min_fee_rate,
        );
        assert_eq!(body.as_ref().unwrap(), &<Vec<u8> as FromHex>::from_hex(SERIALIZED_BODY)?,);
        Ok(())
    }

    #[test]
    fn test_extract_v2_success() -> Result<(), BoxError> {
        let mut sender = create_sender_context()?;
        let exp_time = SHARED_CONTEXT.expiry;
        sender.v1.endpoint.set_exp(exp_time);

        let receiver_pubkey = SHARED_CONTEXT.s.1.clone();
        sender.v1.endpoint.set_receiver_pubkey(receiver_pubkey);

        let ohttp_relay = SHARED_CONTEXT.directory.clone();
        let ohttp_keys = SHARED_CONTEXT.ohttp_keys.clone();
        sender.v1.endpoint.set_ohttp(ohttp_keys);

        let result = sender.extract_v2(ohttp_relay);
        assert!(result.is_ok(), "Expected Ok result, got: {:#?}", result.err());
        let (request, context) = result?;

        assert!(!request.body.is_empty(), "Request body should not be empty");
        assert_eq!(request.url, Url::parse("https://relay.com")?);
        assert_eq!(context.endpoint, sender.v1.endpoint);
        assert_eq!(context.psbt_ctx.original_psbt, sender.v1.psbt);
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_with_missing_keys() -> Result<(), BoxError> {
        let mut sender = create_sender_context()?;
        let exp_time = SHARED_CONTEXT.expiry;
        sender.v1.endpoint.set_exp(exp_time);
        let receiver_pubkey = SHARED_CONTEXT.s.1.clone();
        sender.v1.endpoint.set_receiver_pubkey(receiver_pubkey);
        let ohttp_relay = SHARED_CONTEXT.directory.clone();
        //Not including ohttp_keys will cause a missing ohttp config panic
        let result = sender.extract_v2(ohttp_relay);
        assert!(result.is_err(), "{:#?}", result.err());
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_when_expired() -> Result<(), BoxError> {
        let mut sender = create_sender_context()?;
        let exp_time = std::time::SystemTime::now();
        sender.v1.endpoint.set_exp(exp_time);
        let receiver_pubkey = SHARED_CONTEXT.s.1.clone();
        sender.v1.endpoint.set_receiver_pubkey(receiver_pubkey);
        let ohttp_relay = SHARED_CONTEXT.directory.clone();
        let ohttp_keys = SHARED_CONTEXT.ohttp_keys.clone();
        sender.v1.endpoint.set_ohttp(ohttp_keys);
        //Setting expiry time equal to system time will cause an expiry panic
        let result = sender.extract_v2(ohttp_relay);
        assert!(result.is_err(), "{:#?}", result.err());
        Ok(())
    }
}

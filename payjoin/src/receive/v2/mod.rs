//! Receive BIP 77 Payjoin v2
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Error, InputContributionError};
use super::{
    v1, ImplementationError, InternalPayloadError, JsonError, OutputSubstitutionError,
    ReplyableError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate, OhttpEncapsulationError, OhttpKeys};
use crate::receive::{parse_payload, InputPair};
use crate::uri::ShortId;
use crate::{IntoUrl, IntoUrlError, Request};

pub(crate) mod error;

const SUPPORTED_VERSIONS: &[usize] = &[1, 2];

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: url::Url,
    subdirectory: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    s: HpkeKeyPair,
    e: Option<HpkePublicKey>,
}

fn deserialize_address_assume_checked<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let address = Address::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(address.assume_checked())
}

fn subdir_path_from_pubkey(pubkey: &HpkePublicKey) -> ShortId {
    sha256::Hash::hash(&pubkey.to_compressed_bytes()).into()
}

/// A payjoin V2 receiver, allowing for polled requests to the
/// payjoin directory and response processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver {
    context: SessionContext,
}

impl Receiver {
    /// Creates a new `Receiver` with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `expire_after`: The duration after which the session expires.
    ///
    /// # Returns
    /// A new instance of `Receiver`.
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/pull/1483)
    pub fn new(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        expire_after: Option<Duration>,
    ) -> Result<Self, IntoUrlError> {
        Ok(Self {
            context: SessionContext {
                address,
                directory: directory.into_url()?,
                subdirectory: None,
                ohttp_keys,
                expiry: SystemTime::now()
                    + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
        })
    }

    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        if SystemTime::now() > self.context.expiry {
            return Err(InternalSessionError::Expired(self.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let url = ohttp_relay.into_url().map_err(InternalSessionError::ParseUrl)?;
        let req = Request::new_v2(&url, &body);
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<UncheckedProposal>, Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into()
                .map_err(|_| InternalSessionError::UnexpectedResponseSize(body.len()))?;
        log::trace!("decapsulating directory response");
        let response = ohttp_decapsulate(context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;
        if response.body().is_empty() {
            log::debug!("response is empty");
            return Ok(None);
        }
        match String::from_utf8(response.body().to_vec()) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(self.extract_proposal_from_v1(response)?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(self.extract_proposal_from_v2(response.body().to_vec())?)),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = subdir(&self.context.directory, &self.id());
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        &mut self,
        response: String,
    ) -> Result<UncheckedProposal, ReplyableError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(&mut self, response: Vec<u8>) -> Result<UncheckedProposal, Error> {
        let (payload_bytes, e) = decrypt_message_a(&response, self.context.s.secret_key().clone())?;
        self.context.e = Some(e);
        let payload = String::from_utf8(payload_bytes)
            .map_err(|e| Error::ReplyToSender(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map_err(Error::ReplyToSender)
    }

    fn unchecked_from_payload(
        &mut self,
        payload: String,
    ) -> Result<UncheckedProposal, ReplyableError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {}, base64: {}", query, base64); // my guess is no \n so default is wrong
        let (psbt, mut params) = parse_payload(base64.to_string(), query, SUPPORTED_VERSIONS)
            .map_err(ReplyableError::Payload)?;

        // Output substitution must be disabled for V1 sessions in V2 contexts.
        //
        // V2 contexts depend on a payjoin directory to store and forward payjoin
        // proposals. Plaintext V1 proposals are vulnerable to output replacement
        // attacks by a malicious directory if output substitution is not disabled.
        // V2 proposals are authenticated and encrypted to prevent such attacks.
        //
        // see: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server
        if params.v == 1 {
            params.disable_output_substitution = true;
        }

        let inner = v1::UncheckedProposal { psbt, params };
        Ok(UncheckedProposal { v1: inner, context: self.context.clone() })
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        use crate::uri::{PayjoinExtras, UrlExt};
        let mut pj = subdir(&self.context.directory, &self.id()).clone();
        pj.set_receiver_pubkey(self.context.s.public_key().clone());
        pj.set_ohttp(self.context.ohttp_keys.clone());
        pj.set_exp(self.context.expiry);
        let extras = PayjoinExtras { endpoint: pj, disable_output_substitution: false };
        bitcoin_uri::Uri::with_extras(self.context.address.clone(), extras)
    }

    /// The per-session identifier
    pub fn id(&self) -> ShortId { id(&self.context.s) }
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to process the request. It is returned by
/// [`Receiver::process_res()`].
///
/// If you are implementing an interactive payment processor, you should get extract the original
/// transaction with extract_tx_to_schedule_broadcast() and schedule, followed by checking
/// that the transaction can be broadcast with check_broadcast_suitability. Otherwise it is safe to
/// call assume_interactive_receive to proceed with validation.
#[derive(Debug, Clone)]
pub struct UncheckedProposal {
    v1: v1::UncheckedProposal,
    context: SessionContext,
}

impl UncheckedProposal {
    /// The Sender's Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.v1.extract_tx_to_schedule_broadcast()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `extract_tx_to_schedule_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsOwned, ReplyableError> {
        let inner = self.v1.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(MaybeInputsOwned { v1: inner, context: self.context })
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        let inner = self.v1.assume_interactive_receiver();
        MaybeInputsOwned { v1: inner, context: self.context }
    }

    /// Extract an OHTTP Encapsulated HTTP POST request to return
    /// a Receiver Error Response
    pub fn extract_err_req(
        &mut self,
        err: &ReplyableError,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        let subdir = subdir(&self.context.directory, &id(&self.context.s));
        let (body, ohttp_ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "POST",
            subdir.as_str(),
            Some(err.to_json().as_bytes()),
        )
        .map_err(InternalSessionError::OhttpEncapsulation)?;
        let url = ohttp_relay.into_url().map_err(InternalSessionError::ParseUrl)?;
        let req = Request::new_v2(&url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process an OHTTP Encapsulated HTTP POST Error response
    /// to ensure it has been posted properly
    pub fn process_err_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<(), SessionError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into()
                .map_err(|_| InternalSessionError::UnexpectedResponseSize(body.len()))?;
        let response = ohttp_decapsulate(context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;

        match response.status() {
            http::StatusCode::OK => Ok(()),
            _ => Err(InternalSessionError::UnexpectedStatusCode(response.status()).into()),
        }
    }
}

/// Typestate to validate that the Original PSBT has no receiver-owned inputs.
///
/// Call [`check_no_receiver_owned_inputs()`](struct.UncheckedProposal.html#method.check_no_receiver_owned_inputs) to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    context: SessionContext,
}

impl MaybeInputsOwned {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsSeen, ReplyableError> {
        let inner = self.v1.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { v1: inner, context: self.context })
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`check_no_inputs_seen`](struct.MaybeInputsSeen.html#method.check_no_inputs_seen_before) to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    context: SessionContext,
}

impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<OutputsUnknown, ReplyableError> {
        let inner = self.v1.check_no_inputs_seen_before(is_known)?;
        Ok(OutputsUnknown { inner, context: self.context })
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    inner: v1::OutputsUnknown,
    context: SessionContext,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<WantsOutputs, ReplyableError> {
        let inner = self.inner.identify_receiver_outputs(is_receiver_output)?;
        Ok(WantsOutputs { v1: inner, context: self.context })
    }
}

/// A checked proposal that the receiver may substitute or add outputs to
#[derive(Debug, Clone)]
pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    context: SessionContext,
}

impl WantsOutputs {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.v1.is_output_substitution_disabled()
    }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let inner = self.v1.substitute_receiver_script(output_script)?;
        Ok(WantsOutputs { v1: inner, context: self.context })
    }

    /// Replace **all** receiver outputs with one or more provided outputs.
    /// The drain script specifies which address to *drain* coins to. An output corresponding to
    /// that address must be included in `replacement_outputs`. The value of that output may be
    /// increased or decreased depending on the receiver's input contributions and whether the
    /// receiver needs to pay for additional miner fees (e.g. in the case of adding many outputs).
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: Vec<TxOut>,
        drain_script: &Script,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let inner = self.v1.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(WantsOutputs { v1: inner, context: self.context })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> WantsInputs {
        let inner = self.v1.commit_outputs();
        WantsInputs { v1: inner, context: self.context }
    }
}

/// A checked proposal that the receiver may contribute inputs to to make a payjoin
#[derive(Debug, Clone)]
pub struct WantsInputs {
    v1: v1::WantsInputs,
    context: SessionContext,
}

impl WantsInputs {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    /// if min(in) > min(out) then UIH1 else UIH2
    /// <https://eprint.iacr.org/2022/589.pdf>
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        self.v1.try_preserving_privacy(candidate_inputs)
    }

    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<WantsInputs, InputContributionError> {
        let inner = self.v1.contribute_inputs(inputs)?;
        Ok(WantsInputs { v1: inner, context: self.context })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> ProvisionalProposal {
        let inner = self.v1.commit_inputs();
        ProvisionalProposal { v1: inner, context: self.context }
    }
}

/// A checked proposal that the receiver may sign and finalize to make a proposal PSBT that the
/// sender will accept.
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    context: SessionContext,
}

impl ProvisionalProposal {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<PayjoinProposal, ReplyableError> {
        let inner =
            self.v1.finalize_proposal(wallet_process_psbt, min_fee_rate, max_effective_fee_rate)?;
        Ok(PayjoinProposal { v1: inner, context: self.context })
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[derive(Clone)]
pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    context: SessionContext,
}

impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.v1.utxos_to_be_locked()
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.v1.is_output_substitution_disabled()
    }

    pub fn psbt(&self) -> &Psbt { self.v1.psbt() }

    pub fn extract_v2_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.v1.psbt().serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource = self
                .context
                .directory
                .join(&sender_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.v1.psbt().to_string().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.context.s.public_key());
            target_resource = self
                .context
                .directory
                .join(&receiver_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;
        let url = ohttp_relay.into_url().map_err(InternalSessionError::ParseUrl)?;
        let req = Request::new_v2(&url, &body);
        Ok((req, ctx))
    }

    #[cfg(feature = "v2")]
    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            res.try_into().map_err(|_| InternalSessionError::UnexpectedResponseSize(res.len()))?;
        let res = ohttp_decapsulate(ohttp_context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(InternalSessionError::UnexpectedStatusCode(res.status()).into())
        }
    }
}

/// The subdirectory for this Payjoin receiver session.
/// It consists of a directory URL and the session ShortID in the path.
fn subdir(directory: &Url, id: &ShortId) -> Url {
    let mut url = directory.clone();
    {
        let mut path_segments =
            url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
        path_segments.push(&id.to_string());
    }
    url
}

/// The per-session identifier
fn id(s: &HpkeKeyPair) -> ShortId {
    sha256::Hash::hash(&s.public_key().to_compressed_bytes()).into()
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};
    use once_cell::sync::Lazy;
    use payjoin_test_utils::BoxError;

    use super::*;

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::K256Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    static EXAMPLE_URL: Lazy<Url> =
        Lazy::new(|| Url::parse("https://relay.com").expect("invalid URL"));

    static SHARED_CONTEXT: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        subdirectory: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        s: HpkeKeyPair::gen_keypair(),
        e: None,
    });

    #[test]
    fn extract_err_req() -> Result<(), BoxError> {
        let mut proposal = UncheckedProposal {
            v1: crate::receive::v1::test::proposal_from_test_vector()?,
            context: SHARED_CONTEXT.clone(),
        };

        let server_error = proposal
            .clone()
            .check_broadcast_suitability(None, |_| Err("mock error".into()))
            .err()
            .ok_or("expected error but got success")?;
        assert_eq!(
            server_error.to_json(),
            r#"{ "errorCode": "unavailable", "message": "Receiver error" }"#
        );
        let (_req, _ctx) = proposal.clone().extract_err_req(&server_error, &*EXAMPLE_URL)?;

        let internal_error = InternalPayloadError::MissingPayment.into();
        let (_req, _ctx) = proposal.extract_err_req(&internal_error, &*EXAMPLE_URL)?;
        Ok(())
    }

    #[test]
    fn receiver_ser_de_roundtrip() -> Result<(), serde_json::Error> {
        let session = Receiver { context: SHARED_CONTEXT.clone() };
        let serialized = serde_json::to_string(&session)?;
        let deserialized: Receiver = serde_json::from_str(&serialized)?;
        assert_eq!(session, deserialized);
        Ok(())
    }

    #[test]
    fn test_v2_pj_uri() {
        let uri = Receiver { context: SHARED_CONTEXT.clone() }.pj_uri();
        assert_ne!(uri.extras.endpoint, EXAMPLE_URL.clone());
        assert!(!uri.extras.disable_output_substitution);
    }
}

use bitcoin::{FeeRate, Psbt};
use error::{
    CreateRequestError, FinalizeResponseError, FinalizedError, InternalCreateRequestError,
    InternalFinalizeResponseError, InternalFinalizedError,
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::v2::{self, EncapsulationError, HpkeContext};
use super::BuildSenderError;
use crate::ohttp::ohttp_decapsulate;
use crate::receive::ImplementationError;
use crate::send::v2::{serialize_v2_body, V2PostContext};
use crate::{PjUri, Request};

mod error;

#[derive(Clone)]
pub struct SenderBuilder<'a>(v2::SenderBuilder<'a>);

impl<'a> SenderBuilder<'a> {
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self { Self(v2::SenderBuilder::new(psbt, uri)) }
    pub fn build_recommended(self, min_fee_rate: FeeRate) -> Result<Sender, BuildSenderError> {
        let v2 = v2::SenderBuilder::new(self.0 .0.psbt, self.0 .0.uri)
            .build_recommended(min_fee_rate)?;
        Ok(Sender(v2))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender(v2::Sender);

impl Sender {
    pub fn extract_v2(
        &self,
        ohttp_relay: Url,
    ) -> Result<(Request, PostContext), CreateRequestError> {
        use crate::hpke::encrypt_message_a;
        use crate::ohttp::ohttp_encapsulate;
        use crate::send::PsbtContext;
        use crate::uri::UrlExt;
        let url = self.0.endpoint().clone();
        if let Ok(expiry) = url.exp() {
            if std::time::SystemTime::now() > expiry {
                return Err(InternalCreateRequestError::Expired(expiry).into());
            }
        }
        let rs = self
            .0
            .extract_rs_pubkey()
            .map_err(InternalCreateRequestError::ParseReceiverPubkeyParam)?;
        let body = serialize_v2_body(
            &self.0.v1.psbt,
            self.0.v1.disable_output_substitution,
            self.0.v1.fee_contribution,
            self.0.v1.min_fee_rate,
            true,
        )
        .map_err(InternalCreateRequestError::V2CreateRequest)?;
        let hpke_ctx = HpkeContext::new(rs, &self.0.reply_key);
        let body = encrypt_message_a(
            body,
            &hpke_ctx.reply_pair.public_key().clone(),
            &hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp = self
            .0
            .v1
            .endpoint
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "POST", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;

        let v2_post_ctx = V2PostContext {
            endpoint: self.0.endpoint().clone(),
            psbt_ctx: PsbtContext {
                original_psbt: self.0.v1.psbt.clone(),
                disable_output_substitution: self.0.v1.disable_output_substitution,
                fee_contribution: self.0.v1.fee_contribution,
                payee: self.0.v1.payee.clone(),
                min_fee_rate: self.0.v1.min_fee_rate,
                opt_in_to_optimistic_merge: true,
            },
            hpke_ctx,
            ohttp_ctx,
        };
        Ok((Request::new_v2(&ohttp_relay, &body), PostContext(v2_post_ctx)))
    }
}

/// Post context is used to process the response from the directory and generate
/// the GET context which can be used to extract a request for the receiver
pub struct PostContext(v2::V2PostContext);

impl PostContext {
    pub fn process_response(self, response: &[u8]) -> Result<GetContext, EncapsulationError> {
        let v2_get_ctx = self.0.process_response(response)?;
        Ok(GetContext(v2_get_ctx))
    }
}

/// Get context is used to extract a request for the receiver and process the response from the receiver.
pub struct GetContext(v2::V2GetContext);

impl GetContext {
    /// Extract the GET request that will give us the psbt to be finalized
    pub fn extract_req(
        &self,
        ohttp_relay: Url,
    ) -> Result<(Request, ohttp::ClientResponse), crate::send::v2::CreateRequestError> {
        self.0.extract_req(ohttp_relay)
    }

    /// Process the response from the directory. Provide a closure to finalize the inputs
    /// you own. With the FinalizeContext, you can extract the last POST request and process the response back to the directory.
    pub fn process_response_and_finalize(
        &self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
        finalize_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> Result<FinalizeContext, FinalizedError> {
        if let Some(psbt) = self
            .0
            .process_response(response, ohttp_ctx)
            .map_err(InternalFinalizedError::Response)?
        {
            return Ok(FinalizeContext {
                hpke_ctx: self.0.hpke_ctx.clone(),
                directory_url: self.0.endpoint.clone(),
                psbt: finalize_psbt(&psbt).map_err(InternalFinalizedError::FinalizePsbt)?,
            });
        }

        Err(InternalFinalizedError::MissingResponse.into())
    }
}

/// Finalize context is used to extract the last POST request and process the response back to the directory.
pub struct FinalizeContext {
    hpke_ctx: HpkeContext,
    directory_url: Url,
    psbt: Psbt,
}

impl FinalizeContext {
    pub fn extract_req(
        &self,
        ohttp_relay: Url,
    ) -> Result<(Request, ohttp::ClientResponse), FinalizedError> {
        use crate::hpke::encrypt_message_a;
        use crate::ohttp::ohttp_encapsulate;
        use crate::uri::UrlExt;

        let hpke_ctx = self.hpke_ctx.clone();
        let directory_url = self.directory_url.clone();
        // TODO: check if request is expired off the directory url

        // The query params are not needed for the final request
        // The reciever will ignore them. PSBT is all that is needed.
        let body = serialize_v2_body(
            &self.psbt,
            false, // disable output substitution
            None,  // fee contribution
            FeeRate::BROADCAST_MIN,
            false,
        )
        .map_err(InternalFinalizedError::CreateRequest)?;
        let body = encrypt_message_a(
            body,
            &hpke_ctx.reply_pair.public_key().clone(),
            &hpke_ctx.receiver.clone(),
        )
        .map_err(InternalFinalizedError::Hpke)?;
        let mut ohttp = directory_url.ohttp().map_err(InternalFinalizedError::ParseOhttp)?;
        let (body, ohttp_ctx) =
            ohttp_encapsulate(&mut ohttp, "POST", directory_url.as_str(), Some(&body))
                .map_err(InternalFinalizedError::Encapsulation)?;
        let request = Request::new_v2(&ohttp_relay, &body);
        Ok((request, ohttp_ctx))
    }

    pub fn process_response(
        self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> Result<(), FinalizeResponseError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] = response
            .try_into()
            .map_err(|_| InternalFinalizeResponseError::InvalidSize(response.len()))?;

        let response = ohttp_decapsulate(ohttp_ctx, response_array)
            .map_err(InternalFinalizeResponseError::Ohttp)?;
        match response.status() {
            http::StatusCode::OK | http::StatusCode::ACCEPTED => Ok(()),
            _ => Err(InternalFinalizeResponseError::UnexpectedStatusCode(response.status()))?,
        }
    }
}

use std::fmt::{self, Display};

use bitcoin::psbt::Error as PsbtError;

use crate::hpke::HpkeError;
use crate::ohttp::OhttpEncapsulationError;
use crate::receive::ImplementationError;
use crate::send::InternalProposalError;
use crate::uri::url_ext::{ParseOhttpKeysParamError, ParseReceiverPubkeyParamError};

#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    #[allow(dead_code)]
    Expired(std::time::SystemTime),
    MissingOhttpConfig,
    OhttpEncapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    ParseReceiverPubkeyParam(ParseReceiverPubkeyParamError),
    Url(url::ParseError),
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalCreateRequestError::Expired(_) => None,
            InternalCreateRequestError::MissingOhttpConfig => None,
            InternalCreateRequestError::OhttpEncapsulation(e) => Some(e),
            InternalCreateRequestError::Hpke(e) => Some(e),
            InternalCreateRequestError::ParseReceiverPubkeyParam(e) => Some(e),
            InternalCreateRequestError::Url(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct FinalizedError(InternalFinalizedError);

#[derive(Debug)]
pub(crate) enum InternalFinalizedError {
    CreateRequest(CreateRequestError),
    Encapsulation(OhttpEncapsulationError),
    Hpke(HpkeError),
    ParseOhttp(ParseOhttpKeysParamError),
    InvalidSize,
    FinalizePsbt(ImplementationError),
    MissingResponse,
    Psbt(PsbtError),
    #[allow(dead_code)]
    UnexpectedStatusCode(http::StatusCode),
    Proposal(InternalProposalError),
}

impl From<InternalFinalizedError> for FinalizedError {
    fn from(value: InternalFinalizedError) -> Self { FinalizedError(value) }
}

impl Display for FinalizedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for FinalizedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalFinalizedError::CreateRequest(e) => Some(e),
            InternalFinalizedError::Encapsulation(e) => Some(e),
            InternalFinalizedError::Hpke(e) => Some(e),
            InternalFinalizedError::ParseOhttp(_e) => None,
            InternalFinalizedError::InvalidSize => None,
            InternalFinalizedError::FinalizePsbt(_e) => None,
            InternalFinalizedError::MissingResponse => None,
            InternalFinalizedError::Psbt(e) => Some(e),
            InternalFinalizedError::UnexpectedStatusCode(_) => None,
            InternalFinalizedError::Proposal(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct FinalizeResponseError(InternalFinalizeResponseError);

#[derive(Debug)]
pub(crate) enum InternalFinalizeResponseError {
    #[allow(dead_code)]
    InvalidSize(usize),
    Ohttp(OhttpEncapsulationError),
    #[allow(dead_code)]
    UnexpectedStatusCode(http::StatusCode),
}

impl From<InternalFinalizeResponseError> for FinalizeResponseError {
    fn from(value: InternalFinalizeResponseError) -> Self { FinalizeResponseError(value) }
}

impl Display for FinalizeResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for FinalizeResponseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalFinalizeResponseError::InvalidSize(_) => None,
            InternalFinalizeResponseError::Ohttp(e) => Some(e),
            InternalFinalizeResponseError::UnexpectedStatusCode(_) => None,
        }
    }
}

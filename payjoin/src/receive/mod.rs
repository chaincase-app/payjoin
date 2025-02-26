//! Receive Payjoin
//!
//! This module contains types and methods used to implement receiving via Payjoin.
//!
//! For most use cases, we recommended enabling the `v2` feature, as it is
//! backwards compatible and provides the most convenient experience for users and implementors.
//! To use version 2, refer to `receive::v2` module documentation.
//!
//! If you specifically need to use
//! version 1, refer to the `receive::v1` module documentation after enabling the `v1` feature.

use std::str::FromStr;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{psbt, AddressType, Psbt, TxIn, TxOut};
pub(crate) use error::InternalPayloadError;
pub use error::{
    Error, ImplementationError, JsonError, OutputSubstitutionError, PayloadError, ReplyableError,
    SelectionError,
};
use optional_parameters::Params;

pub use crate::psbt::PsbtInputError;
use crate::psbt::{InternalInputPair, InternalPsbtInputError, PsbtExt};

mod error;
pub(crate) mod optional_parameters;

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;
#[cfg(not(feature = "v1"))]
pub(crate) mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

/// Helper to construct a pair of (txin, psbtin) with some built-in validation
/// Use with [`InputPair::new`] to contribute receiver inputs.
#[derive(Clone, Debug)]
pub struct InputPair {
    pub(crate) txin: TxIn,
    pub(crate) psbtin: psbt::Input,
}

impl InputPair {
    pub fn new(txin: TxIn, psbtin: psbt::Input) -> Result<Self, PsbtInputError> {
        let input_pair = Self { txin, psbtin };
        let raw = InternalInputPair::from(&input_pair);
        raw.validate_utxo()?;
        let address_type = raw.address_type().map_err(InternalPsbtInputError::AddressType)?;
        if address_type == AddressType::P2sh && input_pair.psbtin.redeem_script.is_none() {
            return Err(InternalPsbtInputError::NoRedeemScript.into());
        }
        Ok(input_pair)
    }

    pub(crate) fn previous_txout(&self) -> TxOut {
        InternalInputPair::from(self)
            .previous_txout()
            .expect("UTXO information should have been validated in InputPair::new")
            .clone()
    }
}

impl<'a> From<&'a InputPair> for InternalInputPair<'a> {
    fn from(pair: &'a InputPair) -> Self { Self { psbtin: &pair.psbtin, txin: &pair.txin } }
}

/// Validate the payload of a Payjoin request for PSBT and Params sanity
pub(crate) fn parse_payload(
    base64: String,
    query: &str,
    supported_versions: &'static [usize],
) -> Result<(Psbt, Params), PayloadError> {
    let unchecked_psbt = Psbt::from_str(&base64).map_err(InternalPayloadError::ParsePsbt)?;

    let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
    log::debug!("Received original psbt: {:?}", psbt);

    let pairs = url::form_urlencoded::parse(query.as_bytes());
    let params = Params::from_query_pairs(pairs, supported_versions)
        .map_err(InternalPayloadError::SenderParams)?;
    log::debug!("Received request with params: {:?}", params);

    Ok((psbt, params))
}

#[derive(Debug)]
pub struct PersisterId {
    txid: bitcoin::Txid,
    state_type: u8,
}

impl PersisterId {
    pub fn new(txid: bitcoin::Txid, state_type: u8) -> Self { Self { txid, state_type } }

    pub fn to_bytes(&self) -> Result<[u8; 33], bitcoin::consensus::encode::Error> {
        let mut bytes = [0u8; 33];
        let mut writer = bytes.as_mut_slice();
        self.txid.consensus_encode(&mut writer)?;
        self.state_type.consensus_encode(&mut writer)?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bitcoin::consensus::encode::Error> {
        let mut reader = bytes;
        let txid = bitcoin::Txid::consensus_decode(&mut reader)?;
        let state_type = u8::consensus_decode(&mut reader)?;
        Ok(Self { txid, state_type })
    }
}

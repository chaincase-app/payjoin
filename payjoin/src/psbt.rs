//! Utilities to make work with PSBTs easier

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::address::FromScriptError;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::InputWeightPrediction;
use bitcoin::{bip32, psbt, Address, AddressType, Network, TxIn, TxOut, Weight};

#[derive(Debug)]
pub(crate) enum InconsistentPsbt {
    UnequalInputCounts { tx_ins: usize, psbt_ins: usize },
    UnequalOutputCounts { tx_outs: usize, psbt_outs: usize },
}

impl fmt::Display for InconsistentPsbt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins, } => write!(f, "The number of PSBT inputs ({}) doesn't equal to the number of unsigned transaction inputs ({})", psbt_ins, tx_ins),
            InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs, } => write!(f, "The number of PSBT outputs ({}) doesn't equal to the number of unsigned transaction outputs ({})", psbt_outs, tx_outs),
        }
    }
}

impl std::error::Error for InconsistentPsbt {}

/// Our Psbt type for validation and utilities
pub(crate) trait PsbtExt: Sized {
    fn inputs_mut(&mut self) -> &mut [psbt::Input];
    fn outputs_mut(&mut self) -> &mut [psbt::Output];
    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)>;
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_>;
    // guarantees that length of psbt input matches that of unsigned_tx inputs and same
    /// thing for outputs.
    fn validate(self) -> Result<Self, InconsistentPsbt>;
    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError>;
}

impl PsbtExt for Psbt {
    fn inputs_mut(&mut self) -> &mut [psbt::Input] { &mut self.inputs }

    fn outputs_mut(&mut self) -> &mut [psbt::Output] { &mut self.outputs }

    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)> {
        &mut self.xpub
    }

    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }

    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_> {
        Box::new(
            self.unsigned_tx
                .input
                .iter()
                .zip(&self.inputs)
                .map(|(txin, psbtin)| InternalInputPair { txin, psbtin }),
        )
    }

    fn validate(self) -> Result<Self, InconsistentPsbt> {
        let tx_ins = self.unsigned_tx.input.len();
        let psbt_ins = self.inputs.len();
        let tx_outs = self.unsigned_tx.output.len();
        let psbt_outs = self.outputs.len();

        if psbt_ins != tx_ins {
            Err(InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins })
        } else if psbt_outs != tx_outs {
            Err(InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs })
        } else {
            Ok(self)
        }
    }

    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError> {
        self.input_pairs().enumerate().try_for_each(|(index, input)| {
            input.validate_utxo().map_err(|error| PsbtInputsError { index, error })
        })
    }
}

// input script: 0x160014{20-byte-key-hash} = 23 bytes
// witness: <signature> <pubkey> = 72, 33 bytes
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh-nested-in-bip16-p2sh
const NESTED_P2WPKH_MAX: InputWeightPrediction = InputWeightPrediction::from_slice(23, &[72, 33]);

#[derive(Clone, Debug)]
pub(crate) struct InternalInputPair<'a> {
    pub txin: &'a TxIn,
    pub psbtin: &'a psbt::Input,
}

impl InternalInputPair<'_> {
    /// Returns TxOut associated with the input
    pub fn previous_txout(&self) -> Result<&TxOut, PrevTxOutError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) => Err(PrevTxOutError::MissingUtxoInformation),
            (_, Some(txout)) => Ok(txout),
            (Some(tx), None) => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or(PrevTxOutError::IndexOutOfBounds {
                    output_count: tx.output.len(),
                    index: self.txin.previous_output.vout,
                }),
        }
    }

    pub fn validate_utxo(&self) -> Result<(), InternalPsbtInputError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) =>
                Err(InternalPsbtInputError::PrevTxOut(PrevTxOutError::MissingUtxoInformation)),
            (Some(tx), None) if tx.compute_txid() == self.txin.previous_output.txid => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or_else(|| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                    .into()
                })
                .map(drop),
            (Some(_), None) => Err(InternalPsbtInputError::UnequalTxid),
            (None, Some(_)) => Ok(()),
            (Some(tx), Some(witness_txout))
                if tx.compute_txid() == self.txin.previous_output.txid =>
            {
                let non_witness_txout = tx
                    .output
                    .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                        PrevTxOutError::IndexOutOfBounds {
                            output_count: tx.output.len(),
                            index: self.txin.previous_output.vout,
                        }
                    })?)
                    .ok_or(PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    })?;
                if witness_txout == non_witness_txout {
                    Ok(())
                } else {
                    Err(InternalPsbtInputError::SegWitTxOutMismatch)
                }
            }
            (Some(_), Some(_)) => Err(InternalPsbtInputError::UnequalTxid),
        }
    }

    pub fn address_type(&self) -> Result<AddressType, AddressTypeError> {
        let txo = self.previous_txout()?;
        // HACK: Network doesn't matter for our use case of only getting the address type
        // but is required in the `from_script` interface. Hardcoded to mainnet.
        Address::from_script(&txo.script_pubkey, Network::Bitcoin)?
            .address_type()
            .ok_or(AddressTypeError::UnknownAddressType)
    }

    pub fn expected_input_weight(&self) -> Result<Weight, InputWeightError> {
        use bitcoin::AddressType::*;

        // Get the input weight prediction corresponding to spending an output of this address type
        let iwp = match self.address_type()? {
            P2pkh => Ok(InputWeightPrediction::P2PKH_COMPRESSED_MAX),
            P2sh => {
                // redeemScript can be extracted from scriptSig for signed P2SH inputs
                let redeem_script = if let Some(ref script_sig) = self.psbtin.final_script_sig {
                    script_sig.redeem_script()
                // try the PSBT redeem_script field for unsigned inputs.
                } else {
                    self.psbtin.redeem_script.as_ref().map(|script| script.as_ref())
                };
                match redeem_script {
                    // Nested segwit p2wpkh.
                    Some(script) if script.is_witness_program() && script.is_p2wpkh() =>
                        Ok(NESTED_P2WPKH_MAX),
                    // Other script or witness program.
                    Some(_) => Err(InputWeightError::NotSupported),
                    // No redeem script provided. Cannot determine the script type.
                    None => Err(InputWeightError::NoRedeemScript),
                }
            }
            P2wpkh => Ok(InputWeightPrediction::P2WPKH_MAX),
            P2wsh => Err(InputWeightError::NotSupported),
            P2tr => Ok(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH),
            _ => Err(AddressTypeError::UnknownAddressType.into()),
        }?;

        // Lengths of txid, index and sequence: (32, 4, 4).
        let input_weight = iwp.weight() + Weight::from_non_witness_data_size(32 + 4 + 4);
        Ok(input_weight)
    }
}

#[derive(Debug)]
pub(crate) enum PrevTxOutError {
    MissingUtxoInformation,
    IndexOutOfBounds { output_count: usize, index: u32 },
}

impl fmt::Display for PrevTxOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrevTxOutError::MissingUtxoInformation => write!(f, "missing UTXO information"),
            PrevTxOutError::IndexOutOfBounds { output_count, index } => {
                write!(f, "index {} out of bounds (number of outputs: {})", index, output_count)
            }
        }
    }
}

impl std::error::Error for PrevTxOutError {}

#[derive(Debug)]
pub(crate) enum InternalPsbtInputError {
    PrevTxOut(PrevTxOutError),
    UnequalTxid,
    /// TxOut provided in `segwit_utxo` doesn't match the one in `non_segwit_utxo`
    SegWitTxOutMismatch,
    AddressType(AddressTypeError),
    NoRedeemScript,
}

impl fmt::Display for InternalPsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::UnequalTxid => write!(f, "transaction ID of previous transaction doesn't match one specified in input spending it"),
            Self::SegWitTxOutMismatch => write!(f, "transaction output provided in SegWit UTXO field doesn't match the one in non-SegWit UTXO field"),
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::NoRedeemScript => write!(f, "provided p2sh PSBT input is missing a redeem_script"),
        }
    }
}

impl std::error::Error for InternalPsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::UnequalTxid => None,
            Self::SegWitTxOutMismatch => None,
            Self::AddressType(error) => Some(error),
            Self::NoRedeemScript => None,
        }
    }
}

impl From<PrevTxOutError> for InternalPsbtInputError {
    fn from(value: PrevTxOutError) -> Self { InternalPsbtInputError::PrevTxOut(value) }
}

impl From<AddressTypeError> for InternalPsbtInputError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

#[derive(Debug)]
pub struct PsbtInputError(InternalPsbtInputError);

impl From<InternalPsbtInputError> for PsbtInputError {
    fn from(e: InternalPsbtInputError) -> Self { PsbtInputError(e) }
}

impl fmt::Display for PsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for PsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[derive(Debug)]
pub struct PsbtInputsError {
    index: usize,
    error: InternalPsbtInputError,
}

impl fmt::Display for PsbtInputsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PSBT input #{}", self.index)
    }
}

impl std::error::Error for PsbtInputsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}

#[derive(Debug)]
pub(crate) enum AddressTypeError {
    PrevTxOut(PrevTxOutError),
    InvalidScript(FromScriptError),
    UnknownAddressType,
}

impl fmt::Display for AddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::InvalidScript(_) => write!(f, "invalid script"),
            Self::UnknownAddressType => write!(f, "unknown address type"),
        }
    }
}

impl std::error::Error for AddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::InvalidScript(error) => Some(error),
            Self::UnknownAddressType => None,
        }
    }
}

impl From<PrevTxOutError> for AddressTypeError {
    fn from(value: PrevTxOutError) -> Self { Self::PrevTxOut(value) }
}

impl From<FromScriptError> for AddressTypeError {
    fn from(value: FromScriptError) -> Self { Self::InvalidScript(value) }
}

#[derive(Debug)]
pub(crate) enum InputWeightError {
    AddressType(AddressTypeError),
    NoRedeemScript,
    NotSupported,
}

impl fmt::Display for InputWeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::NoRedeemScript => write!(f, "p2sh input missing a redeem script"),
            Self::NotSupported => write!(f, "weight prediction not supported"),
        }
    }
}

impl std::error::Error for InputWeightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddressType(error) => Some(error),
            Self::NoRedeemScript => None,
            Self::NotSupported => None,
        }
    }
}
impl From<AddressTypeError> for InputWeightError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

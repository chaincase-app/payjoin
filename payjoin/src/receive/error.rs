use std::{error, fmt};

use crate::error_codes::{
    NOT_ENOUGH_MONEY, ORIGINAL_PSBT_REJECTED, UNAVAILABLE, VERSION_UNSUPPORTED,
};

pub type ImplementationError = Box<dyn error::Error + Send + Sync>;

/// The top-level error type for the payjoin receiver
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Errors that can be replied to the sender
    ReplyToSender(ReplyableError),
    #[cfg(feature = "v2")]
    /// V2-specific errors that are infeasable to reply to the sender
    V2(crate::receive::v2::SessionError),
}

impl From<ReplyableError> for Error {
    fn from(e: ReplyableError) -> Self { Error::ReplyToSender(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ReplyToSender(e) => write!(f, "replyable error: {}", e),
            #[cfg(feature = "v2")]
            Error::V2(e) => write!(f, "unreplyable error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::ReplyToSender(e) => e.source(),
            #[cfg(feature = "v2")]
            Error::V2(e) => e.source(),
        }
    }
}

/// The replyable error type for the payjoin receiver, representing failures need to be
/// returned to the sender.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return using [`JsonError::to_json`]
#[derive(Debug)]
pub enum ReplyableError {
    /// Error arising from validation of the original PSBT payload
    Payload(PayloadError),
    /// Protocol-specific errors for BIP-78 v1 requests (e.g. HTTP request validation, parameter checks)
    #[cfg(feature = "v1")]
    V1(crate::receive::v1::RequestError),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    Implementation(ImplementationError),
}

/// A trait for errors that can be serialized to JSON in a standardized format.
///
/// The JSON output follows the structure:
/// ```json
/// {
///     "errorCode": "specific-error-code",
///     "message": "Human readable error message"
/// }
/// ```
pub trait JsonError {
    /// Converts the error into a JSON string representation.
    fn to_json(&self) -> String;
}

impl JsonError for ReplyableError {
    fn to_json(&self) -> String {
        match self {
            Self::Payload(e) => e.to_json(),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.to_json(),
            Self::Implementation(_) => serialize_json_error(UNAVAILABLE, "Receiver error"),
        }
    }
}

pub(crate) fn serialize_json_error(code: &str, message: impl fmt::Display) -> String {
    format!(r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
}

pub(crate) fn serialize_json_plus_fields(
    code: &str,
    message: impl fmt::Display,
    additional_fields: &str,
) -> String {
    format!(r#"{{ "errorCode": "{}", "message": "{}", {} }}"#, code, message, additional_fields)
}

impl fmt::Display for ReplyableError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::Payload(e) => e.fmt(f),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.fmt(f),
            Self::Implementation(e) => write!(f, "Internal Server Error: {}", e),
        }
    }
}

impl error::Error for ReplyableError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::Payload(e) => e.source(),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.source(),
            Self::Implementation(e) => Some(e.as_ref()),
        }
    }
}

impl From<InternalPayloadError> for ReplyableError {
    fn from(e: InternalPayloadError) -> Self { ReplyableError::Payload(e.into()) }
}

/// An error that occurs during validation of the original PSBT payload sent by the sender.
///
/// This type provides a public abstraction over internal validation errors while maintaining a stable public API.
/// It handles various failure modes like:
/// - Invalid UTF-8 encoding
/// - PSBT parsing errors
/// - BIP-78 specific PSBT validation failures
/// - Fee rate validation
/// - Input ownership validation
/// - Previous transaction output validation
///
/// The error messages are formatted as JSON strings suitable for HTTP responses according to the BIP-78 spec,
/// with appropriate error codes and human-readable messages.
#[derive(Debug)]
pub struct PayloadError(pub(crate) InternalPayloadError);

impl From<InternalPayloadError> for PayloadError {
    fn from(value: InternalPayloadError) -> Self { PayloadError(value) }
}

#[derive(Debug)]
pub(crate) enum InternalPayloadError {
    /// The payload is not valid utf-8
    Utf8(std::string::FromUtf8Error),
    /// The payload is not a valid PSBT
    ParsePsbt(bitcoin::psbt::PsbtParseError),
    /// Invalid sender parameters
    SenderParams(super::optional_parameters::Error),
    /// The raw PSBT fails bip78-specific validation.
    InconsistentPsbt(crate::psbt::InconsistentPsbt),
    /// The prevtxout is missing
    PrevTxOut(crate::psbt::PrevTxOutError),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// The original PSBT transaction fails the broadcast check
    OriginalPsbtNotBroadcastable,
    #[allow(dead_code)]
    /// The sender is trying to spend the receiver input
    InputOwned(bitcoin::ScriptBuf),
    /// The expected input weight cannot be determined
    InputWeight(crate::psbt::InputWeightError),
    #[allow(dead_code)]
    /// Original PSBT input has been seen before. Only automatic receivers, aka "interactive" in the spec
    /// look out for these to prevent probing attacks.
    InputSeen(bitcoin::OutPoint),
    /// Original PSBT fee rate is below minimum fee rate set by the receiver.
    ///
    /// First argument is the calculated fee rate of the original PSBT.
    ///
    /// Second argument is the minimum fee rate optionaly set by the receiver.
    PsbtBelowFeeRate(bitcoin::FeeRate, bitcoin::FeeRate),
    /// Effective receiver feerate exceeds maximum allowed feerate
    FeeTooHigh(bitcoin::FeeRate, bitcoin::FeeRate),
}

impl JsonError for PayloadError {
    fn to_json(&self) -> String {
        use InternalPayloadError::*;

        match &self.0 {
            Utf8(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            ParsePsbt(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion { supported_versions } => {
                    let supported_versions_json =
                        serde_json::to_string(supported_versions).unwrap_or_default();
                    serialize_json_plus_fields(
                        VERSION_UNSUPPORTED,
                        "This version of payjoin is not supported.",
                        &format!(r#""supported": {}"#, supported_versions_json),
                    )
                }
                _ => serialize_json_error("sender-params-error", self),
            },
            InconsistentPsbt(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            PrevTxOut(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            MissingPayment => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            OriginalPsbtNotBroadcastable => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            InputOwned(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            InputWeight(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            InputSeen(_) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            PsbtBelowFeeRate(_, _) => serialize_json_error(ORIGINAL_PSBT_REJECTED, self),
            FeeTooHigh(_, _) => serialize_json_error(NOT_ENOUGH_MONEY, self),
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalPayloadError::*;

        match &self.0 {
            Utf8(e) => write!(f, "{}", e),
            ParsePsbt(e) => write!(f, "{}", e),
            SenderParams(e) => write!(f, "{}", e),
            InconsistentPsbt(e) => write!(f, "{}", e),
            PrevTxOut(e) => write!(f, "PrevTxOut Error: {}", e),
            MissingPayment => write!(f, "Missing payment."),
            OriginalPsbtNotBroadcastable => write!(f, "Can't broadcast. PSBT rejected by mempool."),
            InputOwned(_) => write!(f, "The receiver rejected the original PSBT."),
            InputWeight(e) => write!(f, "InputWeight Error: {}", e),
            InputSeen(_) => write!(f, "The receiver rejected the original PSBT."),
            PsbtBelowFeeRate(original_psbt_fee_rate, receiver_min_fee_rate) => write!(
                f,
                "Original PSBT fee rate too low: {} < {}.",
                original_psbt_fee_rate, receiver_min_fee_rate
            ),
            FeeTooHigh(proposed_fee_rate, max_fee_rate) => write!(
                f,
                "Effective receiver feerate exceeds maximum allowed feerate: {} > {}",
                proposed_fee_rate, max_fee_rate
            ),
        }
    }
}

impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalPayloadError::*;
        match &self.0 {
            Utf8(e) => Some(e),
            ParsePsbt(e) => Some(e),
            SenderParams(e) => Some(e),
            InconsistentPsbt(e) => Some(e),
            PrevTxOut(e) => Some(e),
            InputWeight(e) => Some(e),
            PsbtBelowFeeRate(_, _) => None,
            FeeTooHigh(_, _) => None,
            MissingPayment => None,
            OriginalPsbtNotBroadcastable => None,
            InputOwned(_) => None,
            InputSeen(_) => None,
        }
    }
}

/// Error that may occur when output substitution fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct OutputSubstitutionError(InternalOutputSubstitutionError);

#[derive(Debug)]
pub(crate) enum InternalOutputSubstitutionError {
    /// Output substitution is disabled
    OutputSubstitutionDisabled(&'static str),
    /// Current output substitution implementation doesn't support reducing the number of outputs
    NotEnoughOutputs,
    /// The provided drain script could not be identified in the provided replacement outputs
    InvalidDrainScript,
}

impl fmt::Display for OutputSubstitutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalOutputSubstitutionError::OutputSubstitutionDisabled(reason) => write!(f, "{}", &format!("Output substitution is disabled: {}", reason)),
            InternalOutputSubstitutionError::NotEnoughOutputs => write!(
                f,
                "Current output substitution implementation doesn't support reducing the number of outputs"
            ),
            InternalOutputSubstitutionError::InvalidDrainScript =>
                write!(f, "The provided drain script could not be identified in the provided replacement outputs"),
        }
    }
}

impl From<InternalOutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: InternalOutputSubstitutionError) -> Self { OutputSubstitutionError(value) }
}

impl std::error::Error for OutputSubstitutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalOutputSubstitutionError::OutputSubstitutionDisabled(_) => None,
            InternalOutputSubstitutionError::NotEnoughOutputs => None,
            InternalOutputSubstitutionError::InvalidDrainScript => None,
        }
    }
}

/// Error that may occur when coin selection fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SelectionError(InternalSelectionError);

#[derive(Debug)]
pub(crate) enum InternalSelectionError {
    /// No candidates available for selection
    Empty,
    /// Current privacy selection implementation only supports 2-output transactions
    TooManyOutputs,
    /// No selection candidates improve privacy
    NotFound,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSelectionError::Empty => write!(f, "No candidates available for selection"),
            InternalSelectionError::TooManyOutputs => write!(
                f,
                "Current privacy selection implementation only supports 2-output transactions"
            ),
            InternalSelectionError::NotFound =>
                write!(f, "No selection candidates improve privacy"),
        }
    }
}

impl error::Error for SelectionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalSelectionError::*;

        match &self.0 {
            Empty => None,
            TooManyOutputs => None,
            NotFound => None,
        }
    }
}
impl From<InternalSelectionError> for SelectionError {
    fn from(value: InternalSelectionError) -> Self { SelectionError(value) }
}

/// Error that may occur when input contribution fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct InputContributionError(InternalInputContributionError);

#[derive(Debug)]
pub(crate) enum InternalInputContributionError {
    /// Total input value is not enough to cover additional output value
    ValueTooLow,
}

impl fmt::Display for InputContributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalInputContributionError::ValueTooLow =>
                write!(f, "Total input value is not enough to cover additional output value"),
        }
    }
}

impl error::Error for InputContributionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalInputContributionError::ValueTooLow => None,
        }
    }
}

impl From<InternalInputContributionError> for InputContributionError {
    fn from(value: InternalInputContributionError) -> Self { InputContributionError(value) }
}

mod error;
pub(crate) use error::InternalRequestError;
pub use error::RequestError;

use super::*;
use crate::into_url::IntoUrl;

/// 4_000_000 * 4 / 3 fits in u32
const MAX_CONTENT_LENGTH: usize = 4_000_000 * 4 / 3;
const SUPPORTED_VERSIONS: &[usize] = &[1];

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub fn build_v1_pj_uri<'a>(
    address: &bitcoin::Address,
    endpoint: impl IntoUrl,
    disable_output_substitution: bool,
) -> Result<crate::uri::PjUri<'a>, crate::into_url::Error> {
    let extras =
        crate::uri::PayjoinExtras { endpoint: endpoint.into_url()?, disable_output_substitution };
    Ok(bitcoin_uri::Uri::with_extras(address.clone(), extras))
}

impl UncheckedProposal {
    pub fn from_request(
        body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, ReplyableError> {
        let parsed_body = parse_body(headers, body).map_err(ReplyableError::V1)?;

        let base64 = String::from_utf8(parsed_body).map_err(InternalPayloadError::Utf8)?;

        let (psbt, params) = crate::receive::parse_payload(base64, query, SUPPORTED_VERSIONS)
            .map_err(ReplyableError::Payload)?;

        Ok(UncheckedProposal { psbt, params })
    }
}

/// Validate the request headers for a Payjoin request
///
/// [`RequestError`] should only be produced here.
fn parse_body(
    headers: impl Headers,
    mut body: impl std::io::Read,
) -> Result<Vec<u8>, RequestError> {
    let content_type = headers
        .get_header("content-type")
        .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
    if !content_type.starts_with("text/plain") {
        return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
    }

    let content_length = headers
        .get_header("content-length")
        .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
        .parse::<usize>()
        .map_err(InternalRequestError::InvalidContentLength)?;
    if content_length > MAX_CONTENT_LENGTH {
        return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
    }

    let mut buf = vec![0; content_length];
    body.read_exact(&mut buf).map_err(InternalRequestError::Io)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Address, AddressType};

    use super::*;
    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    #[test]
    fn test_from_request() -> Result<(), Box<dyn std::error::Error>> {
        let body = super::test::ORIGINAL_PSBT.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        let proposal = UncheckedProposal::from_request(body, super::test::QUERY_PARAMS, headers)?;

        let witness_utxo =
            proposal.psbt.inputs[0].witness_utxo.as_ref().expect("witness_utxo should be present");
        let address =
            Address::from_script(&witness_utxo.script_pubkey, bitcoin::params::Params::MAINNET)?;
        assert_eq!(address.address_type(), Some(AddressType::P2sh));

        assert_eq!(proposal.params.v, 1);
        assert_eq!(proposal.params.additional_fee_contribution, Some((Amount::from_sat(182), 0)));
        Ok(())
    }
}

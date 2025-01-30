use std::str::FromStr;
mod error;
pub(crate) use error::InternalRequestError;
pub use error::RequestError;

use super::*;
use crate::into_url::IntoUrl;
use crate::receive::optional_parameters::Params;
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
        mut body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, Error> {
        let content_type = headers
            .get_header("content-type")
            .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if !content_type.starts_with("text/plain") {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut buf = vec![0; content_length as usize]; // 4_000_000 * 4 / 3 fits in u32
        body.read_exact(&mut buf).map_err(InternalRequestError::Io)?;
        let base64 = String::from_utf8(buf).map_err(InternalPayloadError::Utf8)?;
        let unchecked_psbt = Psbt::from_str(&base64).map_err(InternalPayloadError::ParsePsbt)?;

        let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
        log::debug!("Received original psbt: {:?}", psbt);

        let pairs = url::form_urlencoded::parse(query.as_bytes());
        let params = Params::from_query_pairs(pairs, SUPPORTED_VERSIONS)
            .map_err(InternalPayloadError::SenderParams)?;
        log::debug!("Received request with params: {:?}", params);

        // TODO check that params are valid for the request's Original PSBT

        Ok(UncheckedProposal { psbt, params })
    }
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

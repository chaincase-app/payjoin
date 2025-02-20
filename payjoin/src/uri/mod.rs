use std::borrow::Cow;

use bitcoin::address::NetworkChecked;
pub use error::PjParseError;
use url::Url;

#[cfg(feature = "v2")]
pub(crate) use crate::directory::ShortId;
use crate::uri::error::InternalPjParseError;
#[cfg(feature = "v2")]
pub(crate) use crate::uri::url_ext::UrlExt;

pub mod error;
#[cfg(feature = "v2")]
pub(crate) mod url_ext;

#[derive(Debug, Clone)]
pub enum MaybePayjoinExtras {
    Supported(PayjoinExtras),
    Unsupported,
}

impl MaybePayjoinExtras {
    pub fn pj_is_supported(&self) -> bool {
        match self {
            MaybePayjoinExtras::Supported(_) => true,
            MaybePayjoinExtras::Unsupported => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayjoinExtras {
    pub(crate) endpoint: Url,
    pub(crate) disable_output_substitution: bool,
}

impl PayjoinExtras {
    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

pub type Uri<'a, NetworkValidation> = bitcoin_uri::Uri<'a, NetworkValidation, MaybePayjoinExtras>;
pub type PjUri<'a> = bitcoin_uri::Uri<'a, NetworkChecked, PayjoinExtras>;

mod sealed {
    use bitcoin::address::NetworkChecked;

    pub trait UriExt: Sized {}

    impl UriExt for super::Uri<'_, NetworkChecked> {}
    impl UriExt for super::PjUri<'_> {}
}

pub trait UriExt<'a>: sealed::UriExt {
    // Error type is boxed to reduce the size of the Result
    // (See https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err)
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bitcoin_uri::Uri<'a>>>;
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bitcoin_uri::Uri<'a>>> {
        match self.extras {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut uri = bitcoin_uri::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            MaybePayjoinExtras::Unsupported => {
                let mut uri = bitcoin_uri::Uri::new(self.address);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Err(Box::new(uri))
            }
        }
    }
}

impl PayjoinExtras {
    pub fn is_output_substitution_disabled(&self) -> bool { self.disable_output_substitution }
}

impl bitcoin_uri::de::DeserializationError for MaybePayjoinExtras {
    type Error = PjParseError;
}

impl bitcoin_uri::de::DeserializeParams<'_> for MaybePayjoinExtras {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<bool>,
}

impl bitcoin_uri::SerializeParams for &MaybePayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        match self {
            MaybePayjoinExtras::Supported(extras) => extras.serialize_params(),
            MaybePayjoinExtras::Unsupported => vec![].into_iter(),
        }
    }
}

impl bitcoin_uri::SerializeParams for &PayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        // normalizing to uppercase enables QR alphanumeric mode encoding
        // unfortunately Url normalizes these to be lowercase
        let scheme = self.endpoint.scheme();
        let host = self.endpoint.host_str().expect("host must be set");
        let endpoint_str = self
            .endpoint
            .as_str()
            .replacen(scheme, &scheme.to_uppercase(), 1)
            .replacen(host, &host.to_uppercase(), 1);

        vec![
            ("pjos", if self.disable_output_substitution { "0" } else { "1" }.to_string()),
            ("pj", endpoint_str),
        ]
        .into_iter()
    }
}

impl bitcoin_uri::de::DeserializationState<'_> for DeserializationState {
    type Value = MaybePayjoinExtras;

    fn is_param_known(&self, param: &str) -> bool { matches!(param, "pj" | "pjos") }

    fn deserialize_temp(
        &mut self,
        key: &str,
        value: bitcoin_uri::Param<'_>,
    ) -> std::result::Result<
        bitcoin_uri::de::ParamKind,
        <Self::Value as bitcoin_uri::DeserializationError>::Error,
    > {
        match key {
            "pj" if self.pj.is_none() => {
                let endpoint = Cow::try_from(value).map_err(|_| InternalPjParseError::NotUtf8)?;
                let url = Url::parse(&endpoint).map_err(|_| InternalPjParseError::BadEndpoint)?;
                self.pj = Some(url);

                Ok(bitcoin_uri::de::ParamKind::Known)
            }
            "pj" => Err(InternalPjParseError::DuplicateParams("pj").into()),
            "pjos" if self.pjos.is_none() => {
                match &*Cow::try_from(value).map_err(|_| InternalPjParseError::BadPjOs)? {
                    "0" => self.pjos = Some(true),
                    "1" => self.pjos = Some(false),
                    _ => return Err(InternalPjParseError::BadPjOs.into()),
                }
                Ok(bitcoin_uri::de::ParamKind::Known)
            }
            "pjos" => Err(InternalPjParseError::DuplicateParams("pjos").into()),
            _ => Ok(bitcoin_uri::de::ParamKind::Unknown),
        }
    }

    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bitcoin_uri::DeserializationError>::Error>
    {
        match (self.pj, self.pjos) {
            (None, None) => Ok(MaybePayjoinExtras::Unsupported),
            (None, Some(_)) => Err(InternalPjParseError::MissingEndpoint.into()),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(MaybePayjoinExtras::Supported(PayjoinExtras {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                    }))
                } else {
                    Err(InternalPjParseError::UnsecureEndpoint.into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn test_short() {
        assert!(Uri::try_from("").is_err());
        assert!(Uri::try_from("bitcoin").is_err());
        assert!(Uri::try_from("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(Uri::try_from(uri).is_err(), "pj url should be url encoded");
    }

    #[test]
    fn test_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
        assert!(Uri::try_from(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_missing_amount() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(Uri::try_from(uri).is_ok(), "missing amount should be ok");
    }

    #[test]
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
    }

    #[test]
    fn test_valid_uris() {
        let https = "https://example.com";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

        let base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in [base58, bech32_upper, bech32_lower].iter() {
            for pj in [https, onion].iter() {
                let uri_with_amount = format!("{}?amount=1&pj={}", address, pj);
                assert!(Uri::try_from(uri_with_amount).is_ok());

                let uri_without_amount = format!("{}?pj={}", address, pj);
                assert!(Uri::try_from(uri_without_amount).is_ok());

                let uri_shuffled_params = format!("{}?pj={}&amount=1", address, pj);
                assert!(Uri::try_from(uri_shuffled_params).is_ok());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        assert!(!Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
            .unwrap()
            .extras
            .pj_is_supported());
    }

    #[test]
    fn test_pjos_parameter() {
        // pjos=0 should disable output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=0";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert!(extras.is_output_substitution_disabled()),
            _ => panic!("Expected Supported PayjoinExtras"),
        }

        // pjos=1 should allow output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=1";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert!(!extras.is_output_substitution_disabled()),
            _ => panic!("Expected Supported PayjoinExtras"),
        }
    }
}

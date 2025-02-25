use std::borrow::Borrow;
use std::fmt;

use bitcoin::FeeRate;
use log::warn;

#[derive(Debug, Clone)]
pub(crate) struct Params {
    // version
    pub v: usize,
    // disableoutputsubstitution
    pub disable_output_substitution: bool,
    // maxadditionalfeecontribution, additionalfeeoutputindex
    pub additional_fee_contribution: Option<(bitcoin::Amount, usize)>,
    // minfeerate
    pub min_fee_rate: FeeRate,
    #[cfg(feature = "multiparty")]
    /// Opt in to optimistic psbt merge
    pub optimistic_merge: bool,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            v: 1,
            disable_output_substitution: false,
            additional_fee_contribution: None,
            min_fee_rate: FeeRate::BROADCAST_MIN,
            #[cfg(feature = "multiparty")]
            optimistic_merge: false,
        }
    }
}

impl Params {
    pub fn from_query_pairs<K, V, I>(
        pairs: I,
        supported_versions: &'static [usize],
    ) -> Result<Self, Error>
    where
        I: Iterator<Item = (K, V)>,
        K: Borrow<str> + Into<String>,
        V: Borrow<str> + Into<String>,
    {
        let mut params = Params::default();

        let mut additional_fee_output_index = None;
        let mut max_additional_fee_contribution = None;

        for (key, v) in pairs {
            match (key.borrow(), v.borrow()) {
                ("v", version) =>
                    params.v = match version.parse::<usize>() {
                        Ok(version) if supported_versions.contains(&version) => version,
                        _ => return Err(Error::UnknownVersion { supported_versions }),
                    },
                ("additionalfeeoutputindex", index) =>
                    additional_fee_output_index = match index.parse::<usize>() {
                        Ok(index) => Some(index),
                        Err(_error) => {
                            warn!(
                                "bad `additionalfeeoutputindex` query value '{}': {}",
                                index, _error
                            );
                            None
                        }
                    },
                ("maxadditionalfeecontribution", fee) =>
                    max_additional_fee_contribution =
                        match bitcoin::Amount::from_str_in(fee, bitcoin::Denomination::Satoshi) {
                            Ok(contribution) => Some(contribution),
                            Err(_error) => {
                                warn!(
                                    "bad `maxadditionalfeecontribution` query value '{}': {}",
                                    fee, _error
                                );
                                None
                            }
                        },
                ("minfeerate", fee_rate) =>
                    params.min_fee_rate = match fee_rate.parse::<f32>() {
                        Ok(fee_rate_sat_per_vb) => {
                            // TODO Parse with serde when rust-bitcoin supports it
                            let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
                            // since it's a minnimum, we want to round up
                            FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64)
                        }
                        Err(_) => return Err(Error::FeeRate),
                    },
                ("disableoutputsubstitution", v) =>
                    params.disable_output_substitution = v == "true",
                #[cfg(feature = "multiparty")]
                ("optimisticmerge", v) => params.optimistic_merge = v == "true",
                _ => (),
            }
        }

        match (max_additional_fee_contribution, additional_fee_output_index) {
            (Some(amount), Some(index)) =>
                params.additional_fee_contribution = Some((amount, index)),
            (Some(_), None) | (None, Some(_)) => {
                warn!("only one additional-fee parameter specified: {:?}", params);
            }
            _ => (),
        }

        log::debug!("parsed optional parameters: {:?}", params);
        Ok(params)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    UnknownVersion { supported_versions: &'static [usize] },
    FeeRate,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownVersion { .. } => write!(f, "unknown version"),
            Error::FeeRate => write!(f, "could not parse feerate"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

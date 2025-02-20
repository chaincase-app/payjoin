use std::path::PathBuf;

use anyhow::Result;
use clap::ArgMatches;
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use payjoin::bitcoin::FeeRate;
use serde::Deserialize;
use url::Url;

use crate::db;

type Builder = config::builder::ConfigBuilder<DefaultState>;

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    pub rpchost: Url,
    pub cookie: Option<PathBuf>,
    pub rpcuser: String,
    pub rpcpassword: String,
}

#[cfg(feature = "v1")]
#[derive(Debug, Clone, Deserialize)]
pub struct V1Config {
    pub port: u16,
    pub pj_endpoint: Url,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    pub ohttp_relay: Url,
    pub pj_directory: Url,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "version")]
pub enum VersionConfig {
    #[cfg(feature = "v1")]
    #[serde(rename = "v1")]
    V1(V1Config),
    #[cfg(feature = "v2")]
    #[serde(rename = "v2")]
    V2(V2Config),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub db_path: PathBuf,
    pub max_fee_rate: Option<FeeRate>,
    pub bitcoind: BitcoindConfig,
    #[serde(skip)]
    pub version: Option<VersionConfig>,
}

impl Config {
    /// Version flags in order of precedence (newest to oldest)
    const VERSION_FLAGS: &'static [(&'static str, u8)] = &[("bip77", 2), ("bip78", 1)];

    /// Check for multiple version flags and return the highest precedence version
    fn determine_version(matches: &ArgMatches) -> Result<u8, ConfigError> {
        let mut selected_version = None;
        for &(flag, version) in Self::VERSION_FLAGS.iter() {
            if matches.get_flag(flag) {
                if selected_version.is_some() {
                    return Err(ConfigError::Message(format!(
                        "Multiple version flags specified. Please use only one of: {}",
                        Self::VERSION_FLAGS
                            .iter()
                            .map(|(flag, _)| format!("--{}", flag))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                selected_version = Some(version);
            }
        }

        if let Some(version) = selected_version {
            return Ok(version);
        }

        #[cfg(feature = "v2")]
        return Ok(2);
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        return Ok(1);

        #[cfg(not(any(feature = "v1", feature = "v2")))]
        return Err(ConfigError::Message(
            "No valid version available - must compile with v1 or v2 feature".to_string(),
        ));
    }

    pub(crate) fn new(matches: &ArgMatches) -> Result<Self, ConfigError> {
        let mut builder = config::Config::builder();
        builder = add_bitcoind_defaults(builder, matches)?;
        builder = add_common_defaults(builder, matches)?;

        let version = Self::determine_version(matches)?;

        match version {
            1 => {
                #[cfg(feature = "v1")]
                {
                    builder = add_v1_defaults(builder)?;
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            2 => {
                #[cfg(feature = "v2")]
                {
                    builder = add_v2_defaults(builder, matches)?;
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
            _ => unreachable!("determine_version() should only return 1 or 2"),
        }

        builder = handle_subcommands(builder, matches)?;
        builder = builder.add_source(File::new("config.toml", FileFormat::Toml).required(false));

        let built_config = builder.build()?;

        let mut config = Config {
            db_path: built_config.get("db_path")?,
            max_fee_rate: built_config.get("max_fee_rate").ok(),
            bitcoind: built_config.get("bitcoind")?,
            version: None,
        };

        match version {
            1 => {
                #[cfg(feature = "v1")]
                {
                    if let Ok(v1) = built_config.get::<V1Config>("v1") {
                        config.version = Some(VersionConfig::V1(v1));
                    } else {
                        return Err(ConfigError::Message(
                            "V1 configuration is required for BIP78 mode".to_string(),
                        ));
                    }
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            2 => {
                #[cfg(feature = "v2")]
                {
                    if let Ok(v2) = built_config.get::<V2Config>("v2") {
                        config.version = Some(VersionConfig::V2(v2));
                    } else {
                        return Err(ConfigError::Message(
                            "V2 configuration is required for BIP77 mode".to_string(),
                        ));
                    }
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
            _ => unreachable!("determine_version() should only return 1 or 2"),
        }

        if config.version.is_none() {
            return Err(ConfigError::Message(
                "No valid version configuration found for the specified mode".to_string(),
            ));
        }

        log::debug!("App config: {:?}", config);
        Ok(config)
    }

    #[cfg(feature = "v1")]
    pub fn v1(&self) -> Result<&V1Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V1(v1_config)) => Ok(v1_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V1 configuration is required for BIP78 mode")),
        }
    }

    #[cfg(feature = "v2")]
    pub fn v2(&self) -> Result<&V2Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V2(v2_config)) => Ok(v2_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V2 configuration is required for v2 mode")),
        }
    }
}

/// Set up default values and CLI overrides for Bitcoin RPC connection settings
fn add_bitcoind_defaults(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    builder
        .set_default("bitcoind.rpchost", "http://localhost:18443")?
        .set_override_option(
            "bitcoind.rpchost",
            matches.get_one::<Url>("rpchost").map(|s| s.as_str()),
        )?
        .set_default("bitcoind.cookie", None::<String>)?
        .set_override_option(
            "bitcoind.cookie",
            matches.get_one::<String>("cookie_file").map(|s| s.as_str()),
        )?
        .set_default("bitcoind.rpcuser", "bitcoin")?
        .set_override_option(
            "bitcoind.rpcuser",
            matches.get_one::<String>("rpcuser").map(|s| s.as_str()),
        )?
        .set_default("bitcoind.rpcpassword", "")?
        .set_override_option(
            "bitcoind.rpcpassword",
            matches.get_one::<String>("rpcpassword").map(|s| s.as_str()),
        )
}

/// Set up default values and CLI overrides for common settings shared between v1 and v2
fn add_common_defaults(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    builder
        .set_default("db_path", db::DB_PATH)?
        .set_override_option("db_path", matches.get_one::<String>("db_path").map(|s| s.as_str()))
}

/// Set up default values for v1-specific settings when v2 is not enabled
#[cfg(feature = "v1")]
fn add_v1_defaults(builder: Builder) -> Result<Builder, ConfigError> {
    builder
        .set_default("v1.port", 3000_u16)?
        .set_default("v1.pj_endpoint", "https://localhost:3000")
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    builder
        .set_override_option(
            "v2.ohttp_relay",
            matches.get_one::<Url>("ohttp_relay").map(|s| s.as_str()),
        )?
        .set_default("v2.pj_directory", "https://payjo.in")?
        .set_default("v2.ohttp_keys", None::<String>)
}

/// Handles configuration overrides based on CLI subcommands
fn handle_subcommands(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    match matches.subcommand() {
        Some(("send", _)) => Ok(builder),
        Some(("receive", matches)) => {
            let builder = handle_receive_command(builder, matches)?;
            let max_fee_rate = matches.get_one::<FeeRate>("max_fee_rate");
            builder.set_override_option("max_fee_rate", max_fee_rate.map(|f| f.to_string()))
        }
        #[cfg(feature = "v2")]
        Some(("resume", _)) => Ok(builder),
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }
}

/// Handle configuration overrides specific to the receive command
fn handle_receive_command(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    #[cfg(feature = "v1")]
    let builder = {
        let port = matches
            .get_one::<String>("port")
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|_| ConfigError::Message("\"port\" must be a valid number".to_string()))?;
        builder.set_override_option("v1.port", port)?.set_override_option(
            "v1.pj_endpoint",
            matches.get_one::<Url>("pj_endpoint").map(|s| s.as_str()),
        )?
    };

    #[cfg(feature = "v2")]
    let builder = {
        builder
            .set_override_option(
                "v2.pj_directory",
                matches.get_one::<Url>("pj_directory").map(|s| s.as_str()),
            )?
            .set_override_option(
                "v2.ohttp_keys",
                matches.get_one::<String>("ohttp_keys").map(|s| s.as_str()),
            )?
    };

    Ok(builder)
}

#[cfg(feature = "v2")]
fn deserialize_ohttp_keys_from_path<'de, D>(
    deserializer: D,
) -> Result<Option<payjoin::OhttpKeys>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path_str: Option<String> = Option::deserialize(deserializer)?;

    match path_str {
        None => Ok(None),
        Some(path) => std::fs::read(path)
            .map_err(|e| serde::de::Error::custom(format!("Failed to read ohttp_keys file: {}", e)))
            .and_then(|bytes| {
                payjoin::OhttpKeys::decode(&bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed to decode ohttp keys: {}", e))
                })
            })
            .map(Some),
    }
}

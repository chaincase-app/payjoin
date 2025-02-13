use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::psbt::Input as PsbtInput;
use bitcoin::TxIn;
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::FeeRate;
use payjoin::receive::InputPair;
use payjoin::{bitcoin, PjUri};
use tokio::signal;
use tokio::sync::watch;

pub mod config;
use crate::app::config::Config;

#[cfg(feature = "v1")]
pub(crate) mod v1;
#[cfg(feature = "v2")]
pub(crate) mod v2;

#[cfg(feature = "_danger-local-https")]
pub const LOCAL_CERT_FILE: &str = "localhost.der";

#[async_trait::async_trait]
pub trait App {
    fn new(config: Config) -> Result<Self>
    where
        Self: Sized;
    fn bitcoind(&self) -> Result<bitcoincore_rpc::Client>;
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()>;
    async fn receive_payjoin(&self, amount: Amount) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn resume_payjoins(&self) -> Result<()>;

    fn create_original_psbt(&self, uri: &PjUri, fee_rate: FeeRate) -> Result<Psbt> {
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(uri.address.to_string(), amount);
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or(anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(bitcoin::Denomination::Satoshi));
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(fee_per_kvb),
            ..Default::default()
        };
        let psbt = self
            .bitcoind()?
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .context("Failed to create PSBT")?
            .psbt;
        let psbt = self
            .bitcoind()?
            .wallet_process_psbt(&psbt, None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let psbt = Psbt::from_str(&psbt).with_context(|| "Failed to load PSBT from base64")?;
        log::debug!("Original psbt: {:#?}", psbt);
        Ok(psbt)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
        log::debug!("Proposed psbt: {:#?}", psbt);
        let psbt = self
            .bitcoind()?
            .wallet_process_psbt(&psbt.to_string(), None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let tx = self
            .bitcoind()?
            .finalize_psbt(&psbt, Some(true))
            .with_context(|| "Failed to finalize PSBT")?
            .hex
            .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        let txid = self
            .bitcoind()?
            .send_raw_transaction(&tx)
            .with_context(|| "Failed to send raw transaction")?;
        println!("Payjoin sent. TXID: {}", txid);
        Ok(txid)
    }
}

#[cfg(feature = "_danger-local-https")]
fn http_agent() -> Result<reqwest::Client> { Ok(http_agent_builder()?.build()?) }

#[cfg(not(feature = "_danger-local-https"))]
fn http_agent() -> Result<reqwest::Client> { Ok(reqwest::Client::new()) }

#[cfg(feature = "_danger-local-https")]
fn http_agent_builder() -> Result<reqwest::ClientBuilder> {
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    let cert_der = read_local_cert()?;
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(CertificateDer::from(cert_der.as_slice()))?;
    Ok(reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?))
}

#[cfg(feature = "_danger-local-https")]
fn read_local_cert() -> Result<Vec<u8>> {
    let mut local_cert_path = std::env::temp_dir();
    local_cert_path.push(LOCAL_CERT_FILE);
    Ok(std::fs::read(local_cert_path)?)
}

pub fn input_pair_from_list_unspent(
    utxo: bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry,
) -> InputPair {
    let psbtin = PsbtInput {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(bitcoin::TxOut {
            value: utxo.amount,
            script_pubkey: utxo.script_pub_key.clone(),
        }),
        redeem_script: utxo.redeem_script.clone(),
        witness_script: utxo.witness_script.clone(),
        ..Default::default()
    };
    let txin = TxIn {
        previous_output: bitcoin::OutPoint { txid: utxo.txid, vout: utxo.vout },
        ..Default::default()
    };
    InputPair::new(txin, psbtin).expect("Input pair should be valid")
}

async fn handle_interrupt(tx: watch::Sender<()>) {
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("Error setting up Ctrl-C handler: {}", e);
    }
    let _ = tx.send(());
}

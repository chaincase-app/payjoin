use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::json::WalletCreateFundedPsbtOptions;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use payjoin::bitcoin::consensus::encode::{deserialize, serialize_hex};
use payjoin::bitcoin::consensus::Encodable;
use payjoin::bitcoin::psbt::{Input, Psbt};
use payjoin::bitcoin::{
    Address, Amount, Denomination, FeeRate, Network, OutPoint, Script, Transaction, TxIn, TxOut,
    Txid,
};
use payjoin::receive::InputPair;

/// Implementation of PayjoinWallet for bitcoind
#[derive(Clone, Debug)]
pub struct BitcoindWallet {
    pub bitcoind: std::sync::Arc<Client>,
}

impl BitcoindWallet {
    pub fn new(config: &crate::app::config::BitcoindConfig) -> Result<Self> {
        let client = match &config.cookie {
            Some(cookie) => Client::new(config.rpchost.as_str(), Auth::CookieFile(cookie.into())),
            None => Client::new(
                config.rpchost.as_str(),
                Auth::UserPass(config.rpcuser.clone(), config.rpcpassword.clone()),
            ),
        }?;
        Ok(Self { bitcoind: Arc::new(client) })
    }
}

impl BitcoindWallet {
    /// Create a PSBT with the given outputs and fee rate
    pub fn create_psbt(
        &self,
        outputs: HashMap<String, Amount>,
        fee_rate: FeeRate,
        lock_unspent: bool,
    ) -> Result<Psbt> {
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or_else(|| anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(Denomination::Satoshi));

        let options = WalletCreateFundedPsbtOptions {
            lock_unspent: Some(lock_unspent),
            fee_rate: Some(fee_per_kvb),
            ..Default::default()
        };

        let psbt = self
            .bitcoind
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
            .bitcoind
            .wallet_process_psbt(&psbt, None, None, None)
            .context("Failed to process PSBT")?
            .psbt;

        Psbt::from_str(&psbt).context("Failed to load PSBT from base64")
    }

    /// Process a PSBT, validating and signing inputs owned by this wallet
    ///
    /// Does not include bip32 derivations in the PSBT
    pub fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        let psbt_str = psbt.to_string();
        let processed = self
            .bitcoind
            .wallet_process_psbt(&psbt_str, None, None, Some(false))
            .context("Failed to process PSBT")?
            .psbt;
        Psbt::from_str(&processed).context("Failed to parse processed PSBT")
    }

    /// Finalize a PSBT and extract the transaction
    pub fn finalize_psbt(&self, psbt: &Psbt) -> Result<Transaction> {
        let result = self
            .bitcoind
            .finalize_psbt(&psbt.to_string(), Some(true))
            .context("Failed to finalize PSBT")?;
        let tx = deserialize(&result.hex.ok_or_else(|| anyhow!("Incomplete PSBT"))?)?;
        Ok(tx)
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let raw_tx = serialize_hex(&tx);
        let mempool_results = self.bitcoind.test_mempool_accept(&[raw_tx])?;
        match mempool_results.first() {
            Some(result) => Ok(result.allowed),
            None => Err(anyhow!("No mempool results returned on broadcast check",)),
        }
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        let mut serialized_tx = Vec::new();
        tx.consensus_encode(&mut serialized_tx)?;
        self.bitcoind
            .send_raw_transaction(&serialized_tx)
            .context("Failed to broadcast transaction")
    }

    /// Check if a script belongs to this wallet
    pub fn is_mine(&self, script: &Script) -> Result<bool> {
        if let Ok(address) = Address::from_script(script, self.network()?) {
            self.bitcoind
                .get_address_info(&address)
                .map(|info| info.is_mine.unwrap_or(false))
                .context("Failed to get address info")
        } else {
            Ok(false)
        }
    }

    /// Get a new address from the wallet
    pub fn get_new_address(&self) -> Result<Address> {
        self.bitcoind
            .get_new_address(None, None)
            .context("Failed to get new address")?
            .require_network(self.network()?)
            .context("Invalid network for address")
    }

    /// List unspent UTXOs
    pub fn list_unspent(&self) -> Result<Vec<InputPair>> {
        let unspent = self
            .bitcoind
            .list_unspent(None, None, None, None, None)
            .context("Failed to list unspent")?;
        Ok(unspent.into_iter().map(input_pair_from_list_unspent).collect())
    }

    /// Get the network this wallet is operating on
    pub fn network(&self) -> Result<Network> {
        self.bitcoind
            .get_blockchain_info()
            .map_err(|_| anyhow!("Failed to get blockchain info"))
            .map(|info| info.chain)
    }
}

pub fn input_pair_from_list_unspent(
    utxo: bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry,
) -> InputPair {
    let psbtin = Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(TxOut {
            value: utxo.amount,
            script_pubkey: utxo.script_pub_key.clone(),
        }),
        redeem_script: utxo.redeem_script.clone(),
        witness_script: utxo.witness_script.clone(),
        ..Default::default()
    };
    let txin = TxIn {
        previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
        ..Default::default()
    };
    InputPair::new(txin, psbtin).expect("Input pair should be valid")
}

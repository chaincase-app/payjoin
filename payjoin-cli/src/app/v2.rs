use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::Amount;
use payjoin::receive::v2::ActiveSession;
use payjoin::{base64, bitcoin, Error};

use super::config::AppConfig;
use super::App as AppTrait;
use crate::app::http_agent;
use crate::db::Database;

pub(crate) struct App {
    config: AppConfig,
    db: Database,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: AppConfig) -> Result<Self> {
        let db = Database::create(&config.db_path)?;
        let app = Self { config, db };
        app.bitcoind()?
            .get_blockchain_info()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn bitcoind(&self) -> Result<bitcoincore_rpc::Client> {
        match &self.config.bitcoind_cookie {
            Some(cookie) => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::CookieFile(cookie.into()),
            ),
            None => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::UserPass(
                    self.config.bitcoind_rpcuser.clone(),
                    self.config.bitcoind_rpcpassword.clone(),
                ),
            ),
        }
        .with_context(|| "Failed to connect to bitcoind")
    }

    async fn send_payjoin(&self, bip21: &str, fee_rate: &f32, is_retry: bool) -> Result<()> {
        let mut req_ctx = if is_retry {
            log::debug!("Resuming session");
            // Get a reference to RequestContext
            self.db.get_send_session()?.ok_or(anyhow!("No session found"))?
        } else {
            let mut req_ctx = self.create_pj_request(bip21, fee_rate)?;
            self.db.insert_send_session(&mut req_ctx)?;
            req_ctx
        };
        log::debug!("Awaiting response");
        let res = self.long_poll_post(&mut req_ctx).await?;
        self.process_pj_response(res)?;
        self.db.clear_send_session()?;
        Ok(())
    }

    async fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        use payjoin::receive::v2::SessionInitializer;

        let address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let mut initializer = SessionInitializer::new(
            address,
            self.config.pj_directory.clone(),
            ohttp_keys.clone(),
            self.config.ohttp_relay.clone(),
            std::time::Duration::from_secs(60 * 60),
        );
        let (req, ctx) =
            initializer.extract_req().map_err(|e| anyhow!("Failed to extract request {}", e))?;
        println!("Starting new Payjoin session with {}", self.config.pj_directory);
        let http = http_agent()?;
        let ohttp_response = http
            .post(req.url)
            .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)?;

        let session = initializer
            .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), ctx)
            .map_err(|_| anyhow!("Enrollment failed"))?;
        self.db.insert_recv_session(session.clone())?;
        self.spawn_payjoin_receiver(session, Some(amount)).await
    }
}

impl App {
    async fn spawn_payjoin_receiver(
        &self,
        mut session: ActiveSession,
        amount: Option<Amount>,
    ) -> Result<()> {
        println!("Receive session established");
        let mut pj_uri_builder = session.pj_uri_builder();
        if let Some(amount) = amount {
            pj_uri_builder = pj_uri_builder.amount(amount);
        }
        let pj_uri = pj_uri_builder.build();

        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);

        let res = self.long_poll_fallback(&mut session).await?;
        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&res.extract_tx_to_schedule_broadcast()));
        let mut payjoin_proposal = self
            .process_v2_proposal(res)
            .map_err(|e| anyhow!("Failed to process proposal {}", e))?;
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req()
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        println!("Got a request from the sender. Responding with a Payjoin proposal.");
        let http = http_agent()?;
        let res = http
            .post(req.url)
            .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        payjoin_proposal
            .process_res(res.bytes().await?.to_vec(), ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = payjoin_proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx().clone().txid()
        );
        self.db.clear_recv_session()?;
        Ok(())
    }

    pub async fn resume_payjoins(&self) -> Result<()> {
        let session = self.db.get_recv_session()?.ok_or(anyhow!("No session found"))?;
        println!("Resuming Payjoin session: {}", session.public_key());
        self.spawn_payjoin_receiver(session, None).await
    }

    async fn long_poll_post(&self, req_ctx: &mut payjoin::send::RequestContext) -> Result<Psbt> {
        loop {
            let (req, ctx) = req_ctx.extract_v2(self.config.ohttp_relay.clone())?;
            println!("Polling send request...");
            let http = http_agent()?;
            let response = http
                .post(req.url)
                .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            println!("Sent fallback transaction");
            match ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => {
                    println!("No response yet.");
                    std::thread::sleep(std::time::Duration::from_secs(5))
                }
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: &mut payjoin::receive::v2::ActiveSession,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) =
                session.extract_req().map_err(|_| anyhow!("Failed to extract request"))?;
            println!("Polling receive request...");
            let http = http_agent()?;
            let ohttp_response = http
                .post(req.url)
                .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            let proposal = session
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context)
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            match proposal {
                Some(proposal) => break Ok(proposal),
                None => std::thread::sleep(std::time::Duration::from_secs(5)),
            }
        }
    }

    fn process_v2_proposal(
        &self,
        proposal: payjoin::receive::v2::UncheckedProposal,
    ) -> Result<payjoin::receive::v2::PayjoinProposal, Error> {
        use crate::app::try_contributing_inputs;

        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            let mempool_results =
                bitcoind.test_mempool_accept(&[raw_tx]).map_err(|e| Error::Server(e.into()))?;
            match mempool_results.first() {
                Some(result) => Ok(result.allowed),
                None => Err(Error::Server(
                    anyhow!("No mempool results returned on broadcast check").into(),
                )),
            }
        })?;
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            if let Ok(address) = bitcoin::Address::from_script(input, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;
        log::trace!("check2");
        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts()?;
        log::trace!("check3");

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal.check_no_inputs_seen_before(|input| {
            self.db.insert_input_seen_before(*input).map_err(|e| Error::Server(e.into()))
        })?;
        log::trace!("check4");

        let mut provisional_payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        _ = try_contributing_inputs(&mut provisional_payjoin.inner, &bitcoind)
            .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));

        if !provisional_payjoin.is_output_substitution_disabled() {
            // Substitute the receiver output address.
            let receiver_substitute_address = bitcoind
                .get_new_address(None, None)
                .map_err(|e| Error::Server(e.into()))?
                .assume_checked();
            provisional_payjoin.substitute_output_address(receiver_substitute_address);
        }

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, Some(false))
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);
        Ok(payjoin_proposal)
    }
}

async fn unwrap_ohttp_keys_or_else_fetch(config: &AppConfig) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let ohttp_relay = config.ohttp_relay.clone();
        let payjoin_directory = config.pj_directory.clone();
        #[cfg(feature = "danger-local-https")]
        let cert_der = rcgen::generate_simple_self_signed(vec![
            "0.0.0.0".to_string(),
            "localhost".to_string(),
        ])?
        .serialize_der()?;
        Ok(payjoin::io::fetch_ohttp_keys(
            ohttp_relay,
            payjoin_directory,
            #[cfg(feature = "danger-local-https")]
            cert_der,
        )
        .await?)
    }
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}

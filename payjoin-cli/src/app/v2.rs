use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::receive::v2::{Receiver, UncheckedProposal};
use payjoin::receive::{Error, ImplementationError, ReplyableError};
use payjoin::send::v2::{Sender, SenderBuilder};
use payjoin::{bitcoin, Uri};
use tokio::sync::watch;

use super::config::AppConfig;
use super::App as AppTrait;
use crate::app::{handle_interrupt, http_agent, input_pair_from_list_unspent};
use crate::db::Database;

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    db: Arc<Database>,
    interrupt: watch::Receiver<()>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: AppConfig) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let app = Self { config, db, interrupt: interrupt_rx };
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

    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        use payjoin::UriExt;
        let uri =
            Uri::try_from(bip21).map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;
        let uri = uri.assume_checked();
        let uri = uri.check_pj_supported().map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let url = uri.extras.endpoint();
        // match bip21 to send_session public_key
        let req_ctx = match self.db.get_send_session(url)? {
            Some(send_session) => send_session,
            None => {
                let psbt = self.create_original_psbt(&uri, fee_rate)?;
                let mut req_ctx = SenderBuilder::new(psbt, uri.clone())
                    .build_recommended(fee_rate)
                    .with_context(|| "Failed to build payjoin request")?;
                self.db.insert_send_session(&mut req_ctx, url)?;
                req_ctx
            }
        };
        self.spawn_payjoin_sender(req_ctx).await
    }

    async fn receive_payjoin(self, amount: Amount) -> Result<()> {
        let address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let session =
            Receiver::new(address, self.config.pj_directory.clone(), ohttp_keys.clone(), None)?;
        self.db.insert_recv_session(session.clone())?;
        self.spawn_payjoin_receiver(session, Some(amount)).await
    }
}

impl App {
    #[allow(clippy::incompatible_msrv)]
    async fn spawn_payjoin_sender(&self, mut req_ctx: Sender) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.long_poll_post(&mut req_ctx) => {
                self.process_pj_response(res?)?;
                self.db.clear_send_session(req_ctx.endpoint())?;
            }
            _ = interrupt.changed() => {
                println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
            }
        }
        Ok(())
    }

    #[allow(clippy::incompatible_msrv)]
    async fn spawn_payjoin_receiver(
        &self,
        mut session: Receiver,
        amount: Option<Amount>,
    ) -> Result<()> {
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = amount;

        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);

        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(&mut session) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Ok(());
            }
        }?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&receiver.extract_tx_to_schedule_broadcast()));
        let mut payjoin_proposal = match self.process_v2_proposal(receiver.clone()) {
            Ok(proposal) => proposal,
            Err(Error::ReplyToSender(e)) => {
                return Err(handle_recoverable_error(e, receiver, &self.config.ohttp_relay).await);
            }
            Err(e) => return Err(e.into()),
        };
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req(&self.config.ohttp_relay)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        println!("Got a request from the sender. Responding with a Payjoin proposal.");
        let res = post_request(req).await?;
        payjoin_proposal
            .process_res(&res.bytes().await?, ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = payjoin_proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().clone().compute_txid()
        );
        self.db.clear_recv_session()?;
        Ok(())
    }

    #[allow(clippy::incompatible_msrv)]
    pub async fn resume_payjoins(&self) -> Result<()> {
        let recv_sessions = self.db.get_recv_sessions()?;
        let send_sessions = self.db.get_send_sessions()?;

        if recv_sessions.is_empty() && send_sessions.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        for session in recv_sessions {
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move {
                self_clone.spawn_payjoin_receiver(session, None).await
            }));
        }

        for session in send_sessions {
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move { self_clone.spawn_payjoin_sender(session).await }));
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = async {
                for task in tasks {
                    let _ = task.await;
                }
            } => {
                println!("All resumed sessions completed.");
            }
            _ = interrupt.changed() => {
                println!("Resumed sessions were interrupted.");
            }
        }
        Ok(())
    }

    async fn long_poll_post(&self, req_ctx: &mut Sender) -> Result<Psbt> {
        match req_ctx.extract_v2(self.config.ohttp_relay.clone()) {
            Ok((req, ctx)) => {
                println!("Posting Original PSBT Payload request...");
                let response = post_request(req).await?;
                println!("Sent fallback transaction");
                let v2_ctx = Arc::new(ctx.process_response(&response.bytes().await?)?);
                loop {
                    let (req, ohttp_ctx) = v2_ctx.extract_req(self.config.ohttp_relay.clone())?;
                    let response = post_request(req).await?;
                    match v2_ctx.process_response(&response.bytes().await?, ohttp_ctx) {
                        Ok(Some(psbt)) => return Ok(psbt),
                        Ok(None) => {
                            println!("No response yet.");
                        }
                        Err(re) => {
                            println!("{}", re);
                            log::debug!("{:?}", re);
                            return Err(anyhow!("Response error").context(re));
                        }
                    }
                }
            }
            Err(_) => {
                let (req, v1_ctx) = req_ctx.extract_v1()?;
                println!("Posting Original PSBT Payload request...");
                let response = post_request(req).await?;
                println!("Sent fallback transaction");
                match v1_ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()) {
                    Ok(psbt) => Ok(psbt),
                    Err(re) => {
                        println!("{}", re);
                        log::debug!("{:?}", re);
                        Err(anyhow!("Response error").context(re))
                    }
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: &mut payjoin::receive::v2::Receiver,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) = session.extract_req(&self.config.ohttp_relay)?;
            println!("Polling receive request...");
            let ohttp_response = post_request(req).await?;
            let proposal = session
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context)
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            if let Some(proposal) = proposal {
                break Ok(proposal);
            }
        }
    }

    fn process_v2_proposal(
        &self,
        proposal: payjoin::receive::v2::UncheckedProposal,
    ) -> Result<payjoin::receive::v2::PayjoinProposal, Error> {
        let bitcoind = self.bitcoind().map_err(|e| ReplyableError::Implementation(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network = bitcoind
            .get_blockchain_info()
            .map_err(|e| ReplyableError::Implementation(e.into()))?
            .chain;
        // Receive Check 1: Can Broadcast
        let proposal =
            proposal.check_broadcast_suitability(None, |tx| {
                let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
                let mempool_results = bitcoind.test_mempool_accept(&[raw_tx])?;
                match mempool_results.first() {
                    Some(result) => Ok(result.allowed),
                    None => Err(ImplementationError::from(
                        "No mempool results returned on broadcast check",
                    )),
                }
            })?;
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            if let Ok(address) = bitcoin::Address::from_script(input, network) {
                Ok(bitcoind.get_address_info(&address).map(|info| info.is_mine.unwrap_or(false))?)
            } else {
                Ok(false)
            }
        })?;
        log::trace!("check2");

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal
            .check_no_inputs_seen_before(|input| Ok(self.db.insert_input_seen_before(*input)?))?;
        log::trace!("check3");

        let payjoin = payjoin
            .identify_receiver_outputs(|output_script| {
                if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                    Ok(bitcoind
                        .get_address_info(&address)
                        .map(|info| info.is_mine.unwrap_or(false))?)
                } else {
                    Ok(false)
                }
            })?
            .commit_outputs();

        let provisional_payjoin = try_contributing_inputs(payjoin.clone(), &bitcoind)
            .map_err(ReplyableError::Implementation)?;

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                let res =
                    bitcoind.wallet_process_psbt(&psbt.to_string(), None, None, Some(false))?;
                Ok(Psbt::from_str(&res.psbt)?)
            },
            None,
            self.config.max_fee_rate,
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);
        Ok(payjoin_proposal)
    }
}

/// Handle request error by sending an error response over the directory
async fn handle_recoverable_error(
    e: ReplyableError,
    mut receiver: UncheckedProposal,
    ohttp_relay: &payjoin::Url,
) -> anyhow::Error {
    let (err_req, err_ctx) = match receiver.extract_err_req(&e, ohttp_relay) {
        Ok(req_ctx) => req_ctx,
        Err(e) => return anyhow!("Failed to extract error request: {}", e),
    };

    let err_response = match post_request(err_req).await {
        Ok(response) => response,
        Err(e) => return anyhow!("Failed to post error request: {}", e),
    };

    let err_bytes = match err_response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => return anyhow!("Failed to get error response bytes: {}", e),
    };

    if let Err(e) = receiver.process_err_res(&err_bytes, err_ctx) {
        return anyhow!("Failed to process error response: {}", e);
    }

    e.into()
}

fn try_contributing_inputs(
    payjoin: payjoin::receive::v2::WantsInputs,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<payjoin::receive::v2::ProvisionalProposal, ImplementationError> {
    let candidate_inputs = bitcoind
        .list_unspent(None, None, None, None, None)
        .map_err(ImplementationError::from)?
        .into_iter()
        .map(input_pair_from_list_unspent);

    let selected_input =
        payjoin.try_preserving_privacy(candidate_inputs).map_err(ImplementationError::from)?;

    Ok(payjoin
        .contribute_inputs(vec![selected_input])
        .map_err(ImplementationError::from)?
        .commit_inputs())
}

async fn unwrap_ohttp_keys_or_else_fetch(config: &AppConfig) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let ohttp_relay = config.ohttp_relay.clone();
        let payjoin_directory = config.pj_directory.clone();
        #[cfg(feature = "_danger-local-https")]
        let ohttp_keys = {
            let cert_der = crate::app::read_local_cert()?;
            payjoin::io::fetch_ohttp_keys_with_cert(ohttp_relay, payjoin_directory, cert_der)
                .await?
        };
        #[cfg(not(feature = "_danger-local-https"))]
        let ohttp_keys = payjoin::io::fetch_ohttp_keys(ohttp_relay, payjoin_directory).await?;
        Ok(ohttp_keys)
    }
}

async fn post_request(req: payjoin::Request) -> Result<reqwest::Response> {
    let http = http_agent()?;
    http.post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await
        .map_err(map_reqwest_err)
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}

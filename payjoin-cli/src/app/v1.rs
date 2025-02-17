use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, FeeRate};
use payjoin::receive::v1::{PayjoinProposal, UncheckedProposal};
use payjoin::receive::ImplementationError;
use payjoin::receive::ReplyableError::{self, Implementation, V1};
use payjoin::send::v1::SenderBuilder;
use payjoin::{Uri, UriExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::config::AppConfig;
use super::App as AppTrait;
use crate::app::{handle_interrupt, http_agent, input_pair_from_list_unspent};
use crate::db::Database;
#[cfg(feature = "_danger-local-https")]
pub const LOCAL_CERT_FILE: &str = "localhost.der";

struct Headers<'a>(&'a hyper::HeaderMap);
impl payjoin::receive::v1::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|v| v.to_str()).transpose().ok().flatten()
    }
}

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
        let uri =
            Uri::try_from(bip21).map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;
        let uri = uri.assume_checked();
        let uri = uri.check_pj_supported().map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let psbt = self.create_original_psbt(&uri, fee_rate)?;
        let (req, ctx) = SenderBuilder::new(psbt, uri.clone())
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?
            .extract_v1()?;
        let http = http_agent()?;
        let body = String::from_utf8(req.body.clone()).unwrap();
        println!("Sending fallback request to {}", &req.url);
        let response = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(body.clone())
            .send()
            .await
            .with_context(|| "HTTP request failed")?;
        let fallback_tx = Psbt::from_str(&body)
            .map_err(|e| anyhow!("Failed to load PSBT from base64: {}", e))?
            .extract_tx()?;
        println!("Sent fallback transaction txid: {}", fallback_tx.compute_txid());
        println!(
            "Sent fallback transaction hex: {:#}",
            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
        );
        let psbt = ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()).map_err(
            |e| {
                log::debug!("Error processing response: {:?}", e);
                anyhow!("Failed to process response {}", e)
            },
        )?;

        self.process_pj_response(psbt)?;
        Ok(())
    }

    async fn receive_payjoin(self, amount: Amount) -> Result<()> {
        let pj_uri_string = self.construct_payjoin_uri(amount, None)?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.port
        );
        println!("{}", pj_uri_string);

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.start_http_server() => { res?; }
            _ = interrupt.changed() => {
                println!("Interrupted.");
            }
        }
        Ok(())
    }
}

impl App {
    fn construct_payjoin_uri(
        &self,
        amount: Amount,
        fallback_target: Option<&str>,
    ) -> Result<String> {
        let pj_receiver_address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let pj_part = match fallback_target {
            Some(target) => target,
            None => self.config.pj_endpoint.as_str(),
        };
        let pj_part = payjoin::Url::parse(pj_part)
            .map_err(|e| anyhow!("Failed to parse pj_endpoint: {}", e))?;

        let mut pj_uri =
            payjoin::receive::v1::build_v1_pj_uri(&pj_receiver_address, &pj_part, false)?;
        pj_uri.amount = Some(amount);

        Ok(pj_uri.to_string())
    }

    async fn start_http_server(self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));
        let listener = TcpListener::bind(addr).await?;
        let app = self.clone();

        #[cfg(feature = "_danger-local-https")]
        let tls_acceptor = Self::init_tls_acceptor()?;
        while let Ok((stream, _)) = listener.accept().await {
            let app = app.clone();
            #[cfg(feature = "_danger-local-https")]
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                #[cfg(feature = "_danger-local-https")]
                let stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        log::error!("TLS accept error: {}", e);
                        return;
                    }
                };

                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| app.clone().handle_web_request(req)),
                    )
                    .await;
            });
        }
        Ok(())
    }

    #[cfg(feature = "_danger-local-https")]
    fn init_tls_acceptor() -> Result<tokio_rustls::TlsAcceptor> {
        use std::io::Write;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio_rustls::TlsAcceptor;

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = cert.serialize_der()?;
        let mut local_cert_path = std::env::temp_dir();
        local_cert_path.push(LOCAL_CERT_FILE);
        let mut file = std::fs::File::create(local_cert_path)?;
        file.write_all(&cert_der)?;
        let key = PrivateKeyDer::try_from(cert.serialize_private_key_der())
            .map_err(|e| anyhow::anyhow!("Could not parse key: {}", e))?;
        let certs = vec![CertificateDer::from(cert_der)];
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        server_config.alpn_protocols =
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    async fn handle_web_request(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        log::debug!("Received request: {:?}", req);
        let mut response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/bip21") => {
                let query_string = req.uri().query().unwrap_or("");
                log::debug!("{:?}, {:?}", req.method(), query_string);
                let query_params: HashMap<_, _> =
                    url::form_urlencoded::parse(query_string.as_bytes()).into_owned().collect();
                let amount = query_params.get("amount").map(|amt| {
                    Amount::from_btc(amt.parse().expect("Failed to parse amount")).unwrap()
                });
                self.handle_get_bip21(amount)
                    .map_err(|e| {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(500).body(full(e.to_string())).unwrap()
                    })
                    .unwrap_or_else(|err_resp| err_resp)
            }
            (&Method::POST, _) => self
                .handle_payjoin_post(req)
                .await
                .map_err(|e| match e {
                    V1(e) => {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(400).body(full(e.to_string())).unwrap()
                    }
                    e => {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(500).body(full(e.to_string())).unwrap()
                    }
                })
                .unwrap_or_else(|err_resp| err_resp),
            _ => Response::builder().status(StatusCode::NOT_FOUND).body(full("Not found")).unwrap(),
        };
        response
            .headers_mut()
            .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));
        Ok(response)
    }

    fn handle_get_bip21(
        &self,
        amount: Option<Amount>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ReplyableError> {
        let address = self
            .bitcoind()
            .map_err(|e| Implementation(e.into()))?
            .get_new_address(None, None)
            .map_err(|e| Implementation(e.into()))?
            .assume_checked();
        let uri_string = if let Some(amount) = amount {
            format!(
                "{}?amount={}&pj={}",
                address.to_qr_uri(),
                amount.to_btc(),
                self.config.pj_endpoint
            )
        } else {
            format!("{}?pj={}", address.to_qr_uri(), self.config.pj_endpoint)
        };
        let uri = Uri::try_from(uri_string.clone())
            .map_err(|_| Implementation(anyhow!("Could not parse payjoin URI string.").into()))?;
        let _ = uri.assume_checked(); // we just got it from bitcoind above

        Ok(Response::new(full(uri_string)))
    }

    async fn handle_payjoin_post(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ReplyableError> {
        let (parts, body) = req.into_parts();
        let headers = Headers(&parts.headers);
        let query_string = parts.uri.query().unwrap_or("");
        let body = body.collect().await.map_err(|e| Implementation(e.into()))?.aggregate().reader();
        let proposal = UncheckedProposal::from_request(body, query_string, headers)?;

        let payjoin_proposal = self.process_v1_proposal(proposal)?;
        let psbt = payjoin_proposal.psbt();
        let body = psbt.to_string();
        println!(
            "Responded with Payjoin proposal {}",
            psbt.clone().extract_tx_unchecked_fee_rate().compute_txid()
        );
        Ok(Response::new(full(body)))
    }

    fn process_v1_proposal(
        &self,
        proposal: UncheckedProposal,
    ) -> Result<PayjoinProposal, ReplyableError> {
        let bitcoind = self.bitcoind().map_err(|e| Implementation(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network = bitcoind.get_blockchain_info().map_err(|e| Implementation(e.into()))?.chain;

        // Receive Check 1: Can Broadcast
        let proposal =
            proposal.check_broadcast_suitability(None, |tx| {
                let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
                let mempool_results = bitcoind
                    .test_mempool_accept(&[raw_tx])
                    .map_err(|e| Implementation(e.into()))?;
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

        let payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                Ok(bitcoind.get_address_info(&address).map(|info| info.is_mine.unwrap_or(false))?)
            } else {
                Ok(false)
            }
        })?;

        let payjoin = payjoin
            .substitute_receiver_script(
                &bitcoind
                    .get_new_address(None, None)
                    .map_err(|e| Implementation(e.into()))?
                    .require_network(network)
                    .map_err(|e| Implementation(e.into()))?
                    .script_pubkey(),
            )
            .map_err(|e| Implementation(e.into()))?
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
        Ok(payjoin_proposal)
    }
}

fn try_contributing_inputs(
    payjoin: payjoin::receive::v1::WantsInputs,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<payjoin::receive::v1::ProvisionalProposal, ImplementationError> {
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

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

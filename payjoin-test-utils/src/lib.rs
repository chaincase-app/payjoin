use std::env;
use std::result::Result;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::json::AddressType;
use bitcoind::bitcoincore_rpc::{self, RpcApi};
use http::{StatusCode, Uri};
use log::{log_enabled, Level};
use once_cell::sync::OnceCell;
use payjoin::io::{fetch_ohttp_keys_with_cert, Error as IOError};
use payjoin::OhttpKeys;
use reqwest::{Client, ClientBuilder};
use testcontainers::{clients, Container};
use testcontainers_modules::redis::{Redis, REDIS_PORT};
use tokio::task::JoinHandle;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use url::Url;

pub type BoxError = Box<dyn std::error::Error + 'static>;
pub type BoxSendSyncError = Box<dyn std::error::Error + Send + Sync>;

static INIT_TRACING: OnceCell<()> = OnceCell::new();

pub fn init_tracing() {
    INIT_TRACING.get_or_init(|| {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("failed to set global default subscriber");
    });
}

pub struct TestServices {
    cert_key: (Vec<u8>, Vec<u8>),
    /// redis is an implicit dependency of the directory service
    #[allow(dead_code)]
    redis: (u16, Container<'static, Redis>),
    directory: (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>),
    ohttp_relay: (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>),
    http_agent: Arc<Client>,
}

impl TestServices {
    pub async fn initialize() -> Result<Self, BoxSendSyncError> {
        let cert_key = local_cert_key();
        let redis = init_redis();
        let db_host = format!("127.0.0.1:{}", redis.0);
        let directory = init_directory(db_host, cert_key.clone()).await?;
        let gateway_origin = Uri::from_str(&format!("https://localhost:{}", directory.0))?;
        let ohttp_relay = ohttp_relay::listen_tcp_on_free_port(gateway_origin).await?;
        let http_agent: Arc<Client> = Arc::new(http_agent(cert_key.0.clone())?);
        Ok(Self {
            cert_key,
            redis,
            directory: (directory.0, Some(directory.1)),
            ohttp_relay: (ohttp_relay.0, Some(ohttp_relay.1)),
            http_agent,
        })
    }

    pub fn cert(&self) -> Vec<u8> { self.cert_key.0.clone() }

    pub fn directory_url(&self) -> Url {
        Url::parse(&format!("https://localhost:{}", self.directory.0)).expect("invalid URL")
    }

    pub fn take_directory_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        self.directory.1.take().expect("directory handle not found")
    }

    pub fn ohttp_relay_url(&self) -> Url {
        Url::parse(&format!("http://localhost:{}", self.ohttp_relay.0)).expect("invalid URL")
    }

    pub fn ohttp_gateway_url(&self) -> Url {
        let url = self.directory_url();
        url.join("/.well-known/ohttp-gateway").expect("invalid URL")
    }

    pub fn take_ohttp_relay_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        self.ohttp_relay.1.take().expect("ohttp relay handle not found")
    }

    pub fn http_agent(&self) -> Arc<Client> { self.http_agent.clone() }

    pub async fn wait_for_services_ready(&self) -> Result<(), &'static str> {
        wait_for_service_ready(self.ohttp_relay_url(), self.http_agent()).await?;
        wait_for_service_ready(self.directory_url(), self.http_agent()).await?;
        Ok(())
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<OhttpKeys, IOError> {
        fetch_ohttp_keys_with_cert(self.ohttp_relay_url(), self.directory_url(), self.cert()).await
    }
}

pub fn init_redis() -> (u16, Container<'static, Redis>) {
    let docker = Box::leak(Box::new(clients::Cli::default()));
    let redis_instance = docker.run(Redis);
    let host_port = redis_instance.get_host_port_ipv4(REDIS_PORT);
    (host_port, redis_instance)
}

pub async fn init_directory(
    db_host: String,
    local_cert_key: (Vec<u8>, Vec<u8>),
) -> std::result::Result<
    (u16, tokio::task::JoinHandle<std::result::Result<(), BoxSendSyncError>>),
    BoxSendSyncError,
> {
    println!("Database running on {}", db_host);
    let timeout = Duration::from_secs(2);
    payjoin_directory::listen_tcp_with_tls_on_free_port(db_host, timeout, local_cert_key).await
}

/// generate or get a DER encoded localhost cert and key.
pub fn local_cert_key() -> (Vec<u8>, Vec<u8>) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["0.0.0.0".to_string(), "localhost".to_string()])
            .expect("Failed to generate cert");
    let cert_der = cert.serialize_der().expect("Failed to serialize cert");
    let key_der = cert.serialize_private_key_der();
    (cert_der, key_der)
}

pub fn init_bitcoind_sender_receiver(
    sender_address_type: Option<AddressType>,
    receiver_address_type: Option<AddressType>,
) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), BoxError> {
    let bitcoind_exe = env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .expect("bitcoind not found");
    let mut conf = bitcoind::Conf::default();
    conf.view_stdout = log_enabled!(Level::Debug);
    let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)?;
    let receiver = bitcoind.create_wallet("receiver")?;
    let receiver_address = receiver.get_new_address(None, receiver_address_type)?.assume_checked();
    let sender = bitcoind.create_wallet("sender")?;
    let sender_address = sender.get_new_address(None, sender_address_type)?.assume_checked();
    bitcoind.client.generate_to_address(1, &receiver_address)?;
    bitcoind.client.generate_to_address(101, &sender_address)?;

    assert_eq!(
        Amount::from_btc(50.0)?,
        receiver.get_balances()?.mine.trusted,
        "receiver doesn't own bitcoin"
    );

    assert_eq!(
        Amount::from_btc(50.0)?,
        sender.get_balances()?.mine.trusted,
        "sender doesn't own bitcoin"
    );
    Ok((bitcoind, sender, receiver))
}

pub fn http_agent(cert_der: Vec<u8>) -> Result<Client, BoxSendSyncError> {
    Ok(http_agent_builder(cert_der).build()?)
}

fn http_agent_builder(cert_der: Vec<u8>) -> ClientBuilder {
    ClientBuilder::new().danger_accept_invalid_certs(true).use_rustls_tls().add_root_certificate(
        reqwest::tls::Certificate::from_der(cert_der.as_slice())
            .expect("cert_der should be a valid DER-encoded certificate"),
    )
}

const TESTS_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_SERVICE_INTERVAL: Duration = Duration::from_secs(3);

pub async fn wait_for_service_ready(
    service_url: Url,
    agent: Arc<Client>,
) -> Result<(), &'static str> {
    let health_url = service_url.join("/health").map_err(|_| "Invalid URL")?;
    let start = std::time::Instant::now();

    while start.elapsed() < TESTS_TIMEOUT {
        let request_result =
            agent.get(health_url.as_str()).send().await.map_err(|_| "Bad request")?;
        match request_result.status() {
            StatusCode::OK => return Ok(()),
            StatusCode::NOT_FOUND => return Err("Endpoint not found"),
            _ => std::thread::sleep(WAIT_SERVICE_INTERVAL),
        }
    }

    Err("Timeout waiting for service to be ready")
}

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use payjoin::directory::{ShortId, ShortIdError, ENCAPSULATED_MESSAGE_BYTES};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace};

use crate::db::DbPool;

pub const DEFAULT_DIR_PORT: u16 = 8080;
pub const DEFAULT_DB_HOST: &str = "localhost:6379";
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

const CHACHA20_POLY1305_NONCE_LEN: usize = 32; // chacha20poly1305 n_k
const POLY1305_TAG_SIZE: usize = 16;
pub const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);
const V1_MAX_BUFFER_SIZE: usize = 65536;

const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;

mod db;

#[cfg(feature = "_danger-local-https")]
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "_danger-local-https")]
pub async fn listen_tcp_with_tls_on_free_port(
    db_host: String,
    timeout: Duration,
    cert_key: (Vec<u8>, Vec<u8>),
) -> Result<(u16, tokio::task::JoinHandle<Result<(), BoxError>>), BoxError> {
    let listener = tokio::net::TcpListener::bind("[::]:0").await?;
    let port = listener.local_addr()?.port();
    println!("Directory server binding to port {}", listener.local_addr()?);
    let handle = listen_tcp_with_tls_on_listener(listener, db_host, timeout, cert_key).await?;
    Ok((port, handle))
}

// Helper function to avoid code duplication
#[cfg(feature = "_danger-local-https")]
async fn listen_tcp_with_tls_on_listener(
    listener: tokio::net::TcpListener,
    db_host: String,
    timeout: Duration,
    tls_config: (Vec<u8>, Vec<u8>),
) -> Result<tokio::task::JoinHandle<Result<(), BoxError>>, BoxError> {
    let pool = DbPool::new(timeout, db_host).await?;
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let tls_acceptor = init_tls_acceptor(tls_config)?;
    // Spawn the connection handling loop in a separate task
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let pool = pool.clone();
            let ohttp = ohttp.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        error!("TLS accept error: {}", e);
                        return;
                    }
                };
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls_stream),
                        service_fn(move |req| {
                            serve_payjoin_directory(req, pool.clone(), ohttp.clone())
                        }),
                    )
                    .with_upgrades()
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
        Ok(())
    });
    Ok(handle)
}

// Modify existing listen_tcp_with_tls to use the new helper
pub async fn listen_tcp(
    port: u16,
    db_host: String,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = DbPool::new(timeout, db_host).await?;
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(bind_addr).await?;
    while let Ok((stream, _)) = listener.accept().await {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        serve_payjoin_directory(req, pool.clone(), ohttp.clone())
                    }),
                )
                .with_upgrades()
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }

    Ok(())
}

#[cfg(feature = "_danger-local-https")]
pub async fn listen_tcp_with_tls(
    port: u16,
    db_host: String,
    timeout: Duration,
    cert_key: (Vec<u8>, Vec<u8>),
) -> Result<tokio::task::JoinHandle<Result<(), BoxError>>, BoxError> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    listen_tcp_with_tls_on_listener(listener, db_host, timeout, cert_key).await
}

#[cfg(feature = "_danger-local-https")]
fn init_tls_acceptor(cert_key: (Vec<u8>, Vec<u8>)) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;
    let (cert, key) = cert_key;
    let cert = CertificateDer::from(cert);
    let key =
        PrivateKeyDer::try_from(key).map_err(|e| anyhow::anyhow!("Could not parse key: {}", e))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn init_ohttp() -> Result<ohttp::Server> {
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::K256Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    // create or read from file
    let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    info!("Initialized a new OHTTP Key Configuration. GET /ohttp-keys to fetch it.");
    Ok(ohttp::Server::new(server_config)?)
}

async fn serve_payjoin_directory(
    req: Request<Incoming>,
    pool: DbPool,
    ohttp: Arc<Mutex<ohttp::Server>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("serve_payjoin_directory: {:?}", &path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, ["", ".well-known", "ohttp-gateway"]) =>
            handle_ohttp_gateway(body, pool, ohttp).await,
        (Method::GET, ["", ".well-known", "ohttp-gateway"]) => get_ohttp_keys(&ohttp).await,
        (Method::POST, ["", ""]) => handle_ohttp_gateway(body, pool, ohttp).await,
        (Method::GET, ["", "ohttp-keys"]) => get_ohttp_keys(&ohttp).await,
        (Method::POST, ["", id]) => post_fallback_v1(id, query, body, pool).await,
        (Method::GET, ["", "health"]) => health_check().await,
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    Ok(response)
}

async fn handle_ohttp_gateway(
    body: Incoming,
    pool: DbPool,
    ohttp: Arc<Mutex<ohttp::Server>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    // decapsulate
    let ohttp_body =
        body.collect().await.map_err(|e| HandlerError::BadRequest(e.into()))?.to_bytes();
    let ohttp_locked = ohttp.lock().await;
    let (bhttp_req, res_ctx) = ohttp_locked
        .decapsulate(&ohttp_body)
        .map_err(|e| HandlerError::OhttpKeyRejection(e.into()))?;
    drop(ohttp_locked);
    let mut cursor = std::io::Cursor::new(bhttp_req);
    let req =
        bhttp::Message::read_bhttp(&mut cursor).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let uri = Uri::builder()
        .scheme(req.control().scheme().unwrap_or_default())
        .authority(req.control().authority().unwrap_or_default())
        .path_and_query(req.control().path().unwrap_or_default())
        .build()?;
    let body = req.content().to_vec();
    let mut http_req =
        Request::builder().uri(uri).method(req.control().method().unwrap_or_default());
    for header in req.header().fields() {
        http_req = http_req.header(header.name(), header.value())
    }
    let request = http_req.body(full(body))?;

    let response = handle_v2(pool, request).await?;

    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(parts.status.as_u16());
    for (name, value) in parts.headers.iter() {
        bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
    }
    let full_body =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();
    bhttp_res.write_content(&full_body);
    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    bhttp_bytes.resize(BHTTP_REQ_BYTES, 0);
    let ohttp_res = res_ctx
        .encapsulate(&bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    assert!(ohttp_res.len() == ENCAPSULATED_MESSAGE_BYTES, "Unexpected OHTTP response size");
    Ok(Response::new(full(ohttp_res)))
}

async fn handle_v2(
    pool: DbPool,
    req: Request<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("handle_v2: {:?}", &path_segments);
    match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", id]) => post_subdir(id, body, pool).await,
        (Method::GET, &["", id]) => get_subdir(id, pool).await,
        (Method::PUT, &["", id]) => put_payjoin_v1(id, body, pool).await,
        _ => Ok(not_found()),
    }
}

async fn health_check() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    Ok(Response::new(empty()))
}

#[derive(Debug)]
enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
}

impl HandlerError {
    fn to_response(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut res = Response::new(empty());
        match self {
            HandlerError::PayloadTooLarge => *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE,
            HandlerError::InternalServerError(e) => {
                error!("Internal server error: {}", e);
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR
            }
            HandlerError::OhttpKeyRejection(e) => {
                const OHTTP_KEY_REJECTION_RES_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;

                error!("Bad request: Key configuration rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
                *res.body_mut() = full(OHTTP_KEY_REJECTION_RES_JSON);
            }
            HandlerError::BadRequest(e) => {
                error!("Bad request: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST
            }
        };

        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(e: hyper::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

impl From<ShortIdError> for HandlerError {
    fn from(_: ShortIdError) -> Self {
        HandlerError::BadRequest(anyhow::anyhow!("subdirectory ID must be 13 bech32 characters"))
    }
}

fn handle_peek(
    result: db::Result<Vec<u8>>,
    timeout_response: Response<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    match result {
        Ok(buffered_req) => Ok(Response::new(full(buffered_req))),
        Err(e) => match e {
            db::Error::Redis(re) => {
                error!("Redis error: {}", re);
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            db::Error::Timeout(_) => Ok(timeout_response),
        },
    }
}

async fn post_fallback_v1(
    id: &str,
    query: String,
    body: impl Body,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("Post fallback v1");
    let none_response = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(full(V1_UNAVAILABLE_RES_JSON))?;
    let bad_request_body_res =
        Response::builder().status(StatusCode::BAD_REQUEST).body(full(V1_REJECT_RES_JSON))?;

    let body_bytes = match body.collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(_) => return Ok(bad_request_body_res),
    };

    let body_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(body_str) => body_str,
        Err(_) => return Ok(bad_request_body_res),
    };

    let v2_compat_body = format!("{}\n{}", body_str, query);
    let id = ShortId::from_str(id)?;
    pool.push_default(&id, v2_compat_body.into())
        .await
        .map_err(|e| HandlerError::BadRequest(e.into()))?;
    handle_peek(pool.peek_v1(&id).await, none_response)
}

async fn put_payjoin_v1(
    id: &str,
    body: BoxBody<Bytes, hyper::Error>,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("Put_payjoin_v1");
    let ok_response = Response::builder().status(StatusCode::OK).body(empty())?;

    let id = ShortId::from_str(id)?;
    let req =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();
    if req.len() > V1_MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_v1(&id, req.into()).await {
        Ok(_) => Ok(ok_response),
        Err(e) => Err(HandlerError::BadRequest(e.into())),
    }
}

async fn post_subdir(
    id: &str,
    body: BoxBody<Bytes, hyper::Error>,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let none_response = Response::builder().status(StatusCode::OK).body(empty())?;
    trace!("post_subdir");

    let id = ShortId::from_str(id)?;

    let req =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();
    if req.len() > V1_MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_default(&id, req.into()).await {
        Ok(_) => Ok(none_response),
        Err(e) => Err(HandlerError::BadRequest(e.into())),
    }
}

async fn get_subdir(
    id: &str,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("get_subdir");
    let id = ShortId::from_str(id)?;
    let timeout_response = Response::builder().status(StatusCode::ACCEPTED).body(empty())?;
    handle_peek(pool.peek_default(&id).await, timeout_response)
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

async fn get_ohttp_keys(
    ohttp: &Arc<Mutex<ohttp::Server>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let ohttp_keys = ohttp
        .lock()
        .await
        .config()
        .encode()
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    let mut res = Response::new(full(ohttp_keys));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
    Ok(res)
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

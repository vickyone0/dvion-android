use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::crypto::{
    client_derive_key, server_derive_key, ClientHello, ServerHello, SessionCipher,
};
use crate::tunnel;

/// Install the default rustls crypto provider. Safe to call multiple times.
pub fn install_crypto_provider() {
    rustls::crypto::ring::default_provider().install_default().ok();
}

// ── QUIC helpers ──────────────────────────────────────────────────────────────

async fn write_frame(stream: &mut SendStream, data: &[u8]) -> Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

async fn read_frame(stream: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65_536 {
        bail!("frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ── Cert persistence + fingerprint ───────────────────────────────────────────

/// Load the cert+key from `cert_dir`, or generate and save them if absent.
/// Returns `(cert_chain, private_key, sha256_fingerprint)`.
pub fn load_or_generate_cert(
    cert_dir: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, Vec<u8>)> {
    let dir = Path::new(cert_dir);
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");

    let (cert_bytes, key_bytes) = if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(&cert_path)
            .map_err(|e| anyhow!("read {}: {e}", cert_path.display()))?;
        let key = std::fs::read(&key_path)
            .map_err(|e| anyhow!("read {}: {e}", key_path.display()))?;
        tracing::debug!("loaded cert from {}", cert_path.display());
        (cert, key)
    } else {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(vec!["dvion-vpn".to_string()])?
            .self_signed(&key_pair)?;
        let cb = cert.der().to_vec();
        let kb = key_pair.serialize_der();
        std::fs::write(&cert_path, &cb)
            .map_err(|e| anyhow!("write {}: {e}", cert_path.display()))?;
        std::fs::write(&key_path, &kb)
            .map_err(|e| anyhow!("write {}: {e}", key_path.display()))?;
        tracing::info!("generated new cert → {}", cert_path.display());
        (cb, kb)
    };

    let fingerprint = Sha256::digest(&cert_bytes).to_vec();
    let cert = CertificateDer::from(cert_bytes);
    let key: PrivateKeyDer = PrivatePkcs8KeyDer::from(key_bytes).into();
    Ok((vec![cert], key, fingerprint))
}

/// Format a raw fingerprint as `AA:BB:CC:...` uppercase hex.
pub fn fmt_fingerprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a `AA:BB:CC:...` fingerprint string into raw bytes.
pub fn parse_fingerprint(s: &str) -> Result<Vec<u8>> {
    let bytes = s
        .split(':')
        .map(|h| {
            u8::from_str_radix(h.trim(), 16)
                .map_err(|_| anyhow!("invalid fingerprint segment: '{h}'"))
        })
        .collect::<Result<Vec<u8>>>()?;
    if bytes.len() != 32 {
        bail!("fingerprint must be 32 bytes (SHA-256) but got {}", bytes.len());
    }
    Ok(bytes)
}

// ── TLS / QUIC endpoint creation ──────────────────────────────────────────────

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    cfg.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).unwrap(),
    ));
    Arc::new(cfg)
}

pub fn make_server_endpoint(
    addr: std::net::SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::Endpoint> {
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    server_cfg.transport_config(transport_config());
    Ok(quinn::Endpoint::server(server_cfg, addr)?)
}

pub fn make_client_endpoint(fingerprint: Option<Vec<u8>>) -> Result<quinn::Endpoint> {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match fingerprint {
        Some(fp) => Arc::new(FingerprintVerifier { fingerprint: fp }),
        None => {
            tracing::warn!(
                "no --server-fingerprint provided — TLS cert is NOT verified (MITM risk)"
            );
            Arc::new(SkipCertVerification)
        }
    };
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    client_cfg.transport_config(transport_config());
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client_cfg);
    Ok(ep)
}

// ── Handshakes ────────────────────────────────────────────────────────────────

async fn do_server_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SessionCipher> {
    let raw = read_frame(recv).await?;
    let client_hello = ClientHello::from_bytes(&raw)?;
    tracing::debug!("received ClientHello");
    let (server_hello, session_key) = server_derive_key(&client_hello)?;
    write_frame(send, &server_hello.to_bytes()).await?;
    tracing::debug!("sent ServerHello");
    Ok(SessionCipher::new(&session_key))
}

async fn do_client_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SessionCipher> {
    let (hello, secrets) = ClientHello::generate();
    write_frame(send, &hello.to_bytes()).await?;
    tracing::debug!("sent ClientHello");
    let raw = read_frame(recv).await?;
    let server_hello = ServerHello::from_bytes(&raw)?;
    tracing::debug!("received ServerHello");
    let session_key = client_derive_key(secrets, &server_hello)?;
    Ok(SessionCipher::new(&session_key))
}

// ── Authentication ────────────────────────────────────────────────────────────

fn key_is_valid(keys_file: &str, token: &str) -> bool {
    use subtle::ConstantTimeEq;

    // Read all valid tokens.
    // We deliberately compare against EVERY token (no short-circuit) so
    // total auth time doesn't leak which key matched, or whether any did.
    let contents = std::fs::read_to_string(keys_file).unwrap_or_default();
    let token_bytes = token.as_bytes();

    let mut matched = subtle::Choice::from(0u8);
    for line in contents.lines() {
        let candidate = line.trim();
        // Token format is public (38 chars), so length itself is not secret.
        // ConstantTimeEq requires equal lengths.
        if candidate.len() == token_bytes.len() {
            matched |= candidate.as_bytes().ct_eq(token_bytes);
        }
    }

    matched.unwrap_u8() == 1
}

async fn server_authenticate(
    send: &mut SendStream,
    recv: &mut RecvStream,
    cipher: &SessionCipher,
    keys_file: &str,
    state: &Arc<ServerState>,
) -> Result<Ipv4Addr> {
    let raw = read_frame(recv).await?;
    let token_bytes = cipher.decrypt(&raw)?;
    let token = std::str::from_utf8(&token_bytes)?;

    if !key_is_valid(keys_file, token) {
        let _ = write_frame(send, &cipher.encrypt(b"FAIL")?).await;
        bail!("invalid auth token (rejected)");
    }

    let ip = state
        .assign_ip()
        .await
        .ok_or_else(|| anyhow!("IP pool exhausted — server full"))?;

    write_frame(send, &cipher.encrypt(ip.to_string().as_bytes())?).await?;
    tracing::info!("client authenticated, assigned IP {ip}");
    Ok(ip)
}

async fn client_authenticate(
    send: &mut SendStream,
    recv: &mut RecvStream,
    cipher: &SessionCipher,
    auth_key: &str,
) -> Result<Ipv4Addr> {
    write_frame(send, &cipher.encrypt(auth_key.as_bytes())?).await?;

    let raw = read_frame(recv).await?;
    let resp_bytes = cipher.decrypt(&raw)?;
    let resp = std::str::from_utf8(&resp_bytes)?;

    if resp == "FAIL" {
        bail!("authentication rejected — wrong auth key");
    }

    let ip: Ipv4Addr = resp.parse()?;
    tracing::info!("authenticated, assigned IP: {ip}");
    Ok(ip)
}

// ── Shared server state ───────────────────────────────────────────────────────

struct ServerState {
    ip_pool: Mutex<Vec<Ipv4Addr>>,
    routing_table: RwLock<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>,
    tun_in_tx: mpsc::Sender<Vec<u8>>,
}

impl ServerState {
    fn new(tun_in_tx: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        let pool: Vec<Ipv4Addr> = (2u8..=254)
            .map(|i| Ipv4Addr::new(10, 0, 0, i))
            .collect();
        Arc::new(Self {
            ip_pool: Mutex::new(pool),
            routing_table: RwLock::new(HashMap::new()),
            tun_in_tx,
        })
    }

    async fn assign_ip(&self) -> Option<Ipv4Addr> {
        self.ip_pool.lock().await.pop()
    }

    async fn release_ip(&self, ip: Ipv4Addr) {
        self.ip_pool.lock().await.push(ip);
    }

    async fn register(&self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        self.routing_table.write().await.insert(ip, tx);
    }

    async fn unregister(&self, ip: Ipv4Addr) {
        self.routing_table.write().await.remove(&ip);
    }

    async fn route(&self, pkt: Vec<u8>) {
        if pkt.len() < 20 {
            return;
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        if let Some(tx) = self.routing_table.read().await.get(&dst) {
            let _ = tx.send(pkt).await;
        }
    }
}

// ── Tunnel forwarding ─────────────────────────────────────────────────────────

async fn run_tunnel(
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    cipher: Arc<SessionCipher>,
) {
    let cipher_tx = Arc::clone(&cipher);

    tokio::spawn(async move {
        loop {
            let Some(pkt) = from_tun.recv().await else { break };
            match cipher_tx.encrypt(&pkt) {
                Ok(enc) => {
                    if write_frame(&mut quic_send, &enc).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::error!("encrypt: {e}"),
            }
        }
    });

    loop {
        match read_frame(&mut quic_recv).await {
            Ok(data) => match cipher.decrypt(&data) {
                Ok(pkt) => {
                    if to_tun.send(pkt).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::error!("decrypt: {e}"),
            },
            Err(_) => break,
        }
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

async fn handle_connection(conn: Connection, state: Arc<ServerState>, keys_file: String) {
    tracing::info!("incoming from {}", conn.remote_address());

    let result: Result<()> = async {
        let (mut send, mut recv) = conn.accept_bi().await?;

        let cipher = Arc::new(do_server_handshake(&mut send, &mut recv).await?);
        let assigned_ip =
            server_authenticate(&mut send, &mut recv, &cipher, &keys_file, &state).await?;

        let (client_tx, client_rx) = mpsc::channel::<Vec<u8>>(256);
        state.register(assigned_ip, client_tx).await;

        tracing::info!("tunnel up for {assigned_ip}");
        run_tunnel(send, recv, client_rx, state.tun_in_tx.clone(), cipher).await;

        state.unregister(assigned_ip).await;
        state.release_ip(assigned_ip).await;
        tracing::info!("client {assigned_ip} disconnected");
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::warn!("connection error: {e}");
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

#[cfg(feature = "cli")]
pub async fn run_server(
    listen_addr: &str,
    tun_ip: &str,
    keys_file: &str,
    nat: bool,
    cert_dir: &str,
) -> Result<()> {
    let addr: std::net::SocketAddr = listen_addr.parse()?;
    let (certs, key, fingerprint) = load_or_generate_cert(cert_dir)?;

    tracing::info!("server cert SHA-256 fingerprint:");
    tracing::info!("  {}", fmt_fingerprint(&fingerprint));
    tracing::info!(
        "give clients: --server-fingerprint {}",
        fmt_fingerprint(&fingerprint)
    );

    let endpoint = make_server_endpoint(addr, certs, key)?;
    let (mut tun_out_rx, tun_in_tx, _tun_name) = tunnel::create_tun(tun_ip)?;
    let state = ServerState::new(tun_in_tx);

    let _nat_guard = if nat {
        Some(crate::routing::enable_server_nat()?)
    } else {
        None
    };

    let state_router = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(pkt) = tun_out_rx.recv().await {
            state_router.route(pkt).await;
        }
    });

    tracing::info!("server listening on {listen_addr} | TUN {tun_ip}/24");

    while let Some(incoming) = endpoint.accept().await {
        match incoming.await {
            Ok(conn) => {
                tokio::spawn(handle_connection(conn, Arc::clone(&state), keys_file.to_string()));
            }
            Err(e) => tracing::warn!("incoming connection failed: {e}"),
        }
    }

    Ok(())
}

/// Android variant: the TUN fd is already open (provided by Android's VpnService).
/// `log_fn` receives each log line so the JNI bridge can forward it to JS.
pub async fn run_client_with_tun<F>(
    _tun_file: std::fs::File,
    server_addr: &str,
    auth_key: &str,
    full_tunnel: bool,
    fingerprint: Option<Vec<u8>>,
    mut log_fn: F,
) -> Result<()>
where
    F: FnMut(String) + Send + 'static,
{
    use std::os::unix::io::IntoRawFd;

    let tun_fd = _tun_file.into_raw_fd();
    let (tun_out_rx, tun_in_tx) = crate::tunnel::create_tun_from_fd(tun_fd)?;

    let endpoint = make_client_endpoint(fingerprint)?;
    let server: std::net::SocketAddr = server_addr.parse()?;

    log_fn(format!("INFO: connecting to {server_addr}"));
    let conn = endpoint.connect(server, "dvion-vpn")?.await?;
    log_fn("INFO: QUIC connected".into());

    let (mut send, mut recv) = conn.open_bi().await?;
    let cipher = Arc::new(do_client_handshake(&mut send, &mut recv).await?);
    let assigned_ip = client_authenticate(&mut send, &mut recv, &cipher, auth_key).await?;

    log_fn(format!("INFO: tunnel up | assigned {assigned_ip}/24"));
    run_tunnel(send, recv, tun_out_rx, tun_in_tx, cipher).await;
    log_fn("INFO: disconnected".into());
    Ok(())
}

#[cfg(feature = "cli")]
pub async fn run_client(
    server_addr: &str,
    auth_key: &str,
    full_tunnel: bool,
    fingerprint: Option<Vec<u8>>,
) -> Result<()> {
    let endpoint = make_client_endpoint(fingerprint)?;
    let server: std::net::SocketAddr = server_addr.parse()?;

    tracing::info!("connecting to {server_addr}");
    let conn = endpoint.connect(server, "dvion-vpn")?.await?;
    tracing::info!("QUIC connected");

    let (mut send, mut recv) = conn.open_bi().await?;
    let cipher = Arc::new(do_client_handshake(&mut send, &mut recv).await?);
    let assigned_ip = client_authenticate(&mut send, &mut recv, &cipher, auth_key).await?;

    tracing::info!("tunnel up | TUN {assigned_ip}/24");
    let (tun_out_rx, tun_in_tx, tun_name) = tunnel::create_tun(&assigned_ip.to_string())?;

    let bypass = if full_tunnel {
        let server_ip = server.ip().to_string();
        match crate::routing::enable_full_tunnel(&server_ip, &tun_name) {
            Ok(b) => {
                tracing::info!("all traffic routed through VPN");
                Some(b)
            }
            Err(e) => {
                tracing::error!("full tunnel routing failed: {e}");
                None
            }
        }
    } else {
        None
    };

    run_tunnel(send, recv, tun_out_rx, tun_in_tx, cipher).await;

    if let Some(ref b) = bypass {
        crate::routing::disable_full_tunnel(b, &tun_name);
    }

    tracing::info!("disconnected");
    Ok(())
}

// ── Cert verifiers ────────────────────────────────────────────────────────────

/// Verifies the server cert by SHA-256 fingerprint, and cryptographically
/// verifies the TLS handshake signature so the server must hold the private key.
#[derive(Debug)]
struct FingerprintVerifier {
    fingerprint: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint mismatch\n  expected: {}\n  got:      {}",
                fmt_fingerprint(&self.fingerprint),
                fmt_fingerprint(got.as_slice()),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dsa,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dsa,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Skips all cert verification — kept for the no-fingerprint fallback path.
#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

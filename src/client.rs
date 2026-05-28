// #![cfg(feature = "rustls")]

use crate::auth;
use clap::Parser;
use quinn::{ClientConfig, Endpoint, VarInt};
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(not(windows))]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;
use url::Url;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, Level};

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct Opt {
    /// Server address
    url: Url,
    /// Client address
    #[clap(long = "bind", short = 'b')]
    bind_addr: Option<SocketAddr>,
    /// Show client connection logs on stderr
    #[clap(long = "verbose", short = 'v')]
    pub verbose: bool,
}

/// Enables MTUD if supported by the operating system
#[cfg(not(any(windows, target_os = "linux")))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    quinn::TransportConfig::default()
}

/// Enables MTUD if supported by the operating system
#[cfg(any(windows, target_os = "linux"))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport_config
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn configure_client() -> Result<ClientConfig, Box<dyn Error>> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    if let Some(secret) = auth::secret_from_env() {
        let token = auth::token_for_window(&secret, auth::current_window());
        crypto.alpn_protocols = vec![token.to_vec()];
        info!(
            "[client] auth token configured (window {})",
            auth::current_window()
        );
    }

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    let mut transport_config = enable_mtud_if_supported();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn make_client_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, Box<dyn Error>> {
    let client_cfg = configure_client()?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    let url = options.url;
    if url.scheme() != "quic" {
        return Err("URL scheme must be quic".into());
    }

    // Currently `url` crate doesn't recognize quic as scheme (see socket_addrs()), so we can set default port using argument. In future if quic default port is added (as 80 or 443, likely), we will fail to connect to proper port. Ideally we should define own scheme. (ex. "qsrs://" abbr of quicssh-rs)
    let sock_list = url
        .socket_addrs(|| Some(4433))
        .map_err(|_| "Couldn't resolve to any address")?;

    // Currently we only use the first addr. The other addrs should be fallbacks of the connection, but not implemented now.
    let remote = sock_list[0];
    let sni = url.host_str().unwrap_or("THIS_HOSTNAME_SHOULD_NOT_BE_USED");

    // Remove brackets from IPv6 address
    let sni = sni.trim_start_matches('[').trim_end_matches(']');

    info!("[client] Connecting to: {} <- {}", remote, sni);

    let endpoint = make_client_endpoint(match options.bind_addr {
        Some(local) => local,
        None => {
            use std::net::{IpAddr::*, Ipv4Addr, Ipv6Addr};
            if remote.is_ipv6() {
                SocketAddr::new(V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        }
    })?;
    // connect to server
    let connection = endpoint.connect(remote, sni).unwrap().await.unwrap();
    info!(
        "[client] Connected to: {} <- {}",
        connection.remote_address(),
        sni
    );

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    let recv_thread = async move {
        let mut buf = vec![0; 2048];
        let mut writer = tokio::io::BufWriter::new(tokio::io::stdout());

        loop {
            match recv.read(&mut buf).await {
                // Return value of `Ok(None)` signifies that the remote has
                // closed the stream — stop, don't spin.
                Ok(None) => {
                    debug!("[client] quic server finished stream");
                    return;
                }
                Ok(Some(n)) => {
                    debug!("[client] recv data from quic server {} bytes", n);
                    // Copy the data back to socket
                    match writer.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[client] write to stdout error: {}", e);
                            return;
                        }
                    }
                }
                Err(err) => {
                    // Unexpected socket error. There isn't much we can do
                    // here so just stop processing.
                    error!("[client] recv data from quic server error: {}", err);
                    return;
                }
            }
            if writer.flush().await.is_err() {
                error!("[client] recv data flush stdout error");
            }
        }
    };

    let write_thread = async move {
        let mut buf = [0; 2048];
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());

        loop {
            match reader.read(&mut buf).await {
                // Return value of `Ok(0)` signifies stdin EOF — stop, don't spin.
                Ok(n) => {
                    if n == 0 {
                        debug!("[client] stdin closed (EOF)");
                        return;
                    }
                    debug!("[client] recv data from stdin {} bytes", n);
                    // Copy the data back to socket
                    if send.write_all(&buf[..n]).await.is_err() {
                        // Unexpected socket error. There isn't much we can
                        // do here so just stop processing.
                        info!("[client] send data to quic server error");
                        return;
                    }
                }
                Err(err) => {
                    // Unexpected socket error. There isn't much we can do
                    // here so just stop processing.
                    info!("[client] recv data from stdin error: {}", err);
                    return;
                }
            }
        }
    };

    let signal_thread = create_signal_thread();

    tokio::select! {
        _ = recv_thread => (),
        _ = write_thread => (),
        _ = signal_thread => connection.close(0u32.into(), b"signal HUP"),
    }

    info!("[client] exit client");

    Ok(())
}

#[cfg(windows)]
async fn create_signal_thread() {
    let mut stream = match ctrl_c() {
        Ok(s) => s,
        Err(e) => {
            error!("[client] create signal stream error: {}", e);
            return;
        }
    };

    stream.recv().await;
    info!("[client] got signal Ctrl-C");
}
#[cfg(not(windows))]
async fn create_signal_thread() {
    let mut stream = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!("[client] create signal stream error: {}", e);
            return;
        }
    };

    stream.recv().await;
    info!("[client] got signal HUP");
}

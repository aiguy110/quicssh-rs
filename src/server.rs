use crate::auth;
use clap::Parser;
use quinn::{crypto, Endpoint, ServerConfig, VarInt};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use log::{debug, error, info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::{net::SocketAddr, sync::Arc};
use tokio::fs::read_to_string;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct Opt {
    /// Address to listen on
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    /// Address of the ssh server
    #[clap(long = "proxy-to", short = 'p')]
    proxy_to: Option<SocketAddr>,
    #[clap(long = "conf", short = 'F')]
    conf_path: Option<PathBuf>,
}

/// Cert resolver that gates the handshake on the presence of an ALPN
/// extension when auth is enabled. The actual ALPN value comparison is done
/// by rustls against the configured `alpn_protocols` list, but rustls will
/// happily accept a client that sends no ALPN at all if the server-side
/// list is empty or matches nothing — so we reject "no ALPN" here.
#[derive(Debug)]
struct AuthCertResolver {
    cert: Arc<rustls::sign::CertifiedKey>,
    require_alpn: bool,
}

impl rustls::server::ResolvesServerCert for AuthCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if self.require_alpn {
            match client_hello.alpn() {
                None => {
                    warn!("[server] rejecting handshake: no ALPN extension");
                    return None;
                }
                Some(mut iter) => {
                    if iter.next().is_none() {
                        warn!("[server] rejecting handshake: empty ALPN");
                        return None;
                    }
                }
            }
        }
        Some(self.cert.clone())
    }
}

fn generate_cert() -> Result<
    (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ),
    Box<dyn Error>,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let priv_key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
    let cert_chain = vec![cert_der.clone()];
    Ok((cert_chain, priv_key, cert_der))
}

/// Build a `ServerConfig` using the supplied cert and the current valid auth
/// tokens (if any). When `auth_secret` is `None`, behaviour matches the
/// original codebase (no ALPN gating).
fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    priv_key: PrivateKeyDer<'static>,
    auth_secret: Option<&[u8]>,
) -> Result<ServerConfig, Box<dyn Error>> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&priv_key)?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(cert_chain, signing_key));

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AuthCertResolver {
            cert: certified,
            require_alpn: auth_secret.is_some(),
        }));

    if let Some(secret) = auth_secret {
        crypto.alpn_protocols = auth::valid_tokens(secret);
    }

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    #[cfg(any(windows, target_os = "linux"))]
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    Ok(server_config)
}

#[allow(unused)]
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error>> {
    let (cert_chain, priv_key, cert_der) = generate_cert()?;
    let auth_secret = auth::secret_from_env();
    let server_config = build_server_config(cert_chain, priv_key, auth_secret.as_deref())?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, cert_der))
}

#[derive(Deserialize, Debug)]
struct ServerConf {
    proxy: HashMap<String, SocketAddr>,
}
impl ServerConf {
    fn new() -> Self {
        ServerConf {
            proxy: HashMap::<String, SocketAddr>::new(),
        }
    }
}

#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    let conf: ServerConf = match options.conf_path {
        Some(path) => {
            info!("[server] importing conf file: {}", path.display());
            toml::from_str(&(read_to_string(path).await?))?
        }
        None => ServerConf::new(),
    };

    let default_proxy = match conf.proxy.get("default") {
        Some(sock) => *sock,
        None => options
            .proxy_to
            .unwrap_or(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 22)),
    };
    info!("[server] default proxy aim: {}", default_proxy);

    let auth_secret = auth::secret_from_env();
    let (cert_chain, priv_key, _cert_der) = generate_cert().unwrap();
    let initial_config = build_server_config(
        cert_chain.clone(),
        priv_key.clone_key(),
        auth_secret.as_deref(),
    )
    .unwrap();
    let endpoint = Endpoint::server(initial_config, options.listen).unwrap();
    info!("[server] listening on: {}", options.listen);

    if auth_secret.is_some() {
        info!(
            "[server] ALPN auth enabled (window={}s); rejecting handshakes without a valid token",
            auth::WINDOW_SECS
        );
        let endpoint_for_refresh = endpoint.clone();
        let secret = auth_secret.clone().unwrap();
        let cert_chain_r = cert_chain.clone();
        let priv_key_r = priv_key.clone_key();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(auth::WINDOW_SECS / 2));
            interval.tick().await; // skip the immediate fire
            loop {
                interval.tick().await;
                match build_server_config(
                    cert_chain_r.clone(),
                    priv_key_r.clone_key(),
                    Some(&secret),
                ) {
                    Ok(cfg) => {
                        endpoint_for_refresh.set_server_config(Some(cfg));
                        debug!(
                            "[server] rotated auth tokens (window={})",
                            auth::current_window()
                        );
                    }
                    Err(e) => error!("[server] failed to rebuild server config: {}", e),
                }
            }
        });
    } else {
        warn!(
            "[server] {} not set: no handshake authentication — anyone reaching the port can probe the QUIC service",
            auth::ENV_VAR
        );
    }
    // accept a single connection
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                continue;
            }
        };

        if let Some(secret) = auth_secret.as_deref() {
            let remote = incoming.remote_address();
            let hs = match incoming.handshake_bytes() {
                Ok(b) => b,
                Err(e) => {
                    debug!(
                        "[server] silent-drop {}: handshake_bytes failed: {}",
                        remote, e
                    );
                    incoming.ignore();
                    continue;
                }
            };
            let alpns = auth::parse_client_hello_alpn(&hs).unwrap_or_default();
            let refs: Vec<&[u8]> = alpns.iter().map(|v| v.as_slice()).collect();
            if !auth::any_token_valid(secret, &refs) {
                debug!(
                    "[server] silent-drop {}: ALPN auth token missing/invalid",
                    remote
                );
                incoming.ignore();
                continue;
            }
        }

        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(e) => {
                error!("[server] accept connection error: {}", e);
                continue;
            }
        };
        let conn = match connecting.await {
            Ok(conn) => conn,
            Err(e) => {
                error!("[server] handshake error: {}", e);
                continue;
            }
        };

        let remote_addr = conn.remote_address();
        let sni = conn
            .handshake_data()
            .unwrap()
            .downcast::<crypto::rustls::HandshakeData>()
            .unwrap()
            .server_name
            .unwrap_or(remote_addr.ip().to_string());
        let proxy_to = *conf.proxy.get(&sni).unwrap_or(&default_proxy);
        info!(
            "[audit] accepted connection from {} (sni={}) -> {}",
            remote_addr, sni, proxy_to
        );
        tokio::spawn(async move {
            handle_connection(proxy_to, conn).await;
            info!("[audit] closed connection from {}", remote_addr);
        });
        // Dropping all handles associated with a connection implicitly closes it
    }
}

async fn handle_connection(proxy_for: SocketAddr, connection: quinn::Connection) {
    let ssh_stream = TcpStream::connect(proxy_for).await;
    let ssh_conn = match ssh_stream {
        Ok(conn) => conn,
        Err(e) => {
            error!("[server] connect to ssh error: {}", e);
            return;
        }
    };

    info!("[server] ssh connection established");

    let (mut quinn_send, mut quinn_recv) = match connection.accept_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[server] open quic stream error: {}", e);
            return;
        }
    };

    let (mut ssh_recv, mut ssh_write) = tokio::io::split(ssh_conn);

    let recv_thread = async move {
        let mut buf = [0; 2048];
        loop {
            match ssh_recv.read(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    debug!("[server] recv data from ssh server {} bytes", n);
                    match quinn_send.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to quic stream error: {}", e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("[server] reading from ssh server error: {}", e);
                    return;
                }
            }
        }
    };

    let write_thread = async move {
        let mut buf = [0; 2048];
        loop {
            match quinn_recv.read(&mut buf).await {
                Ok(None) => {
                    continue;
                }
                Ok(Some(n)) => {
                    debug!("[server] recv data from quic stream {} bytes", n);
                    if n == 0 {
                        continue;
                    }
                    match ssh_write.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to ssh server error: {}", e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("[server] reading from quic client error: {}", e);
                    return;
                }
            }
        }
    };

    tokio::select! {
        _ = recv_thread => (),
        _ = write_thread => (),
    }

    info!("[server] exit client");

    // tokio::join!(recv_thread, write_thread);
}

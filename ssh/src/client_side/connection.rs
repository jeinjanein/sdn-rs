use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use russh::client::{Config, connect_stream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};
use tracing::warn;

use crate::client_side::{client::SshClient, error::ClientError, handler::ConnectionHandler};

const TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

fn classify_tcp_connection_error(error: io::Error) -> ClientError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ClientError::TcpConnectionRefused { source: error },

        io::ErrorKind::HostUnreachable => ClientError::TcpHostUnreachable { source: error },

        io::ErrorKind::TimedOut => ClientError::TcpTimeout { source: error },

        _ => ClientError::TcpConnection { source: error },
    }
}

fn classify_ssh_handshake_error(error: ClientError) -> ClientError {
    match error {
        ClientError::Ssh { source } => ClientError::SshHandshake { source },

        error => error,
    }
}

pub async fn resolve_target_hostname(
    hostname: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, ClientError> {
    let addresses = tokio::net::lookup_host((hostname, port))
        .await
        .map_err(|source| ClientError::Dns {
            hostname: hostname.to_owned(),
            source,
        })?
        .collect::<Vec<_>>();

    Ok(addresses)
}

pub async fn create_tcp_connection(addresses: &[SocketAddr]) -> Result<TcpStream, ClientError> {
    let connection_result =
        match timeout(TCP_CONNECTION_TIMEOUT, TcpStream::connect(addresses)).await {
            Ok(connection_result) => connection_result,

            Err(error) => Err(io::Error::new(io::ErrorKind::TimedOut, error)),
        };

    connection_result.map_err(classify_tcp_connection_error)
}

async fn start_ssh_on_stream<S>(
    config: Arc<Config>,
    stream: S,
    handler: ConnectionHandler,
    remote_endpoint: Option<SocketAddr>,
) -> Result<SshClient, ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connection_id = next_connection_id();

    let handle = connect_stream(config, stream, handler)
        .await
        .map_err(classify_ssh_handshake_error)?;

    Ok(SshClient::from_handle(
        handle,
        connection_id,
        remote_endpoint,
    ))
}

pub async fn create_ssh_connection(
    config: Arc<Config>,
    stream: TcpStream,
    handler: ConnectionHandler,
) -> Result<SshClient, ClientError> {
    let remote_endpoint = stream
        .peer_addr()
        .map_err(|source| ClientError::TcpConnection { source })?;

    if config.nodelay {
        if let Err(error) = stream.set_nodelay(true) {
            warn!(
                error = %error,
                "failed to enable TCP_NODELAY on SSH client stream"
            );
        }
    }

    start_ssh_on_stream(config, stream, handler, Some(remote_endpoint)).await
}

pub async fn create_ssh_connection_from_custom_stream<S>(
    config: Arc<Config>,
    stream: S,
    handler: ConnectionHandler,
) -> Result<SshClient, ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    start_ssh_on_stream(config, stream, handler, None).await
}

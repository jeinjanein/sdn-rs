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

use crate::client_side::context::ConnectionContext;
use crate::client_side::known_hosts::HostKeyPolicy;
use crate::client_side::target::TargetIdentity;
use crate::client_side::{client::SshClient, error::ClientError, handler::ConnectionHandler};

const TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

/// Converts a TCP connection failure into the project's error category
fn classify_tcp_connection_error(error: io::Error) -> ClientError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ClientError::TcpConnectionRefused { source: error },

        io::ErrorKind::HostUnreachable => ClientError::TcpHostUnreachable { source: error },

        io::ErrorKind::TimedOut => ClientError::TcpTimeout { source: error },

        _ => ClientError::TcpConnection { source: error },
    }
}

/// Converts an SSH handshake failure into the project's error category
fn classify_ssh_handshake_error(error: ClientError) -> ClientError {
    match error {
        ClientError::Ssh { source } => ClientError::SshHandshake { source },

        error => error,
    }
}

/// Resolves a hostname or numeric IP address into candidate socket addresses
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

/// Opens a TCP connection from an already resolved list of IP addresses and ports.
/// This function returns one connected stream or a connection error.
/// - `Ok(Ok(stream))`: TCP connected before the timeout was reported.
/// - `Ok(Err(source))`: the connection operation completed with an I/O error.
/// - `Err(elapsed)`: the timeout expired while connection establishment remained pending.
pub async fn create_tcp_connection(addresses: &[SocketAddr]) -> Result<TcpStream, ClientError> {
    let connection_result =
        match timeout(TCP_CONNECTION_TIMEOUT, TcpStream::connect(addresses)).await {
            Ok(connection_result) => connection_result,

            Err(error) => Err(io::Error::new(io::ErrorKind::TimedOut, error)),
        };

    connection_result.map_err(classify_tcp_connection_error)
}

/// Starts SSH on an already connected TCP stream.
pub async fn create_ssh_connection(
    config: Arc<Config>,
    stream: TcpStream,
    target_identity: TargetIdentity,
    host_key_policy: HostKeyPolicy,
) -> Result<SshClient, ClientError> {
    if config.nodelay {
        if let Err(error) = stream.set_nodelay(true) {
            warn!(
                error = %error,
                "failed to enable TCP_NODELAY on SSH client stream"
            );
        }
    }

    start_ssh_on_stream(config, stream, target_identity, host_key_policy).await
}

/// A helper function that starts SSH, verifies the server's host key through the configured policy, and returns the project's client wrapper before user authentication.
async fn start_ssh_on_stream<S>(
    config: Arc<Config>,
    stream: S,
    target_identity: TargetIdentity,
    host_key_policy: HostKeyPolicy,
) -> Result<SshClient, ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connection_id = next_connection_id();

    let connection_context = Arc::new(ConnectionContext::new(
        connection_id,
        target_identity,
        host_key_policy,
    ));

    let connection_handler = ConnectionHandler::new(Arc::clone(&connection_context));

    let handle = connect_stream(config, stream, connection_handler)
        .await
        .map_err(classify_ssh_handshake_error)?;

    Ok(SshClient::from_handle(handle, connection_context))
}

/// Starts SSH on a bidirectional byte stream supplied by the caller. Use it when the transport is already available, such as an in-memory stream, a Unix-domain socket, or an established tunnel whose other end speaks SSH.
pub async fn create_ssh_connection_from_custom_stream<S>(
    config: Arc<Config>,
    stream: S,
    target_identity: TargetIdentity,
    host_key_policy: HostKeyPolicy,
) -> Result<SshClient, ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    start_ssh_on_stream(config, stream, target_identity, host_key_policy).await
}

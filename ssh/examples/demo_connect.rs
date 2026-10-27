use std::{sync::Arc, time::Duration};

use anyhow::Context;
use russh::keys::{HashAlg, load_public_key, load_secret_key};
use ssh::client_side::{
    client_key::load_client_private_key,
    config::create_client_config,
    connection::{create_ssh_connection, create_tcp_connection, resolve_target_hostname},
    error::ClientError,
    known_hosts::HostKeyPolicy,
    target::TargetIdentity,
};
use tokio::time::timeout;
use tracing::info;
use tracing_subscriber::EnvFilter;

const TARGET_HOST_NAME: &str = "127.0.0.1";

const TARGET_PORT: u16 = 2222;

const DEFAULT_PINNED_KEY_PATH: &str = "./keys/host_ed25519_key.pub";

const DEFAULT_CLIENT_KEY_PATH: &str = "./keys/admin_ed25519_key";

const SSH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const DISCONNECT_MESSAGE: &str = "demo connection complete";

const SSH_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);

fn initialize_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    initialize_logging();

    let pinned_key_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_PINNED_KEY_PATH.to_owned());

    let pinned_key = load_public_key(&pinned_key_path).with_context(|| {
        format!("stage 1 failed: cannot load pinned key from {pinned_key_path}")
    })?;

    info!(
        path = %pinned_key_path,
        fingerprint = %pinned_key.fingerprint(HashAlg::Sha256),
        "stage 1: pinned server public key loaded"
    );

    let client_key_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_CLIENT_KEY_PATH.to_string());

    let client_key = load_client_private_key(&client_key_path).with_context(|| {
        format!("stage 1 failed: cannot load client private key from {client_key_path}")
    })?;

    info!(
        path = %client_key_path,
        algorithm = %client_key.algorithm(),
        fingerprint = %client_key.fingerprint(HashAlg::Sha256),
        "stage 1: client private key loaded"
    );

    let config = Arc::new(
        create_client_config().context("stage 1 failed: cannot create SSH client configuration")?,
    );

    let addresses = resolve_target_hostname(TARGET_HOST_NAME, TARGET_PORT)
        .await
        .context("stage 2 failed: cannot resolve target")?;

    let stream = create_tcp_connection(&addresses)
        .await
        .context("stage 2 failed: TCP connection")?;

    let peer_addr = stream.peer_addr().ok();

    info!(peer_addr = ?peer_addr, "stage 2: TCP connection established");

    let target_identity = TargetIdentity::new(TARGET_HOST_NAME.to_string(), TARGET_PORT, peer_addr);

    let host_key_policy = HostKeyPolicy::PinnedKey { key: pinned_key };

    let mut client = timeout(
        SSH_HANDSHAKE_TIMEOUT,
        create_ssh_connection(config, stream, target_identity, host_key_policy),
    )
    .await
    .context("stage 3 failed: SSH handshake did not finish within the deadline")?
    .context("stage 3 failed: SSH handshake")?;

    info!(
        connection_id = client.connection_context().connection_id(),
        "stage 3: SSH connection established, server key matched the pin"
    );

    client
        .handle_mut()
        .disconnect(russh::Disconnect::ByApplication, DISCONNECT_MESSAGE, "en")
        .await
        .context("stage 4 failed: cannot send SSH disconnect")?;

    info!("stage 4: SSH disconnect sent");

    let termination = timeout(SSH_TERMINATION_TIMEOUT, client.handle_mut())
        .await
        .context("stage 5 failed: connection task did not finish within the deadline")?;

    match termination {
        Ok(()) => info!("stage 5: connection task finished after the server's disconnect message"),

        Err(ClientError::Ssh {
            source: russh::Error::Disconnect,
        }) => info!("stage 5: connection task finished after the local disconnect"),

        Err(error) => {
            return Err(error).context("stage 5 failed: connection task ended with an error");
        }
    }
    Ok(())
}

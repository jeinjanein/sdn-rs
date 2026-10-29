use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use russh::{
    ChannelMsg,
    client::AuthResult,
    keys::{HashAlg, PrivateKeyWithHashAlg, load_public_key},
};
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

const SSH_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);

const CLIENT_USERNAME: &str = "admin";

const SSH_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

const NETCONF_SUBSYSTEM_NAME: &str = "netconf";

const SSH_SUBSYSTEM_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

    // Stage 1: load local key before any network activity
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

    let client_key_fingerprint = client_key.fingerprint(HashAlg::Sha256);

    info!(
        path = %client_key_path,
        algorithm = %client_key.algorithm(),
        fingerprint = %client_key_fingerprint,
        "stage 1: client private key loaded"
    );

    let config = Arc::new(
        create_client_config().context("stage 1 failed: cannot create SSH client configuration")?,
    );

    // Stage 2: open the TCP connection
    let addresses = resolve_target_hostname(TARGET_HOST_NAME, TARGET_PORT)
        .await
        .context("stage 2 failed: cannot resolve target")?;

    let stream = create_tcp_connection(&addresses)
        .await
        .context("stage 2 failed: TCP connection")?;

    let peer_addr = stream.peer_addr().ok();

    info!(peer_addr = ?peer_addr, "stage 2: TCP connection established");

    // Stage 3: run the SSH handshake under the pinned-key policy
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

    // Stage 4: send one public-key authentication request
    let client_key = PrivateKeyWithHashAlg::new(Arc::new(client_key), None);

    let auth_result = timeout(
        SSH_AUTHENTICATION_TIMEOUT,
        client
            .handle_mut()
            .authenticate_publickey(CLIENT_USERNAME, client_key),
    )
    .await
    .context("stage 4 failed: authentication did not finish within the deadline")?
    .context("stage 4 failed: cannot send the authentication request")?;

    match auth_result {
        AuthResult::Success => {
            info!(
                user = CLIENT_USERNAME,
                "stage 4: public-key authentication succeeded"
            );
        }
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            bail!(
                "stage 4 failed: public-key authentication as {CLIENT_USERNAME} with the loaded client key {client_key_fingerprint} was not accepted 
                (remaining methods: {remaining_methods:?}, partial success: {partial_success}"
            );
        }
    }

    // Stage 5: open one session channel on the authenticated connection
    let mut session_channel = timeout(
        SSH_CHANNEL_OPEN_TIMEOUT,
        client.handle_mut().channel_open_session(),
    )
    .await
    .context("stage 5 failed: session channel open did not finish within the deadline")?
    .context("stage 5 failed: session channel was not opened")?;

    info!(
        channel_id = ?session_channel.id(),
        "stage 5: session channel opened"
    );

    // Stage 6: request the netconf subsystem on the session channel
    let subsystem_reply = timeout(SSH_SUBSYSTEM_REQUEST_TIMEOUT, async {
        session_channel
            .request_subsystem(true, NETCONF_SUBSYSTEM_NAME)
            .await?;

        Ok::<_, russh::Error>(session_channel.wait().await)
    })
    .await
    .context("stage 6 failed: subsystem request did not finish within the deadline")?
    .context("stage 6 failed: cannot send the netconf subsystem request")?;

    let netconf_channel = match subsystem_reply {
        Some(ChannelMsg::Success) => session_channel,

        Some(ChannelMsg::Failure) => {
            bail!("stage 6 failed: the server refused the {NETCONF_SUBSYSTEM_NAME} subsystem");
        }

        None => {
            bail!(
                "stage 6 failed: the channel closed before the server answered the subsystem request"
            );
        }

        Some(other) => {
            bail!(
                "stage 6 failed: unexpected channel message before the subsytem reply: {other:?}"
            );
        }
    };

    info!(
        channel_id = ?netconf_channel.id(),
        subsystem = NETCONF_SUBSYSTEM_NAME,
        "stage 6: subsystem request accepted"
    );

    // Stage 7: request SSH termination
    client
        .handle_mut()
        .disconnect(russh::Disconnect::ByApplication, DISCONNECT_MESSAGE, "en")
        .await
        .context("stage 7 failed: cannot send SSH disconnect")?;

    info!("stage 7: SSH disconnect sent");

    // Stage 8: wait for the connection task to finish
    let termination = timeout(SSH_TERMINATION_TIMEOUT, client.handle_mut())
        .await
        .context("stage 8 failed: connection task did not finish within the deadline")?;

    match termination {
        Ok(()) => info!("stage 8: connection task finished after the server's disconnect message"),

        Err(ClientError::Ssh {
            source: russh::Error::Disconnect,
        }) => info!("stage 8: connection task finished after the local disconnect"),

        Err(error) => {
            return Err(error).context("stage 8 failed: connection task ended with an error");
        }
    }
    Ok(())
}

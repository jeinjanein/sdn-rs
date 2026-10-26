use std::{sync::Arc, time::Duration};

use russh::{
    keys::{PrivateKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth},
};
use ssh::client_side::{
    client::SshClient, config::create_client_config,
    connection::create_ssh_connection_from_custom_stream, known_hosts::HostKeyPolicy,
    target::TargetIdentity,
};

const TEST_HOST_KEY_SEED: [u8; 32] = [7; 32];

const IN_MEMORY_STREAM_BUFFER_SIZE: usize = 64 * 1024;

const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// A server that accepts any user without credentials, so tests reach the authenticated state
/// in which server-opened channels are dispatched.
struct TestServer;

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(Auth::Accept)
    }
}

/// Connects the project client to `TestServer`, authenticates, and returns both ends.
/// The client pins the test server's host key
async fn authenticated_connection() -> (SshClient, server::Handle) {
    let host_key = PrivateKey::from(Ed25519Keypair::from_seed(&TEST_HOST_KEY_SEED));
    let pinned_key = host_key.public_key().clone();

    let server_config = Arc::new(server::Config {
        keys: vec![host_key],
        ..Default::default()
    });

    let client_config = Arc::new(create_client_config().expect("client config should be created"));

    let (client_stream, server_stream) = tokio::io::duplex(IN_MEMORY_STREAM_BUFFER_SIZE);

    let (server_session, client) = tokio::join!(
        server::run_stream(server_config, server_stream, TestServer),
        create_ssh_connection_from_custom_stream(
            client_config,
            client_stream,
            TargetIdentity::new("test-server".to_string(), 22, None),
            HostKeyPolicy::PinnedKey { key: pinned_key },
        ),
    );

    let server_session = server_session.expect("test server should start");
    let mut client = client.expect("client should complete the handshake");

    let auth_result = client
        .handle_mut()
        .authenticate_none("test")
        .await
        .expect("authentication request should complete");

    assert!(
        auth_result.success(),
        "test server should accept the client`"
    );

    (client, server_session.handle())
}

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use crate::{CHANNEL_OPEN_TIMEOUT, authenticated_connection};

    #[tokio::test]
    async fn client_rejects_server_opened_forwared_tcpip_channel() {
        let (_client, server_handle) = authenticated_connection().await;

        let result = timeout(
            CHANNEL_OPEN_TIMEOUT,
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 8080, "192.0.2.10", 50000),
        )
        .await
        .expect("client should answer the channel-open request");

        match result {
            Err(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited,
            )) => {}
            Err(error) => panic!("expected an administrative refusal, got error {error:?}"),
            Ok(_) => panic!("client accepted a forwared-tcpip channel"),
        }
    }

    #[tokio::test]
    async fn client_rejects_server_opened_forwarded_streamlocal_channel() {
        let (_cient, server_handle) = authenticated_connection().await;

        let result = timeout(
            CHANNEL_OPEN_TIMEOUT,
            server_handle.channel_open_forwarded_streamlocal("/tmp/forwaded.sock"),
        )
        .await
        .expect("client should answer the channel-open request");

        match result {
            Err(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited,
            )) => {}
            Err(error) => panic!("expected an administrative refusal, got error {error:?}"),
            Ok(_) => panic!("client accepted a forwarded-stream local channel"),
        }
    }

    #[tokio::test]
    async fn client_rejects_server_opened_agent_forward_channel() {
        let (_client, server_handle) = authenticated_connection().await;

        let result = timeout(CHANNEL_OPEN_TIMEOUT, server_handle.channel_open_agent())
            .await
            .expect("client should answer the channel-open request");

        match result {
            Err(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited,
            )) => {}
            Err(error) => panic!("expected an administrative refusal, got error {error:?}"),
            Ok(_) => panic!("client accepted an auth-agent channel"),
        }
    }
}

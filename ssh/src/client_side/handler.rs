use crate::client_side::error::ClientError;
use crate::client_side::{context::ConnectionContext, known_hosts::verify_server_key};
use russh::{client::DisconnectReason, keys::PublicKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ConnectionHandler {
    connection_context: Arc<ConnectionContext>,
}

impl ConnectionHandler {
    pub fn new(connection_context: Arc<ConnectionContext>) -> Self {
        Self { connection_context }
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_context.connection_id()
    }

    pub fn peer_addr(&self) -> &Option<SocketAddr> {
        self.connection_context.target_host().peer_addr()
    }

    pub fn connection_context(&self) -> Arc<ConnectionContext> {
        Arc::clone(&self.connection_context)
    }
}

impl russh::client::Handler for ConnectionHandler {
    type Error = ClientError;

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            banner = ?banner,
            "SSH authentication banner received"
        );

        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let target_host = self.connection_context.target_host();
        let host_name = target_host.host_name();
        let port = target_host.port();
        let key_algorithm = server_public_key.algorithm();
        let server_key_fingerprint = server_public_key.fingerprint(Default::default());

        match verify_server_key(self.connection_context(), server_public_key) {
            Ok(true) => {
                info!(
                    connection_id = self.connection_id(),
                    host_name,
                    port,
                    peer_addr = ?self.peer_addr(),
                    %key_algorithm,
                    %server_key_fingerprint,
                    "SSH server host key verified",
                );
                Ok(true)
            }
            Ok(false) => {
                warn!(
                    connection_id = self.connection_id(),
                    host_name,
                    port,
                    peer_addr = ?self.peer_addr(),
                    %key_algorithm,
                    %server_key_fingerprint,
                    "SSH server host key rejected",
                );
                Ok(false)
            }

            Err(error) => {
                warn!(
                    connection_id = self.connection_id(),
                    host_name,
                    port,
                    peer_addr = ?self.peer_addr(),
                    %key_algorithm,
                    %server_key_fingerprint,
                    error = %error,
                    "SSH server host key verification failed",
                );

                Err(error)
            }
        }
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            kex_algorithm = ?names.kex,
            host_key_algorithm = ?names.key,
            cipher = ?names.cipher,
            client_mac = ?names.client_mac,
            server_mac = ?names.server_mac,
            client_compression = ?names.client_compression,
            server_compression = ?names.server_compression,
            strict_kex = names.strict_kex(),
            "SSH key exchange completed"
        );

        Ok(())
    }

    async fn channel_open_confirmation(
        &mut self,
        id: russh::ChannelId,
        max_packet_size: u32,
        window_size: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?id,
            remote_max_packet_size = max_packet_size,
            remote_window_size = window_size,
            "SSH channel open confirmed"
        );

        Ok(())
    }

    async fn channel_success(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel,
            "SSH channel request succeeded"
        );

        Ok(())
    }

    async fn channel_failure(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel,
            "SSH channel request failed"
        );

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel,
            "SSH channel close received"
        );

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel,
            "SSH channel EOF received"
        );

        Ok(())
    }

    async fn channel_open_failure(
        &mut self,
        channel: russh::ChannelId,
        reason: russh::ChannelOpenFailure,
        description: &str,
        language: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel,
            reason_code = reason.code(),
            reason = ?reason,
            description = ?description,
            language = ?language,
            "SSH channel open failed"
        );

        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(disconnect_info) => {
                debug!(
                    connection_id = self.connection_id(),
                    peer_addr = ?self.peer_addr(),
                    reason_code = ?disconnect_info.reason_code,
                    message = ?disconnect_info.message,
                    lang_tag = ?disconnect_info.lang_tag,
                    "SSH disconnect signal received"
                );

                Ok(())
            }
            DisconnectReason::Error(error) => {
                warn!(
                    connection_id = self.connection_id(),
                    peer_addr = ?self.peer_addr(),
                    error = ?error,
                    "SSH connection ended with an error"
                );

                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use russh::{client::Handler, keys::PublicKey};

    use crate::client_side::{
        context::ConnectionContext, error::ClientError, handler::{self, ConnectionHandler}, known_hosts::HostKeyPolicy, target::TargetIdentity,
    };

    const KNOWN_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAINU0dNEp2u7eCNMf1M3ZRejErz2QUqYh6EJs/+CFUrnf"
    );
    const OTHER_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAIJwutwmIIUraD6U+R31Ah6CBPiZijfoghZvET0dxOCT0"
    );

    const KNOWN_HOSTS_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/known_hosts");

    fn handler(host: &str, host_key_policy: HostKeyPolicy) -> ConnectionHandler {
        let connection_context = Arc::new(ConnectionContext::new(
            1,
            TargetIdentity::new(host.into(), 2222, Some("127.0.0.1:2222".parse().unwrap())),
            host_key_policy,
        ));

        ConnectionHandler { connection_context }
    }

    #[tokio::test]
    async fn check_server_key_policy_rejects_all_keys() {
        let key = PublicKey::from_openssh(KNOWN_KEY).unwrap();
        let host_key_policy = HostKeyPolicy::RejectAll;
        let mut handler = handler("demo", host_key_policy);
        assert!(!handler.check_server_key(&key).await.unwrap())
    }

    #[tokio::test]
    async fn check_server_key_policy_known_host_matches() {
        let key = PublicKey::from_openssh(KNOWN_KEY).unwrap();
        let path = PathBuf::from(KNOWN_HOSTS_PATH);
        let host_key_policy = HostKeyPolicy::KnownHost { path };
        let mut handler = handler("router.example1.com", host_key_policy);

        assert!(handler.check_server_key(&key).await.unwrap())
    }

    #[tokio::test]
    async fn check_server_key_policy_known_host_key_changed() {
        let other_key = PublicKey::from_openssh(OTHER_KEY).unwrap();
        let path = PathBuf::from(KNOWN_HOSTS_PATH);
        let host_key_policy = HostKeyPolicy::KnownHost { path };
        let mut handler = handler("router.example1.com", host_key_policy);

        assert!(matches!(
            handler.check_server_key(&other_key).await,
            Err(ClientError::HostKeyChanged { host, port, path, line }) if host == "router.example1.com"
        ));
    }

    #[tokio::test]
    async fn check_server_key_policy_pinned_key() {
        let key = PublicKey::from_openssh(KNOWN_KEY).unwrap();
        let other_key = PublicKey::from_openssh(OTHER_KEY).unwrap();
        let host_key_policy = HostKeyPolicy::PinnedKey { key: key.clone() };
        let mut handler = handler("Pinned Key", host_key_policy);

        assert!(handler.check_server_key(&key).await.unwrap());
        assert!(!handler.check_server_key(&other_key).await.unwrap())
    }

    #[tokio::test]
    async fn check_server_key_policy_pinned_fingerprint() {
        let key = PublicKey::from_openssh(KNOWN_KEY).unwrap();
        let other_key = PublicKey::from_openssh(OTHER_KEY).unwrap();
        let pinned_fingerprint = key.fingerprint(Default::default());
        let host_key_policy = HostKeyPolicy::PinnedFingerprint {
            fingerprint: pinned_fingerprint,
        };
        let mut handler = handler("Pinned Fingerprint", host_key_policy);

        assert!(handler.check_server_key(&key).await.unwrap());
        assert!(!handler.check_server_key(&other_key).await.unwrap());
    }

    #[tokio::test]
    async fn check_server_key_policy_accept_any() {
        let key = PublicKey::from_openssh(KNOWN_KEY).unwrap();
        let host_key_policy = HostKeyPolicy::AcceptAnyForTesting;
        let mut handler = handler("Accept any", host_key_policy);

        assert!(handler.check_server_key(&key).await.unwrap());
    }
}

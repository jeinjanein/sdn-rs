use crate::client_side::error::ClientError;
use crate::client_side::{context::ConnectionContext, known_hosts::verify_server_key};
use russh::client::{ChannelOpenHandle, Msg, Session};
use russh::{
    Channel, ChannelId, ChannelOpenFailure, Sig, client::DisconnectReason, keys::PublicKey,
};
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

    /// Refuses a channel that the server tried to open toward this client.
    /// The refusal is queued for the session loop, which sends it after
    /// the calling callback returns `Ok(())`.
    async fn reject_server_opened_channel(
        &self,
        channel_id: ChannelId,
        channel_type: &str,
        reply: ChannelOpenHandle,
    ) {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;

        warn!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            channel_id = ?channel_id,
            channel_type,
            "server-opened SSH channel rejected"
        );
    }
}

impl russh::client::Handler for ConnectionHandler {
    type Error = ClientError;

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
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
        _session: &mut Session,
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
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        _session: &mut Session,
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
        channel: ChannelId,
        _session: &mut Session,
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
        channel: ChannelId,
        _session: &mut Session,
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
        channel: ChannelId,
        _session: &mut Session,
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
        channel: ChannelId,
        _session: &mut Session,
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
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        _session: &mut Session,
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

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject_server_opened_channel(channel.id(), "forwared-tcpip", reply)
            .await;

        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject_server_opened_channel(channel.id(), "forwarded-streamlocal", reply)
            .await;

        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject_server_opened_channel(channel.id(), "auth-agent", reply)
            .await;

        Ok(())
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: ChannelId,
        _channel_type: &str,
    ) -> bool {
        false
    }

    async fn server_channel_open_unknown(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject_server_opened_channel(channel.id(), "session", reply)
            .await;

        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _ext: u32,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn xon_xoff(
        &mut self,
        _channel: ChannelId,
        _client_can_do: bool,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn exit_status(
        &mut self,
        _channel: ChannelId,
        _exit_status: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn exit_signal(
        &mut self,
        _channel: ChannelId,
        _signal_name: Sig,
        _core_dumped: bool,
        _error_message: &str,
        _lang_tag: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn window_adjusted(
        &mut self,
        _channel: ChannelId,
        _new_size: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn adjust_window(&mut self, _channel: ChannelId, window: u32) -> u32 {
        window
    }

    async fn openssh_ext_host_keys_announced(
        &mut self,
        _keys: Vec<PublicKey>,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
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
        context::ConnectionContext, error::ClientError, handler::ConnectionHandler,
        known_hosts::HostKeyPolicy, target::TargetIdentity,
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
            Err(ClientError::HostKeyChanged { host, .. }) if host == "router.example1.com"
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

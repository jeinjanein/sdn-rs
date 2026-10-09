use crate::client_side::context::ConnectionContext;
use crate::client_side::error::ClientError;
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
}

impl russh::client::Handler for ConnectionHandler {
    type Error = ClientError;

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        info!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            banner = ?banner,
            "SSH authentication banner received"
        );

        Ok(())
    }

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(false)
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
    use russh::{client::Handler, keys::PublicKey};

    use crate::client_side::handler::ConnectionHandler;

    const UNKNOWN_SERVER_PUBLIC_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAIJwutwmIIUraD6U+R31Ah6CBPiZijfoghZvET0dxOCT0 ",
        "unknown test server key"
    );

    fn parse_public_key(public_key: &str) -> PublicKey {
        PublicKey::from_openssh(public_key)
            .expect("test public key should be a OpenSSH-formatted public key")
    }
}

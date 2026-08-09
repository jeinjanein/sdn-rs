use russh::{
    ChannelId, ChannelOpenFailure,
    server::{Auth, ChannelOpenHandle},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tracing::{debug, info, warn};

use crate::server_side::{
    auth::{AuthenticationMethods, admin_password_authentication, check_admin_public_key},
    channel::{ChannelData, MAXIMUM_SESSION_CHANNELS_PER_CONNECTION},
    error::ServerError,
    permissions::Permissions,
    resources::ServerResources,
    security::DEVELOPMENT_USERNAME,
    subsystem::Subsystem,
};

#[derive(Debug)]
pub struct ConnectionHandler {
    connection_id: u64,
    peer_addr: Option<SocketAddr>,
    authenticated_username: Option<String>,
    permissions: Option<Permissions>,
    authentication_method: Option<AuthenticationMethods>,
    access_subsystem: Option<Subsystem>,
    server_resources: Arc<ServerResources>,
    channels: HashMap<ChannelId, ChannelData>,
}

impl ConnectionHandler {
    pub fn new(
        connection_id: u64,
        peer_addr: Option<SocketAddr>,
        server_resources: Arc<ServerResources>,
    ) -> Self {
        Self {
            connection_id,
            peer_addr,
            authenticated_username: None,
            authentication_method: None,
            permissions: None,
            server_resources,
            access_subsystem: None,
            channels: HashMap::new(),
        }
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn peer_addr(&self) -> Option<&SocketAddr> {
        self.peer_addr.as_ref()
    }

    pub fn authenticated_username(&self) -> Option<&str> {
        self.authenticated_username.as_deref()
    }

    pub fn permissions(&self) -> Option<Permissions> {
        self.permissions
    }

    pub fn authentication_method(&self) -> Option<AuthenticationMethods> {
        self.authentication_method
    }

    pub fn access_subsystem(&self) -> Option<Subsystem> {
        self.access_subsystem
    }

    pub fn server_resources(&self) -> Arc<ServerResources> {
        Arc::clone(&self.server_resources)
    }

    pub fn channels(&self) -> &HashMap<ChannelId, ChannelData> {
        &self.channels
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    pub fn record_authenticated_identity(&mut self, username: &str, permissions: Permissions) {
        self.authenticated_username = Some(username.to_owned());

        self.permissions = Some(permissions);
    }

    pub fn record_authentication_method(&mut self, method: AuthenticationMethods) {
        self.authentication_method = Some(method)
    }

    pub fn is_authorized_to_access_subsystem(&self) -> bool {
        self.permissions.is_some()
    }

    pub fn record_authorized_to_access_subsystem(&mut self, subsystem: Subsystem) {
        self.access_subsystem = Some(subsystem);
    }

    pub fn may_accept_another_session_channel(&self) -> bool {
        self.channel_count() < MAXIMUM_SESSION_CHANNELS_PER_CONNECTION
    }

    pub async fn reject_unsupported_channel(
        &self,
        channel_id: ChannelId,
        channel_type: &str,
        reply: ChannelOpenHandle,
    ) {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            ?channel_id,
            channel_type,
            "unsupported ssh channel type rejected",
        );
    }
}

impl russh::server::Handler for ConnectionHandler {
    type Error = ServerError;

    async fn auth_password(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        if username == DEVELOPMENT_USERNAME {
            if admin_password_authentication(username, password) {
                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    username,
                    "admin authenticated"
                );

                self.record_authenticated_identity(username, Permissions::Administrator);

                self.record_authentication_method(AuthenticationMethods::Password);

                return Ok(Auth::Accept);
            }

            warn!(
                connection_id = self.connection_id,
                peer_address = ?self.peer_addr,
                authentication_method = ?self.authentication_method,
                username,
                "wrong password"
            );

            return Ok(Auth::reject());
        }

        warn!(
            connection_id = self.connection_id,
            peer_address = ?&self.peer_addr,
            username,
            "unknown user rejected"
        );

        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        username: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(Default::default());

        if username == DEVELOPMENT_USERNAME {
            let authorized_keys = self.server_resources.authorized_public_keys();

            if check_admin_public_key(authorized_keys, public_key) {
                debug!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    username,
                    public_key_fingerprint = %fingerprint,
                    "public key offered"
                );

                return Ok(Auth::Accept);
            }
        }

        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(Default::default());

        if username == DEVELOPMENT_USERNAME {
            let authorized_keys = self.server_resources.authorized_public_keys();

            if check_admin_public_key(authorized_keys, public_key) {
                self.record_authenticated_identity(username, Permissions::Administrator);

                self.record_authentication_method(AuthenticationMethods::PublicKey);

                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    username,
                    authentication_method = ?self.authentication_method,
                    public_key_fingerprint = %fingerprint,
                    "public key authenticated"
                );

                return Ok(Auth::Accept);
            }
        }

        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            username,
            public_key_fingerprint = %fingerprint,
            "public key rejected"
        );

        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();

        if !self.may_accept_another_session_channel() {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;

            warn!(
                connection_id = self.connection_id,
                peer_address = ?self.peer_addr,
                ?channel_id,
                current_channel_count = self.channel_count(),
                maximum_session_channels = MAXIMUM_SESSION_CHANNELS_PER_CONNECTION,
                "session reached channel limit"
            );

            return Ok(());
        }

        reply.accept().await;

        let channel_data = ChannelData::new();

        self.channels.insert(channel_id, channel_data);

        info!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            ?channel_id,
            current_channel_count = self.channel_count(),
            maximum_session_channels = MAXIMUM_SESSION_CHANNELS_PER_CONNECTION,
            "new session channel accepted"
        );

        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        self.reject_unsupported_channel(channel_id, "x11", reply)
            .await;
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        self.reject_unsupported_channel(channel_id, "direct-tcpip", reply)
            .await;
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        self.reject_unsupported_channel(channel_id, "direct-streamlocal", reply)
            .await;
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        self.reject_unsupported_channel(channel_id, "forwarded-tcpip", reply)
            .await;
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if self.is_authorized_to_access_subsystem() {
            if name == "netconf" {
                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    channel_id = ?channel,
                    "netconf subsystem authorized"
                );
                self.record_authorized_to_access_subsystem(Subsystem::Netconf);
                session.channel_success(channel)?;
            } else {
                warn!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    channel_id = ?channel,
                    "unknown subsystem rejected"
                );
                session.channel_failure(channel)?;
            }
        } else {
            warn!(
                connection_id = self.connection_id,
                peer_address = ?self.peer_addr,
                channel_id = ?channel,
                "access to subsystem denied"
            );
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            reject_reason = "feature is unsupported",
            "agent request denied",
        );
        session.channel_failure(channel)?;

        Ok(false)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        _variable_value: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            variable_name,
            reject_reason = "feature is unsupported",
            "environment variable request denied",
        );
        session.channel_failure(channel)?;

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            data_len = data.len(),
            reject_reason = "feature is unsupported",
            "command execution request denied",
        );
        session.channel_failure(channel)?;

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes = ?modes,
            reject_reason = "feature is unsupported",
            "pty request denied",
        );
        session.channel_failure(channel)?;

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            reject_reason = "feature is unsupported",
            "shell request denied",
        );
        session.channel_failure(channel)?;

        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            channel_id = ?channel,
            single_connection,
            x11_auth_protocol,
            x11_screen_number,
            x11_auth_cookie,
            reject_reason = "feature is unsupported",
            "x11 connection request denied",
        );
        session.channel_failure(channel)?;

        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            request_bind_address = address,
            request_bind_port = port,
            reject_reason = "feature is unsupported",
            "agent request denied",
        );

        Ok(false)
    }
}

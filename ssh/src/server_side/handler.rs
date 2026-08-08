use russh::{ChannelId, keys::ssh_key::authorized_keys, server::Auth};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tracing::{debug, info};

use crate::server_side::{
    auth::{AuthenticationMethods, admin_password_authentication, check_admin_public_key},
    channel::ChannelData,
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

            info!(
                connection_id = self.connection_id,
                peer_address = ?self.peer_addr,
                authentication_method = ?self.authentication_method,
                username,
                "wrong password"
            );

            return Ok(Auth::reject());
        }

        info!(
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

        info!(
            connection_id = self.connection_id,
            peer_address = ?self.peer_addr,
            username,
            public_key_fingerprint = %fingerprint,
            "public key rejected"
        );

        Ok(Auth::reject())
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
                session.channel_success(channel)?;
            } else {
                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    channel_id = ?channel,
                    "unknown subsystem rejected"
                );
                session.channel_failure(channel)?;
            }
        } else {
            info!(
                connection_id = self.connection_id,
                peer_address = ?self.peer_addr,
                channel_id = ?channel,
                "access to subsystem denied"
            );
        }

        Ok(())
    }
}

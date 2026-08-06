use russh::{ChannelId, keys::ssh_key::authorized_keys, server::Auth};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tracing::{debug, info};

use crate::server_side::{
    auth::{admin_password_authentication, check_admin_public_key},
    channel::ChannelData,
    error::ServerError,
    permissions::Permissions,
    resources::ServerResources,
    security::DEVELOPMENT_USERNAME,
};

#[derive(Debug)]
pub struct ConnectionHandler {
    connection_id: u64,
    peer_addr: Option<SocketAddr>,
    authenticated_username: Option<String>,
    permissions: Option<Permissions>,
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
            permissions: None,
            server_resources,
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

    pub fn record_authenticated_identity(&mut self, username: &str, permissions: Permissions) {
        self.authenticated_username = Some(username.to_owned());

        self.permissions = Some(permissions);
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

                return Ok(Auth::Accept);
            }

            info!(
                connection_id = self.connection_id,
                peer_address = ?&self.peer_addr,
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
                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    username,
                    public_key_fingerprint = %fingerprint,
                    "public key authenticated"
                );

                self.record_authenticated_identity(username, Permissions::Administrator);

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
}

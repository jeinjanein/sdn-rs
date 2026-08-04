use russh::server::Auth;
use std::net::SocketAddr;
use tracing::info;

use crate::server_side::{
    auth::admin_authentication, error::ServerError, security::DEVELOPMENT_USERNAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionHandler {
    connection_id: u64,
    peer_addr: Option<SocketAddr>,
}

impl ConnectionHandler {
    pub fn new(connection_id: u64, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            connection_id,
            peer_addr,
        }
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn peer_addr(&self) -> Option<&SocketAddr> {
        self.peer_addr.as_ref()
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
            if admin_authentication(username, password) {
                info!(
                    connection_id = self.connection_id,
                    peer_address = ?self.peer_addr,
                    username,
                    "admin authenticated"
                );
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
}

use std::sync::{Arc, atomic::AtomicU64};

use russh::keys::PublicKey;
use tracing::warn;

use crate::server_side::{
    error::ServerError, handler::ConnectionHandler, resources::ServerResources,
};

#[derive(Debug)]
pub struct SshServer {
    next_connection_id: AtomicU64,
    server_resources: Arc<ServerResources>,
}

impl SshServer {
    pub fn new(authorized_public_keys: Vec<PublicKey>) -> Self {
        Self {
            next_connection_id: AtomicU64::new(0),
            server_resources: Arc::new(ServerResources::new(authorized_public_keys)),
        }
    }

    pub fn connection_id(&mut self) -> u64 {
        self.next_connection_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

impl russh::server::Server for SshServer {
    type Handler = ConnectionHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let connection_id = self.connection_id();
        ConnectionHandler::new(connection_id, peer_addr, Arc::clone(&self.server_resources))
    }

    fn handle_session_error(&mut self, error: ServerError) {
        warn!(
            %error,
            "SSH client ended with an error"
        )
    }
}

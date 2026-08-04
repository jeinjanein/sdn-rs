use std::sync::atomic::AtomicU64;

use russh::server;

use crate::server_side::handler::ConnectionHandler;

#[derive(Debug)]
pub struct SshServer {
    next_connection_id: AtomicU64,
}

impl SshServer {
    pub fn new() -> Self {
        Self {
            next_connection_id: AtomicU64::new(0),
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
        ConnectionHandler::new(connection_id, peer_addr)
    }
}
